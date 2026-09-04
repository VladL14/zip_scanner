import asyncio
import hashlib
import logging
import os
from pathlib import Path

import aiofiles
import vt
import yara

logger = logging.getLogger("StaticScanner")

class StaticScanner:
    YARA_RULES = None
    # TODO: Replace with Redis for distributed caching in production
    _VT_CACHE = {}

    @classmethod
    def load_rules(cls, rules_dir: Path):
        """
        Dynamically load and compile all .yar/.yara rules from the specified directory.
        """
        filepaths = {}
        if rules_dir.exists() and rules_dir.is_dir():
            for rule_file in rules_dir.glob("*.yar*"):
                # yara.compile expects a dict of {namespace: filepath}
                filepaths[rule_file.stem] = str(rule_file)
                
        try:
            if filepaths:
                cls.YARA_RULES = yara.compile(filepaths=filepaths)
                logger.info(f"Successfully loaded {len(filepaths)} YARA rule files from {rules_dir}")
            else:
                raise ValueError("No YARA rules found in directory.")
        except Exception as e:
            logger.warning(f"Failed to load dynamic YARA rules from {rules_dir}: {e}. Falling back to dummy rule.")
            cls.YARA_RULES = yara.compile(source='rule Dummy_Rule { condition: false }')

    @classmethod
    async def _compute_sha256(cls, file_path: Path, chunk_size: int = 65536) -> str:
        """
        Asynchronously compute the SHA256 hash of a file in chunks to save memory.
        Uses aiofiles to avoid blocking the event loop on large binaries.
        """
        sha256_hash = hashlib.sha256()
        async with aiofiles.open(file_path, 'rb') as f:
            while chunk := await f.read(chunk_size):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

    @classmethod
    async def _check_virustotal(cls, file_hash: str) -> bool:
        """
        Query VirusTotal API v3 using vt-py for file reputation.
        Returns False if known threat (malicious votes >= 2), True otherwise.
        """
        if file_hash in cls._VT_CACHE:
            logger.debug(f"VirusTotal Cache HIT for {file_hash}")
            return cls._VT_CACHE[file_hash]

        vt_api_key = os.getenv("VT_API_KEY")
        if not vt_api_key:
            logger.warning("VT_API_KEY environment variable is not set. Skipping VirusTotal check.")
            return True

        try:
            # Use vt.Client asynchronously
            async with vt.Client(vt_api_key) as client:
                file_obj = await client.get_object_async(f"/files/{file_hash}")
                
                malicious_votes = file_obj.last_analysis_stats.get('malicious', 0)
                if malicious_votes >= 2:
                    logger.warning(f"VirusTotal flagged hash {file_hash} with {malicious_votes} malicious votes.")
                    cls._VT_CACHE[file_hash] = False
                    return False
                
                cls._VT_CACHE[file_hash] = True
                return True
                
        except vt.error.APIError as e:
            if e.code == "NotFoundError":
                # File not found in VT database, so it's unknown/clean to them
                cls._VT_CACHE[file_hash] = True
                return True
            logger.error(f"VirusTotal API Error: {e.message} (Code: {e.code}). Bypassing VT check.")
            return True
        except Exception as e:
            logger.error(f"Unexpected error during VirusTotal lookup: {e}")
            return True

    @classmethod
    def _scan_yara_sync(cls, file_path: Path) -> bool:
        """Synchronous CPU-bound YARA scanning logic."""
        try:
            matches = cls.YARA_RULES.match(str(file_path))
            if matches:
                match_names = [m.rule for m in matches]
                logger.warning(f"YARA matched local threats in {file_path.name}: {match_names}")
                return False
            return True
        except yara.Error as e:
            logger.error(f"YARA scanning error on {file_path.name}: {e}")
            return True # Fail open on engine errors
        except Exception as e:
            logger.error(f"Unexpected YARA error on {file_path.name}: {e}")
            return True

    @classmethod
    async def _scan_yara(cls, file_path: Path) -> bool:
        """
        Asynchronously scans the file against YARA rules.
        Runs in a separate thread to avoid blocking the asyncio event loop.
        """
        return await asyncio.to_thread(cls._scan_yara_sync, file_path)

    @classmethod
    async def check_virustotal(cls, file_path: Path) -> bool:
        """
        Public wrapper to compute hash and check VirusTotal.
        """
        try:
            file_hash = await cls._compute_sha256(file_path)
            logger.debug(f"Checking VirusTotal for {file_path.name} (Hash: {file_hash})...")
            is_clean = await cls._check_virustotal(file_hash)
            if not is_clean:
                logger.warning(f"[StaticScan] External Threat (VT) detected for {file_path.name}. Dropping.")
            return is_clean
        except Exception as e:
            logger.error(f"Error during VT check for {file_path.name}: {e}")
            return False

    @classmethod
    async def scan_yara(cls, file_path: Path) -> bool:
        """
        Public wrapper to run YARA scan asynchronously.
        """
        logger.debug(f"Running YARA scan on {file_path.name}...")
        is_clean = await cls._scan_yara(file_path)
        if not is_clean:
            logger.warning(f"[StaticScan] Local Threat (YARA) detected for {file_path.name}. Dropping.")
        return is_clean
