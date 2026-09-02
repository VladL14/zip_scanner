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
    # Compile YARA rules at the class level so it's only done once during startup
    YARA_RULES = yara.compile(source="""
        rule Suspicious_PowerShell {
            meta:
                description = "Detects suspicious PowerShell execution policies"
                author = "Clean-Room"
            strings:
                $ps1 = "powershell -ExecutionPolicy Bypass" nocase
                $ps2 = "powershell.exe -ep bypass" nocase
                $ps3 = "Invoke-Expression" nocase
            condition:
                any of them
        }
        rule EICAR_Test_String {
            meta:
                description = "Standard AV test string"
            strings:
                $eicar = "X5O!P%@AP[4\\\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
            condition:
                $eicar
        }
    """)

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
                    return False
                
                return True
                
        except vt.error.APIError as e:
            if e.code == "NotFoundError":
                # File not found in VT database, so it's unknown/clean to them
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
    async def check_file_reputation(cls, file_path: Path) -> bool:
        """
        Dual-layer static scan: VirusTotal (external) + YARA (local).
        Returns False if the file is a known threat, True if unknown/clean.
        """
        try:
            # 1. Compute Hash
            file_hash = await cls._compute_sha256(file_path)
            
            # 2. Layer 1: VirusTotal Threat Intel
            logger.debug(f"Checking VirusTotal for {file_path.name} (Hash: {file_hash})...")
            is_vt_clean = await cls._check_virustotal(file_hash)
            if not is_vt_clean:
                logger.warning(f"[StaticScan] External Threat (VT) detected for {file_path.name}. Dropping instantly.")
                return False
                
            # 3. Layer 2: Local YARA Pattern Matching
            logger.debug(f"Running YARA scan on {file_path.name}...")
            is_yara_clean = await cls._scan_yara(file_path)
            if not is_yara_clean:
                logger.warning(f"[StaticScan] Local Threat (YARA) detected for {file_path.name}. Dropping instantly.")
                return False
                
            logger.info(f"[StaticScan] File passed all static reputation checks: {file_path.name}.")
            return True
            
        except Exception as e:
            logger.error(f"Error during static scanning pipeline for {file_path.name}: {e}")
            # If we fail to read or hash, dropping is the safest enterprise default
            return False
