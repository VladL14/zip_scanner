import asyncio
import hashlib
import logging
from pathlib import Path

import aiofiles

logger = logging.getLogger("StaticScanner")

class StaticScanner:
    # Dummy blacklist containing standard test hashes
    # EICAR test string hash: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
    BLACKLISTED_HASHES = {
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "131f95c51cc819465fa1797f6cc0e2984a9c687e87ff27d21b7952e463a5aaec", # Hash of just the word "eicar"
    }

    @classmethod
    async def _compute_sha256(cls, file_path: Path, chunk_size: int = 65536) -> str:
        """
        Asynchronously compute the SHA256 hash of a file in chunks to save memory.
        Uses aiofiles to avoid blocking the event loop on large 500MB binaries.
        """
        sha256_hash = hashlib.sha256()
        async with aiofiles.open(file_path, 'rb') as f:
            while chunk := await f.read(chunk_size):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

    @classmethod
    async def _mock_vt_lookup(cls, file_hash: str) -> bool:
        """
        Mock an API call to a threat intelligence feed (e.g. VirusTotal).
        Returns True if the hash is clean/unknown, False if it is a known threat.
        """
        # Simulate network latency for API call
        await asyncio.sleep(0.1)
        if file_hash in cls.BLACKLISTED_HASHES:
            return False
        return True

    @classmethod
    async def check_file_reputation(cls, file_path: Path) -> bool:
        """
        Fast-track static scan. Computes file hash and checks reputation.
        Returns False if the file is a known threat, True if unknown/clean.
        """
        try:
            # 1. Compute Hash
            file_hash = await cls._compute_sha256(file_path)
            
            # 2. Check Reputation (Threat Intel)
            is_clean = await cls._mock_vt_lookup(file_hash)
            if not is_clean:
                logger.warning(f"[StaticScan] KNOWN THREAT detected for {file_path.name} (Hash: {file_hash}). Dropping instantly.")
                return False
                
            logger.info(f"[StaticScan] UNKNOWN/CLEAN reputation for {file_path.name}.")
            return True
        except Exception as e:
            logger.error(f"Error during static scanning of {file_path.name}: {e}")
            # If we fail to read or hash, dropping is the safest enterprise default
            return False
