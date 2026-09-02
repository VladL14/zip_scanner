import asyncio
import hashlib
import logging
import os
from pathlib import Path

import aiofiles
import httpx

logger = logging.getLogger("StaticScanner")


class StaticScanner:
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
    async def _vt_lookup(cls, file_hash: str) -> bool:
        """
        Query VirusTotal API v3 for file reputation.
        Returns False if known threat (malicious votes > 0), True otherwise.
        """
        vt_api_key = os.getenv("VT_API_KEY")
        if not vt_api_key:
            logger.warning("VT_API_KEY environment variable is not set. Skipping real VirusTotal check (fail-open).")
            return True

        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {
            "x-apikey": vt_api_key
        }

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url, headers=headers, timeout=10.0)

            if response.status_code == 404:
                # File not found in VT database, so it's unknown/clean
                return True
            elif response.status_code == 429:
                logger.warning("VirusTotal API rate limit exceeded (429). Bypassing static check.")
                return True
            elif response.status_code != 200:
                logger.error(f"VirusTotal API returned unexpected status {response.status_code}: {response.text}")
                return True  # Fail open on unexpected errors

            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_votes = stats.get("malicious", 0)

            if malicious_votes > 0:
                logger.warning(f"VirusTotal flagged hash {file_hash} with {malicious_votes} malicious votes.")
                return False

            return True

        except httpx.RequestError as e:
            logger.error(f"Network error while contacting VirusTotal: {e}")
            return True
        except Exception as e:
            logger.error(f"Unexpected error during VirusTotal lookup: {e}")
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
            is_clean = await cls._vt_lookup(file_hash)
            if not is_clean:
                logger.warning(f"[StaticScan] KNOWN THREAT detected for {file_path.name} (Hash: {file_hash}). Dropping instantly.")
                return False
                
            logger.info(f"[StaticScan] UNKNOWN/CLEAN reputation for {file_path.name}.")
            return True
        except Exception as e:
            logger.error(f"Error during static scanning of {file_path.name}: {e}")
            # If we fail to read or hash, dropping is the safest enterprise default
            return False
