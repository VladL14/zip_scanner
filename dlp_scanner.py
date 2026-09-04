import asyncio
import logging
import re
from pathlib import Path

import aiofiles
import fitz  # PyMuPDF

logger = logging.getLogger("DLPScanner")

class DLPScanner:
    # Compile regex patterns for sensitive data in binary mode to handle mixed files safely
    PATTERNS = {
        "AWS_ACCESS_KEY": re.compile(rb"AKIA[0-9A-Z]{16}"),
        "RSA_PRIVATE_KEY": re.compile(rb"-----BEGIN (?:RSA )?PRIVATE KEY-----"),
        # Basic Visa/Mastercard matching (13-19 digits, can be improved with Luhn check later)
        "CREDIT_CARD_BASIC": re.compile(rb"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b")
    }

    @classmethod
    def _scan_pdf_sync(cls, file_path: Path) -> bool:
        """Extracts text from PDF and scans it."""
        try:
            doc = fitz.open(file_path)
            for page in doc:
                text = page.get_text()
                if not text:
                    continue
                # Encode text to bytes so it matches our binary regex patterns
                text_bytes = text.encode('utf-8', errors='ignore')
                for violation_type, pattern in cls.PATTERNS.items():
                    if pattern.search(text_bytes):
                        logger.warning(f"[DLP] Violation detected: {violation_type} found in PDF {file_path.name}. Dropping file.")
                        doc.close()
                        return False
            doc.close()
            return True
        except Exception as e:
            logger.error(f"[DLP] Error parsing PDF {file_path.name}: {e}")
            return False

    @classmethod
    async def scan_for_sensitive_data(cls, file_path: Path, chunk_size: int = 1024 * 1024) -> bool:
        """
        Scans a file for Data Loss Prevention (DLP) violations.
        Uses PyMuPDF for PDFs, otherwise falls back to binary chunking.
        Returns False if sensitive data is found (Drop), True if clean (Keep).
        """
        logger.debug(f"Starting DLP scan for {file_path.name}...")
        
        # Check if PDF
        if file_path.suffix.lower() == ".pdf":
            # Run PDF scanning in a separate thread to avoid blocking asyncio
            is_clean = await asyncio.to_thread(cls._scan_pdf_sync, file_path)
            if not is_clean:
                return False
            logger.info(f"[DLP] Clean. No sensitive data found in PDF {file_path.name}.")
            return True

        try:
            async with aiofiles.open(file_path, 'rb') as f:
                # Keep a small overlap between chunks to catch patterns that cross chunk boundaries
                overlap_size = 128
                overlap_buffer = b""
                
                while chunk := await f.read(chunk_size):
                    data_to_scan = overlap_buffer + chunk
                    
                    for violation_type, pattern in cls.PATTERNS.items():
                        if pattern.search(data_to_scan):
                            logger.warning(f"[DLP] Violation detected: {violation_type} found in {file_path.name}. Dropping file.")
                            return False
                            
                    # Prepare overlap for next iteration
                    if len(data_to_scan) > overlap_size:
                        overlap_buffer = data_to_scan[-overlap_size:]
                    else:
                        overlap_buffer = data_to_scan

            logger.info(f"[DLP] Clean. No sensitive data found in {file_path.name}.")
            return True
        except Exception as e:
            logger.error(f"[DLP] Error scanning {file_path.name}: {e}")
            # Fail closed on enterprise DLP for safety
            return False
