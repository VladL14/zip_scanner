import asyncio
import logging
import os
import tempfile
import zipfile
from pathlib import Path

logger = logging.getLogger("OfficeSanitizer")

class OfficeSanitizer:
    
    # Signatures of macro/executable payloads commonly embedded in OOXML
    SUSPICIOUS_EXTENSIONS = {".bin", ".vbs", ".exe", ".dll", ".ps1"}
    SUSPICIOUS_NAMES = {"vbaproject.bin", "vbadata.xml"}
    SUSPICIOUS_PATHS = {"word/activex", "xl/activex", "ppt/activex", "macros"}

    @staticmethod
    def _is_suspicious(file_path: Path, base_dir: Path) -> bool:
        """
        Determine if an internal OOXML file is suspicious (macros, OLE, ActiveX).
        """
        # Get the internal relative path normalized to posix for easy checking
        rel_path = file_path.relative_to(base_dir).as_posix().lower()
        
        # Check specific suspicious file names
        if file_path.name.lower() in OfficeSanitizer.SUSPICIOUS_NAMES:
            return True
            
        # Check suspicious extensions (like OLE .bin objects)
        if file_path.suffix.lower() in OfficeSanitizer.SUSPICIOUS_EXTENSIONS:
            return True
            
        # Check suspicious internal directories
        for susp_path in OfficeSanitizer.SUSPICIOUS_PATHS:
            if susp_path in rel_path:
                return True
                
        return False

    @staticmethod
    def _process_ooxml_sync(file_path: Path) -> bool:
        """
        Synchronous I/O bound logic to extract, strip, and repack the OOXML container.
        """
        if not zipfile.is_zipfile(file_path):
            logger.warning(f"CDR: {file_path.name} is not a valid ZIP/OOXML file. (Could be a PDF or Legacy format)")
            # If we want to support legacy formats or PDFs later, we'd add logic here.
            # For now, if it's not a zip, we'll return True assuming it passed the static checks (like a PDF).
            return True

        with tempfile.TemporaryDirectory(prefix="cdr_office_") as temp_dir:
            temp_path = Path(temp_dir)
            
            # 1. Extract the container
            try:
                with zipfile.ZipFile(file_path, 'r') as zf:
                    zf.extractall(temp_path)
            except Exception as e:
                logger.error(f"CDR Failed to extract OOXML {file_path.name}: {e}")
                return False

            # 2. Sanitize contents
            safe_files = []
            for root, dirs, files in os.walk(temp_path):
                for f in files:
                    full_path = Path(root) / f
                    if OfficeSanitizer._is_suspicious(full_path, temp_path):
                        logger.info(f"CDR Stripped malicious asset from {file_path.name}: {full_path.relative_to(temp_path)}")
                        full_path.unlink() # Delete the dangerous file
                    else:
                        safe_files.append(full_path)

            # 3. Repack the container
            try:
                temp_output = file_path.with_suffix('.tmp_cdr')
                with zipfile.ZipFile(temp_output, 'w', zipfile.ZIP_DEFLATED) as zf:
                    for sf in safe_files:
                        rel_path = sf.relative_to(temp_path)
                        zf.write(sf, arcname=str(rel_path))
                
                # Overwrite original file with the sanitized version
                temp_output.replace(file_path)
            except Exception as e:
                logger.error(f"CDR Failed to repack sanitized OOXML {file_path.name}: {e}")
                if 'temp_output' in locals() and temp_output.exists():
                    temp_output.unlink()
                return False

        return True

    @classmethod
    async def sanitize_ooxml(cls, file_path: Path) -> bool:
        """
        Asynchronously sanitizes a modern Microsoft Office file by treating it as a ZIP
        and removing macros, VBA projects, and ActiveX binary objects.
        Returns True if successful, False if the file was corrupted.
        """
        logger.info(f"Starting OOXML CDR on {file_path.name}")
        try:
            # Offload heavy CPU/IO zip operations to a separate thread
            success = await asyncio.to_thread(cls._process_ooxml_sync, file_path)
            return success
        except Exception as e:
            logger.error(f"Unexpected error during OOXML sanitization of {file_path.name}: {e}")
            return False
