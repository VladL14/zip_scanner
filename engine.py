import asyncio
import logging
import os
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import List, Optional

import aiofiles
import magic

from cdr_office import OfficeSanitizer
from cdr_pdf import PDFSanitizer
from static_scanner import StaticScanner

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger("SanitizationEngine")


class SecurityViolation(Exception):
    """Exception raised for security violations like Zip-Slip or Zip-Bomb."""
    pass


class SanitizationEngine:
    def __init__(
        self,
        max_file_size: int = 500 * 1024 * 1024,        # 500 MB per file - allows for large enterprise documents (CAD, raw video)
        max_total_size: int = 2 * 1024 * 1024 * 1024,  # 2 GB total per archive - enterprise standard for web uploads
        max_compression_ratio: float = 250.0,          # Max compression ratio - some text logs compress very well
        max_depth: int = 3                             # Max recursive archive depth to prevent infinite loops
    ):
        """
        Enterprise-grade configurations for extraction limits.
        """
        self.max_file_size = max_file_size
        self.max_total_size = max_total_size
        self.max_compression_ratio = max_compression_ratio
        self.max_depth = max_depth

    async def _process_executable(self, file_path: Path) -> bool:
        """Route A: Executables (PE, ELF, Scripts)"""
        logger.info(f"[Exec/Sandbox] Fast-tracking {file_path.name} through static reputation...")
        is_clean = await StaticScanner.check_file_reputation(file_path)
        if not is_clean:
            return False
            
        logger.info(f"[Exec/Sandbox] Sending {file_path.name} to Sandbox/ML model...")
        await asyncio.sleep(0.5)  # Mock async call
        logger.info(f"[Exec/Sandbox] {file_path.name} was analyzed. (Mocking as Safe)")
        return True

    async def _process_document(self, file_path: Path, mime_type: str) -> bool:
        """Route B: Documents (PDF, Office)"""
        logger.info(f"[Doc/CDR] Performing CDR on {file_path.name}...")
        
        if "pdf" in mime_type:
            success = await PDFSanitizer.sanitize_pdf(file_path)
        elif "officedocument" in mime_type or "msword" in mime_type:
            success = await OfficeSanitizer.sanitize_ooxml(file_path)
        else:
            logger.warning(f"[Doc/CDR] Unknown document format: {mime_type}. Mocking as safe.")
            success = True
            
        if success:
            logger.info(f"[Doc/CDR] {file_path.name} sanitized successfully.")
            return True
        else:
            logger.error(f"[Doc/CDR] {file_path.name} could not be sanitized and will be dropped.")
            return False

    async def _process_media_text(self, file_path: Path) -> bool:
        """Route C: Media/Text (Images, Plain text)"""
        logger.info(f"[Media/Static] Running static reputation check on {file_path.name}...")
        is_clean = await StaticScanner.check_file_reputation(file_path)
        if not is_clean:
            return False
            
        logger.info(f"[Media/Static] {file_path.name} passed static scan.")
        return True

    async def _process_file(self, file_path: Path, mime_type: str, extract_dir: Path, current_depth: int) -> Optional[Path]:
        """
        Routes the file to the appropriate pipeline based on its MIME type.
        Returns the path to the safe/sanitized file, or None if it should be dropped.
        """
        logger.info(f"Routing '{file_path.name}' with MIME type: {mime_type}")
        is_safe = False

        if "zip" in mime_type or "rar" in mime_type or "7z" in mime_type or "tar" in mime_type:
            logger.info(f"[Archive] Recursive archive detected: {file_path.name}")
            # Route D: Archives
            is_safe = await self._process_archive_internal(file_path, current_depth + 1)
            # If safe, the recursive function has already replaced the file in-place with a clean version.
        elif mime_type.startswith("application/x-dosexec") or mime_type.startswith("application/x-executable") or mime_type.startswith("text/x-"):
            is_safe = await self._process_executable(file_path)
        elif "pdf" in mime_type or "msword" in mime_type or "officedocument" in mime_type:
            is_safe = await self._process_document(file_path, mime_type)
        elif mime_type.startswith("image/") or mime_type.startswith("text/") or mime_type.startswith("video/") or mime_type.startswith("audio/"):
            is_safe = await self._process_media_text(file_path)
        else:
            logger.warning(f"Unknown or unhandled MIME type '{mime_type}' for '{file_path.name}'. Dropping by default.")
            is_safe = False

        return file_path if is_safe else None

    def _extract_safely(self, archive_path: Path, extract_dir: Path) -> List[Path]:
        """
        Extracts an archive synchronously while strictly enforcing Anti-Zip-Bomb and Anti-Zip-Slip rules.
        """
        extracted_files = []
        total_extracted_size = 0
        archive_size = archive_path.stat().st_size

        if not zipfile.is_zipfile(archive_path):
            logger.error(f"File {archive_path.name} is not a valid ZIP archive.")
            return extracted_files

        with zipfile.ZipFile(archive_path, 'r') as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue

                # 1. Zip-Bomb Prevention
                if info.file_size > self.max_file_size:
                    raise SecurityViolation(f"File {info.filename} exceeds max file size limit ({self.max_file_size} bytes)")
                
                total_extracted_size += info.file_size
                if total_extracted_size > self.max_total_size:
                    raise SecurityViolation(f"Archive exceeds max total extraction size ({self.max_total_size} bytes)")
                
                if archive_size > 0:
                    ratio = info.file_size / archive_size
                    if ratio > self.max_compression_ratio:
                        raise SecurityViolation(f"File {info.filename} exceeds max compression ratio ({self.max_compression_ratio})")

                # 2. Zip-Slip Prevention
                # Resolve the absolute path of the target and the extraction directory
                target_path = extract_dir / info.filename
                resolved_target = target_path.resolve()
                resolved_extract_dir = extract_dir.resolve()

                # Ensure the resolved target path is strictly within the extraction directory
                if not str(resolved_target).startswith(str(resolved_extract_dir)):
                    logger.warning(f"Zip-Slip attempt detected and blocked! File: {info.filename}")
                    continue  # Skip malicious file instead of failing entire archive (Enterprise approach)

                # Proceed with safe extraction manually to guarantee path integrity
                resolved_target.parent.mkdir(parents=True, exist_ok=True)
                
                with zf.open(info.filename) as source, open(resolved_target, "wb") as target:
                    shutil.copyfileobj(source, target)
                
                extracted_files.append(resolved_target)
                logger.debug(f"Safely extracted: {resolved_target}")
                
        return extracted_files

    async def _process_archive_internal(self, archive_path: Path, depth: int) -> bool:
        """
        Processes an archive recursively. Replaces the archive_path with a sanitized version.
        """
        if depth > self.max_depth:
            logger.warning(f"Max recursion depth reached ({self.max_depth}). Dropping archive: {archive_path.name}")
            return False

        logger.info(f"Processing archive at depth {depth}: {archive_path.name}")
        
        # Create a unique temp directory for this extraction bounded by standard OS temp mechanisms
        with tempfile.TemporaryDirectory(prefix="safe_extract_") as temp_dir:
            temp_path = Path(temp_dir)
            
            try:
                # Extract synchronously (CPU/IO bound, moved to thread to avoid blocking event loop)
                extracted_files = await asyncio.to_thread(self._extract_safely, archive_path, temp_path)
            except SecurityViolation as e:
                logger.error(f"Security violation while extracting {archive_path.name}: {e}")
                return False
            except Exception as e:
                logger.error(f"Error extracting {archive_path.name}: {e}")
                return False

            if not extracted_files:
                logger.warning(f"No files safely extracted from {archive_path.name} (maybe all were malicious/empty).")
                return False

            # Triage and Route
            tasks = []
            for file_path in extracted_files:
                # Determine REAL MIME type via magic bytes
                try:
                    mime_type = magic.from_file(str(file_path), mime=True)
                except Exception as e:
                    logger.error(f"Failed to determine MIME type for {file_path.name}: {e}")
                    mime_type = "application/octet-stream"
                
                tasks.append(self._process_file(file_path, mime_type, temp_path, depth))

            # Wait for all files in this archive to be processed concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)

            safe_files = []
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Pipeline error during file processing: {result}")
                elif result is not None:
                    safe_files.append(result)

            if not safe_files:
                logger.warning(f"All files in {archive_path.name} were dropped during triage. Dropping the archive.")
                return False

            # Reconstruct the archive
            logger.info(f"Reconstructing safe archive for: {archive_path.name}")
            try:
                await asyncio.to_thread(self._repack_archive, archive_path, safe_files, temp_path)
                return True
            except Exception as e:
                logger.error(f"Failed to repack archive {archive_path.name}: {e}")
                return False

    def _repack_archive(self, output_archive: Path, safe_files: List[Path], base_dir: Path):
        """
        Creates a new ZIP archive containing only the safe files.
        Maintains relative paths based on base_dir.
        """
        # Repack into a temporary file first to avoid corruption if interrupted
        temp_output = output_archive.with_suffix(".tmp")
        
        with zipfile.ZipFile(temp_output, 'w', zipfile.ZIP_DEFLATED) as zf:
            for file_path in safe_files:
                # Compute relative path to maintain folder structure
                relative_path = file_path.relative_to(base_dir)
                zf.write(file_path, arcname=str(relative_path))
                logger.debug(f"Repacked {relative_path} into {output_archive.name}")
                
        # Replace original archive with the safe temporary one
        temp_output.replace(output_archive)

    async def process(self, input_archive_path: str, output_archive_path: str) -> bool:
        """
        Main entry point for the Sanitization Engine.
        Copies the input to the output location first, then processes it in-place.
        """
        input_path = Path(input_archive_path)
        output_path = Path(output_archive_path)

        if not input_path.exists():
            logger.error(f"Input archive not found: {input_path}")
            return False

        # Copy original archive to output path to begin in-place sanitization
        try:
            shutil.copy2(input_path, output_path)
        except Exception as e:
            logger.error(f"Failed to copy input archive: {e}")
            return False

        logger.info(f"Starting Clean-Room pipeline on {output_path.name}")
        success = await self._process_archive_internal(output_path, depth=1)
        
        if success:
            logger.info(f"Sanitization complete! Clean archive available at: {output_path}")
        else:
            logger.error("Sanitization failed or archive was completely malicious/empty.")
            if output_path.exists():
                output_path.unlink()  # Clean up failed output

        return success


# --- Example Usage & Testing ---

async def main():
    test_dir = Path("test_data")
    test_dir.mkdir(exist_ok=True)
    
    # 1. Create safe file
    dummy_txt = test_dir / "safe.txt"
    dummy_txt.write_text("Hello World! This is a clean text document.")
    
    # 2. Create mock malicious executable
    dummy_exe = test_dir / "malicious.exe"
    dummy_exe.write_bytes(b"MZ" + b"\x00" * 1024) 
    
    # 3. Create input ZIP with a Zip-Slip payload
    input_zip = test_dir / "input.zip"
    with zipfile.ZipFile(input_zip, 'w') as zf:
        zf.write(dummy_txt, arcname="safe.txt")
        zf.write(dummy_exe, arcname="malicious.exe")
        
        # Crafting a Zip-Slip payload
        zinfo = zipfile.ZipInfo("../evil.txt")
        zf.writestr(zinfo, "I am a path traversal payload!")

    logger.info(f"Created test archive at {input_zip} containing safe.txt, malicious.exe, and ../evil.txt")

    # 4. Run the Engine
    engine = SanitizationEngine()
    output_zip = test_dir / "clean_output.zip"
    
    await engine.process(str(input_zip), str(output_zip))
    
    # 5. Verify the output
    if output_zip.exists():
        logger.info("Contents of the final sanitized ZIP:")
        with zipfile.ZipFile(output_zip, 'r') as zf:
            for name in zf.namelist():
                logger.info(f" - {name}")


if __name__ == "__main__":
    asyncio.run(main())
