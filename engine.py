import asyncio
import logging
import os
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import List, Optional

import magic

from cdr_office import OfficeSanitizer
from cdr_pdf import PDFSanitizer
from dlp_scanner import DLPScanner
from static_scanner import StaticScanner

logger = logging.getLogger("SanitizationEngine")


class MLScanner:
    """Placeholder for future Machine Learning / AI Sandbox integrations."""
    @staticmethod
    async def analyze_bytes(file_path: Path) -> bool:
        """Mock AI analysis for executables."""
        logger.info(f"[MLScanner] Analyzing {file_path.name} (Mocking as Safe)")
        await asyncio.sleep(0.5)
        return True


class SecurityViolation(Exception):
    """Exception raised for security violations like Zip-Bomb."""
    pass


class SanitizationEngine:
    def __init__(
        self,
        max_file_size: int = 500 * 1024 * 1024,        # 500 MB per file
        max_total_size: int = 2 * 1024 * 1024 * 1024,  # 2 GB total per archive
        max_files: int = 10000,                        # Max files per archive
    ):
        self.max_file_size = max_file_size
        self.max_total_size = max_total_size
        self.max_files = max_files

    async def _process_atomic_file(self, input_path: Path, mime_type: str, staging_dir: Path) -> Optional[Path]:
        """
        Universal Multi-Layered Triage.
        Routes files based on their type to either the Detection Pipeline or CDR Pipeline.
        """
        file_path = input_path
        is_safe = False
        
        # Route A: Detection Pipeline (Executables/Scripts)
        if mime_type.startswith("application/x-dosexec") or mime_type.startswith("application/x-executable") or mime_type.startswith("text/x-"):
            logger.info(f"[{file_path.name}] Route A: Detection Pipeline (Executables)")
            
            is_vt_clean = await StaticScanner.check_virustotal(file_path)
            if is_vt_clean:
                is_yara_clean = await StaticScanner.scan_yara(file_path)
                if is_yara_clean:
                    is_ml_clean = await MLScanner.analyze_bytes(file_path)
                    if is_ml_clean:
                        is_safe = True

        # Route B: CDR Pipeline (Documents - Zero Trust)
        elif "pdf" in mime_type:
            logger.info(f"[{file_path.name}] Route B: CDR Pipeline (PDF)")
            is_safe = await PDFSanitizer.sanitize_pdf(file_path)
            if is_safe:
                is_safe = await DLPScanner.scan_for_sensitive_data(file_path)
            
        elif "officedocument" in mime_type or "msword" in mime_type:
            logger.info(f"[{file_path.name}] Route B: CDR Pipeline (Office)")
            is_safe = await OfficeSanitizer.sanitize_ooxml(file_path)
            if is_safe:
                is_safe = await DLPScanner.scan_for_sensitive_data(file_path)
            
        # Fallback (Media/Text/Unknown)
        else:
            logger.info(f"[{file_path.name}] Default Route: Static Scanning (Media/Text/Unknown)")
            is_vt_clean = await StaticScanner.check_virustotal(file_path)
            if is_vt_clean:
                is_yara_clean = await StaticScanner.scan_yara(file_path)
                if is_yara_clean:
                    is_safe = await DLPScanner.scan_for_sensitive_data(file_path)

        if not is_safe:
            logger.warning(f"File {file_path.name} failed triage and was DROPPED.")
            
        return file_path if is_safe else None

    def _safe_unpack(self, archive_path: Path, extract_dir: Path) -> List[Path]:
        """
        Safely unpack ZIP and TAR archives while enforcing limits BEFORE extraction.
        Prevents Zip-Bomb and Zip-Slip attacks.
        """
        extracted_files = []
        total_extracted_size = 0
        file_count = 0
        
        resolved_extract_dir = extract_dir.resolve()

        if zipfile.is_zipfile(archive_path):
            with zipfile.ZipFile(archive_path, 'r') as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                        
                    file_count += 1
                    if file_count > self.max_files:
                        raise SecurityViolation(f"Archive exceeds max file count limit ({self.max_files})")
                        
                    if info.file_size > self.max_file_size:
                        raise SecurityViolation(f"File {info.filename} exceeds max file size limit.")
                        
                    total_extracted_size += info.file_size
                    if total_extracted_size > self.max_total_size:
                        raise SecurityViolation("Archive exceeds max total extraction size.")

                    # Zip-Slip Prevention
                    target_path = (extract_dir / info.filename).resolve()
                    if not str(target_path).startswith(str(resolved_extract_dir)):
                        logger.warning(f"Zip-Slip attempt detected and blocked! File: {info.filename}")
                        continue

                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(info.filename) as source, open(target_path, "wb") as target:
                        shutil.copyfileobj(source, target)
                        
                    extracted_files.append(target_path)
                    
        elif tarfile.is_tarfile(archive_path):
            with tarfile.open(archive_path, 'r:*') as tf:
                for member in tf.getmembers():
                    if member.isdir():
                        continue
                        
                    file_count += 1
                    if file_count > self.max_files:
                        raise SecurityViolation(f"Archive exceeds max file count limit ({self.max_files})")
                        
                    if member.size > self.max_file_size:
                        raise SecurityViolation(f"File {member.name} exceeds max file size limit.")
                        
                    total_extracted_size += member.size
                    if total_extracted_size > self.max_total_size:
                        raise SecurityViolation("Archive exceeds max total extraction size.")

                    # Tar-Slip Prevention
                    target_path = (extract_dir / member.name).resolve()
                    if not str(target_path).startswith(str(resolved_extract_dir)):
                        logger.warning(f"Tar-Slip attempt detected and blocked! File: {member.name}")
                        continue

                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    
                    if member.isreg():
                        f = tf.extractfile(member)
                        if f is not None:
                            with open(target_path, "wb") as target:
                                shutil.copyfileobj(f, target)
                            extracted_files.append(target_path)
                    else:
                        logger.warning(f"Skipping non-regular tar member: {member.name}")
        else:
            raise SecurityViolation("Unsupported archive format or corrupted file.")
            
        return extracted_files

    async def _unpack_and_process_archive(self, input_path: Path, staging_dir: Path) -> bool:
        """
        Unpacks archive, processes contents concurrently, and repacks into a clean ZIP.
        """
        extract_dir = staging_dir / "extracted"
        extract_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            extracted_files = await asyncio.to_thread(self._safe_unpack, input_path, extract_dir)
        except SecurityViolation as e:
            logger.error(f"Security violation extracting {input_path.name}: {e}")
            return False
        except Exception as e:
            logger.error(f"Error unpacking {input_path.name}: {e}")
            return False
            
        # Triage and Route all extracted files concurrently
        tasks = []
        for file_path in extracted_files:
            try:
                mime_type = magic.from_file(str(file_path), mime=True)
            except Exception:
                mime_type = "application/octet-stream"
                
            tasks.append(self._process_atomic_file(file_path, mime_type, extract_dir))
            
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        safe_files = []
        for res in results:
            if isinstance(res, Exception):
                logger.error(f"Pipeline error during concurrent processing: {res}")
            elif res is not None:
                safe_files.append(res)
                
        if not safe_files:
            logger.warning(f"All files inside {input_path.name} were dropped. Archive is fully malicious or empty.")
            return False
            
        # The Compiler: Repack into a clean ZIP archive (standard enterprise output)
        repack_path = staging_dir / f"clean_{input_path.stem}.zip"
        await asyncio.to_thread(self._repack_archive, repack_path, safe_files, extract_dir)
        
        # Replace original with the sanitized archive
        shutil.move(repack_path, input_path.with_suffix('.zip'))
        
        # Clean up the original if it wasn't a zip (e.g. tar.gz to zip conversion)
        if input_path.suffix != '.zip' and input_path.exists():
            input_path.unlink()
            
        return True

    def _repack_archive(self, output_archive: Path, safe_files: List[Path], base_dir: Path):
        """Creates a new ZIP archive containing only the safe files, maintaining structure."""
        with zipfile.ZipFile(output_archive, 'w', zipfile.ZIP_DEFLATED) as zf:
            for file_path in safe_files:
                relative_path = file_path.relative_to(base_dir)
                zf.write(file_path, arcname=str(relative_path))
                logger.debug(f"Repacked safe file: {relative_path}")

    async def process(self, input_archive_path: str, output_archive_path: str) -> bool:
        """
        Universal entry point for the Sanitization Pipeline.
        """
        input_path = Path(input_archive_path)
        output_path = Path(output_archive_path)

        if not input_path.exists():
            logger.error(f"Input file not found: {input_path}")
            return False

        try:
            mime_type = magic.from_file(str(input_path), mime=True)
        except Exception as e:
            logger.error(f"Failed to determine MIME type for {input_path.name}: {e}")
            return False

        # Create a secure temporary staging directory for this execution
        with tempfile.TemporaryDirectory(prefix="sanitization_staging_") as staging_dir_str:
            staging_dir = Path(staging_dir_str)
            staging_input = staging_dir / input_path.name
            
            try:
                shutil.copy2(input_path, staging_input)
            except Exception as e:
                logger.error(f"Failed to copy input to staging environment: {e}")
                return False

            success = False
            final_staging_file = staging_input

            # Determine routing path
            if any(ext in mime_type for ext in ["zip", "tar", "gzip", "bzip2", "x-rar", "7z"]):
                logger.info(f"[{input_path.name}] Identified as ARCHIVE. Unpacking contents...")
                success = await self._unpack_and_process_archive(staging_input, staging_dir)
                final_staging_file = staging_input.with_suffix('.zip')
            else:
                logger.info(f"[{input_path.name}] Identified as ATOMIC FILE. Routing directly...")
                result = await self._process_atomic_file(staging_input, mime_type, staging_dir)
                if result is not None:
                    success = True
                    final_staging_file = result

            if success and final_staging_file.exists():
                try:
                    # Export the final clean file to the requested output path
                    shutil.move(str(final_staging_file), str(output_path))
                    logger.info(f"Sanitization complete! Safe output generated.")
                    return True
                except Exception as e:
                    logger.error(f"Failed to export clean file: {e}")
                    return False
            else:
                logger.error(f"Sanitization aborted. {input_path.name} was rejected.")
                return False
