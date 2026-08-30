import asyncio
import logging
from pathlib import Path

import pikepdf

logger = logging.getLogger("PDFSanitizer")

class PDFSanitizer:
    @staticmethod
    def _sanitize_pdf_sync(file_path: Path) -> bool:
        """
        Synchronously opens, cleans, and saves a PDF.
        """
        try:
            with pikepdf.Pdf.open(str(file_path)) as pdf:
                # Remove common active content/malicious vectors
                
                # 1. Remove JavaScript from Names dictionary
                if "/Names" in pdf.Root and "/JavaScript" in pdf.Root["/Names"]:
                    del pdf.Root["/Names"]["/JavaScript"]
                    logger.info(f"Stripped JavaScript from Names dictionary in {file_path.name}")
                    
                # 2. Remove OpenAction (can trigger execution/scripts on open)
                if "/OpenAction" in pdf.Root:
                    del pdf.Root["/OpenAction"]
                    logger.info(f"Stripped OpenAction from {file_path.name}")
                
                # 3. Remove AA (Additional Actions) which can also trigger scripts
                if "/AA" in pdf.Root:
                    del pdf.Root["/AA"]
                    logger.info(f"Stripped Additional Actions from {file_path.name}")
                
                # The simple act of loading and saving with pikepdf often corrects malformed
                # structures and drops unreferenced junk.
                temp_output = file_path.with_suffix('.tmp_pdf')
                pdf.save(str(temp_output))
                
            # Replace original
            temp_output.replace(file_path)
            return True
            
        except pikepdf.PdfError as e:
            logger.error(f"CDR Failed: {file_path.name} is malformed or not a valid PDF. Error: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during PDF CDR for {file_path.name}: {e}")
            if 'temp_output' in locals() and temp_output.exists():
                temp_output.unlink()
            return False

    @classmethod
    async def sanitize_pdf(cls, file_path: Path) -> bool:
        """
        Asynchronously sanitizes a PDF file by stripping JavaScript and OpenActions.
        Returns True if successful, False if the file was corrupted or malicious.
        """
        logger.info(f"Starting PDF CDR on {file_path.name}")
        try:
            success = await asyncio.to_thread(cls._sanitize_pdf_sync, file_path)
            return success
        except Exception as e:
            logger.error(f"Unexpected async error for PDF {file_path.name}: {e}")
            return False
