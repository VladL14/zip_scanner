import asyncio
import logging
import os
import tempfile
import zipfile
import xml.etree.ElementTree as ET
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
        rel_path = file_path.relative_to(base_dir).as_posix().lower()
        
        if file_path.name.lower() in OfficeSanitizer.SUSPICIOUS_NAMES:
            return True
            
        if file_path.suffix.lower() in OfficeSanitizer.SUSPICIOUS_EXTENSIONS:
            return True
            
        for susp_path in OfficeSanitizer.SUSPICIOUS_PATHS:
            if susp_path in rel_path:
                return True
                
        return False

    @staticmethod
    def _clean_xml_references(temp_path: Path):
        """
        Removes references to deleted malicious files from XML files 
        to prevent MS Office from throwing 'Document Needs Recovery' errors.
        """
        content_types_ns = 'http://schemas.openxmlformats.org/package/2006/content-types'
        rels_ns = 'http://schemas.openxmlformats.org/package/2006/relationships'
        
        ET.register_namespace('', content_types_ns)
        
        content_types_path = temp_path / '[Content_Types].xml'
        if content_types_path.exists():
            try:
                tree = ET.parse(content_types_path)
                root = tree.getroot()
                
                # Remove <Override> tags that reference deleted macros
                for elem in root.findall(f"{{{content_types_ns}}}Override"):
                    part_name = elem.get('PartName', '').lower()
                    if 'vba' in part_name or part_name.endswith('.bin'):
                        root.remove(elem)
                
                tree.write(content_types_path, xml_declaration=True, encoding='UTF-8')
            except Exception as e:
                logger.warning(f"Failed to clean [Content_Types].xml: {e}")

        ET.register_namespace('', rels_ns)
        
        # Clean all .rels files
        for root_dir, _, files in os.walk(temp_path):
            for file in files:
                if file.endswith('.rels'):
                    rels_path = Path(root_dir) / file
                    try:
                        tree = ET.parse(rels_path)
                        root = tree.getroot()
                        
                        # Remove <Relationship> tags where Target points to deleted macros
                        for elem in root.findall(f"{{{rels_ns}}}Relationship"):
                            target = elem.get('Target', '').lower()
                            if 'vba' in target or target.endswith('.bin'):
                                root.remove(elem)
                                
                        tree.write(rels_path, xml_declaration=True, encoding='UTF-8')
                    except Exception as e:
                        logger.warning(f"Failed to clean rels file {file}: {e}")

    @staticmethod
    def _process_ooxml_sync(file_path: Path) -> bool:
        """
        Synchronous I/O bound logic to extract, strip, and repack the OOXML container.
        """
        if not zipfile.is_zipfile(file_path):
            logger.warning(f"CDR: {file_path.name} is not a valid ZIP/OOXML file.")
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

            # 2. Sanitize contents (Drop dangerous physical files)
            for root, dirs, files in os.walk(temp_path):
                for f in files:
                    full_path = Path(root) / f
                    if OfficeSanitizer._is_suspicious(full_path, temp_path):
                        logger.info(f"CDR Stripped malicious asset from {file_path.name}: {full_path.relative_to(temp_path)}")
                        full_path.unlink() # Delete the dangerous file

            # 3. Fix XML References (So MS Word doesn't crash/complain)
            OfficeSanitizer._clean_xml_references(temp_path)

            # 4. Repack the container
            try:
                temp_output = file_path.with_suffix('.tmp_cdr')
                with zipfile.ZipFile(temp_output, 'w', zipfile.ZIP_DEFLATED) as zf:
                    for root, dirs, files in os.walk(temp_path):
                        for f in files:
                            sf = Path(root) / f
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
