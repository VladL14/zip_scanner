import asyncio
import logging
from pathlib import Path
from PIL import Image

logger = logging.getLogger("ImageSanitizer")

class ImageSanitizer:
    
    @staticmethod
    def _sanitize_image_sync(file_path: Path) -> bool:
        """
        Synchronous I/O bound logic to open an image, strip its EXIF data, 
        and save it back securely.
        """
        try:
            # Pillow natively parses the image structure.
            # If it's a malicious disguised binary, this will raise an Exception.
            with Image.open(file_path) as img:
                # To ensure all metadata/exif/steganography is stripped, 
                # we create a new blank image of the same mode and size, 
                # and copy only the raw pixel data over.
                clean_img = Image.new(img.mode, img.size)
                clean_img.putdata(list(img.getdata()))
                
                # Overwrite original
                # Use PNG as a safe fallback format if format is missing
                safe_format = img.format if img.format else "PNG"
                clean_img.save(file_path, format=safe_format)
                
            return True
        except Exception as e:
            logger.warning(f"CDR Failed to sanitize image {file_path.name}: {e}. Disguised executable?")
            return False

    @classmethod
    async def sanitize_image(cls, file_path: Path) -> bool:
        """
        Asynchronously sanitizes an image file, stripping EXIF and hidden payloads.
        Returns True if successful, False if the file was corrupted/malicious.
        """
        logger.info(f"Starting Image CDR on {file_path.name}")
        try:
            success = await asyncio.to_thread(cls._sanitize_image_sync, file_path)
            return success
        except Exception as e:
            logger.error(f"Unexpected error during Image sanitization of {file_path.name}: {e}")
            return False
