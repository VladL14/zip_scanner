import logging
import shutil
import tempfile
from pathlib import Path

import aiofiles
from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from dotenv import load_dotenv

# Load environment variables from .env file (for local development)
load_dotenv()

from engine import SanitizationEngine
from static_scanner import StaticScanner

# Load YARA rules dynamically at application startup
yara_dir = Path(__file__).parent / "yara_rules"
StaticScanner.load_rules(yara_dir)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger("FastAPI")

app = FastAPI(
    title="Clean-Room-as-a-Service",
    description="Enterprise-grade File Sanitization and Reconstruction API",
    version="1.0.0"
)

# Enable CORS for future frontend integration (e.g., React/Next.js)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def cleanup_temp_dir(temp_dir: str):
    """
    Background task to safely remove the temporary directory
    after the FileResponse has finished streaming the file to the client.
    """
    try:
        shutil.rmtree(temp_dir)
        logger.info(f"Cleaned up temporary workspace: {temp_dir}")
    except Exception as e:
        logger.error(f"Failed to clean up temporary workspace {temp_dir}: {e}")

@app.post("/api/v1/sanitize")
async def sanitize_file(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    """
    Accepts a malicious/unknown ZIP file, runs it through the Clean-Room engine,
    and returns a sanitized ZIP file.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided.")
        
    logger.info(f"Received file for sanitization: {file.filename}")
    
    # Use mkdtemp so we can manually control the cleanup lifecycle via BackgroundTasks
    temp_dir = tempfile.mkdtemp(prefix="clean_room_api_")
    temp_dir_path = Path(temp_dir)
    
    # Schedule cleanup to run strictly AFTER the HTTP response is completed
    background_tasks.add_task(cleanup_temp_dir, temp_dir)
    
    # Keep the original file extension for the input path
    file_suffix = Path(file.filename).suffix
    input_path = temp_dir_path / f"input{file_suffix}"
    
    # Ensure the output filename clearly indicates it's safe
    safe_filename = f"clean_{file.filename}"
    output_path = temp_dir_path / safe_filename
    
    try:
        # Save the uploaded multipart file to disk asynchronously
        async with aiofiles.open(input_path, 'wb') as out_file:
            # Stream in chunks to avoid blowing up memory on huge files
            while content := await file.read(65536):
                await out_file.write(content)
                
        # Initialize and run the core engine
        engine = SanitizationEngine()
        success = await engine.process(str(input_path), str(output_path))
        
        if success and output_path.exists():
            logger.info(f"API returning sanitized file: {safe_filename}")
            
            # Dynamically determine the content type
            import mimetypes
            media_type, _ = mimetypes.guess_type(str(output_path))
            if not media_type:
                media_type = "application/octet-stream"
                
            return FileResponse(
                path=str(output_path),
                filename=safe_filename,
                media_type=media_type
            )
        else:
            logger.warning(f"Sanitization failed or file was fully dropped: {file.filename}")
            raise HTTPException(
                status_code=422,
                detail={"error": "Sanitization failed. The file was malicious or invalid."}
            )
            
    except HTTPException:
        # Re-raise known HTTP exceptions (like our 422 above)
        raise
    except Exception as e:
        logger.error(f"Unexpected error processing file {file.filename}: {e}")
        raise HTTPException(
            status_code=500,
            detail={"error": "An internal server error occurred during processing."}
        )

if __name__ == "__main__":
    import uvicorn
    # Allow running the API directly for local testing
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
