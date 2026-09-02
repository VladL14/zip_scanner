# Use the official lightweight Python image.
# https://hub.docker.com/_/python
FROM python:3.11-slim

# Allow statements and log messages to immediately appear in the Knative logs
ENV PYTHONUNBUFFERED True

# Set the working directory in the container
WORKDIR /app

# Install system dependencies
# libmagic1 is strictly required by python-magic for MIME type detection on Linux
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Copy the local package files to the container's workspace
COPY requirements.txt ./

# Install python dependencies from requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy local code to the container image
COPY . ./

# Run the web service on container startup.
# Cloud Run expects the app to listen on port 8080 by default.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
