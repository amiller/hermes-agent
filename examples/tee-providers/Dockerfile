FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy probe scripts
COPY near_client.py .
COPY venice_client.py .

# Install Python dependencies
RUN pip install --no-cache-dir httpx

# Make scripts executable
RUN chmod +x near_client.py venice_client.py

# Default command: run both probes
CMD echo "=== Running NEAR AI TEE Probe ===" && \
    python near_client.py && \
    echo "" && \
    echo "=== Running Venice TEE Probe ===" && \
    python venice_client.py
