FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Install system dependencies for dcap-qvl (Intel TDX quote verification)
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    pkg-config \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy TEE providers code
COPY . /app/

# Install Python dependencies
RUN pip install --no-cache-dir \
    requests \
    eth-account \
    cryptography \
    dcap-qvl \
    pytest

# Make scripts executable
RUN chmod +x near_validating_provider.py venice_client.py test_validating_provider.py

# Default command: run tests
CMD ["python", "test_validating_provider.py"]
