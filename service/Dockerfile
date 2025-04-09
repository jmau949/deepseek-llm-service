# Build stage
FROM python:3.10-slim AS builder

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install poetry
RUN pip install --no-cache-dir poetry

# Copy poetry configuration
COPY pyproject.toml poetry.lock* ./

# Configure poetry to not create a virtual environment
RUN poetry config virtualenvs.create false

# Install dependencies
RUN poetry install --without dev --no-root --no-interaction --no-ansi

# Copy proto files and generate Python code
COPY proto/ proto/
COPY scripts/ scripts/
RUN python scripts/generate_proto.py

# Copy source code
COPY llm_service/ llm_service/

# Final stage
FROM python:3.10-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=50051 \
    WORKER_THREADS=10 \
    OLLAMA_URL="http://localhost:11434" \
    MODEL_NAME="model-name" \
    LOG_LEVEL="INFO"

WORKDIR /app

# Copy dependencies and source code from builder
COPY --from=builder /usr/local/lib/python3.10/site-packages /usr/local/lib/python3.10/site-packages
COPY --from=builder /build/proto/*.py /app/proto/
COPY --from=builder /build/llm_service /app/llm_service
COPY --from=builder /build/scripts /app/scripts

# Create an empty __init__.py in the proto directory
RUN mkdir -p /app/proto && touch /app/proto/__init__.py

# Install grpcurl for health checks
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    curl \
    unzip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && curl -sSL "https://github.com/fullstorydev/grpcurl/releases/download/v1.8.7/grpcurl_1.8.7_linux_x86_64.tar.gz" | tar -xz -C /usr/local/bin grpcurl

# Create health check file
RUN echo '#!/bin/sh\ngrpcurl -plaintext localhost:$PORT list llm.LLMService 2>/dev/null || exit 1' > /healthcheck.sh && \
    chmod +x /healthcheck.sh

# Expose gRPC port
EXPOSE $PORT

# Health check using grpcurl
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD /healthcheck.sh

# Set Python path
ENV PYTHONPATH=/app

# Run the service
CMD ["python", "-m", "llm_service.main"]