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

# Install grpcio-reflection for healthchecks
# Use exact versions that are compatible with each other
RUN pip install --no-cache-dir protobuf==4.25.1 grpcio==1.62.0 grpcio-reflection==1.62.0 grpcio-tools==1.62.0

# Copy proto files and generate Python code
COPY proto/ proto/
COPY scripts/ scripts/
RUN python scripts/generate_proto.py && \
    # Verify HealthCheck method exists in the generated files
    grep -q "HealthCheck" proto/llm_pb2.py && \
    grep -q "HealthCheck" proto/llm_pb2_grpc.py && \
    echo "Successfully verified HealthCheck method in generated proto files"

# Copy source code
COPY llm_service/ llm_service/

# Final stage
FROM nvidia/cuda:12.1.0-cudnn8-runtime-ubuntu22.04

# Install Python 3.10, pip, and other dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    python3.10 \
    python3-pip \
    curl \
    unzip \
    ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install gRPC tools and dependencies using pip for the final stage's Python environment
RUN pip3 install --no-cache-dir protobuf==4.25.1 grpcio==1.62.0 grpcio-reflection==1.62.0 grpcio-tools==1.62.0

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=50051 \
    WORKER_THREADS=10 \
    OLLAMA_URL="http://localhost:11434" \
    MODEL_NAME="deepseek-r1:7b" \
    LOG_LEVEL="INFO" \
    # Reflection API for healthchecks
    REFLECTION_ENABLED="true" \
    # Sticky session configuration
    STICKY_SESSION_ENABLED="true" \
    STICKY_SESSION_COOKIE="LlmServiceStickiness" \
    # HTTP/2 settings for ALB
    GRPC_ENABLE_HTTP2=1 \
    GRPC_KEEPALIVE_TIME_MS=30000 \
    GRPC_KEEPALIVE_TIMEOUT_MS=20000 \
    GRPC_KEEPALIVE_PERMIT_WITHOUT_CALLS=1 \
    GRPC_HTTP2_MIN_SENT_PING_INTERVAL_WITHOUT_DATA_MS=30000 \
    GRPC_HTTP2_MAX_PINGS_WITHOUT_DATA=0 \
    # TLS settings - disabled by default
    USE_TLS="false"

WORKDIR /app

# Copy dependencies and source code from builder
COPY --from=builder /usr/local/lib/python3.10/site-packages /usr/local/lib/python3.10/site-packages
COPY --from=builder /build/proto/*.py /app/proto/
COPY --from=builder /build/llm_service /app/llm_service
COPY --from=builder /build/scripts /app/scripts
COPY proto/*.proto proto/

# Create an empty __init__.py in the proto directory
RUN mkdir -p /app/proto && touch /app/proto/__init__.py

# Link python3 to python and pip3 to pip if necessary
RUN ln -sf /usr/bin/python3.10 /usr/bin/python3 && \
    ln -sf /usr/bin/python3 /usr/bin/python && \
    ln -sf /usr/bin/pip3 /usr/bin/pip

# Install grpcurl for health checks
RUN curl -sSL "https://github.com/fullstorydev/grpcurl/releases/download/v1.8.7/grpcurl_1.8.7_linux_x86_64.tar.gz" | tar -xz -C /usr/local/bin grpcurl

# Create health check file
RUN echo '#!/bin/sh\n\
# First check if the port is open using built-in bash\n\
if (timeout 1 bash -c "</dev/tcp/localhost/$PORT") 2>/dev/null; then\n\
  echo "Port connectivity: success"\n\
  # Try reflection check first\n\
  if grpcurl -plaintext localhost:$PORT list llm.LLMService 2>/dev/null; then\n\
    echo "Reflection check: success"\n\
    exit 0\n\
  fi\n\
  \n\
  # Try direct method call if reflection fails\n\
  if grpcurl -plaintext -d "{}" localhost:$PORT llm.LLMService/HealthCheck 2>/dev/null; then\n\
    echo "Direct method call: success"\n\
    exit 0\n\
  fi\n\
  \n\
  echo "Port is open but both reflection and direct method calls failed"\n\
  exit 1\n\
else\n\
  echo "Port connectivity: failed"\n\
  exit 1\n\
fi' > /healthcheck.sh && \
    chmod +x /healthcheck.sh

# Create directory for TLS certificates
RUN mkdir -p /app/certs

# Expose gRPC port
EXPOSE $PORT

# Health check using grpcurl
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD /healthcheck.sh

# Set Python path
ENV PYTHONPATH=/app

# Regenerate proto files from source proto files
RUN cd /app && python -m scripts.generate_proto && \
    # Verify HealthCheck method exists
    grep -q "HealthCheck" /app/proto/llm_pb2.py && \
    grep -q "HealthCheck" /app/proto/llm_pb2_grpc.py && \
    echo "Successfully verified proto files include HealthCheck method"

# Run the service
CMD ["python", "-m", "llm_service.main"]