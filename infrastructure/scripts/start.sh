#!/bin/bash
# Get instance ID for logging
INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)

# Create network
docker network create llm-network 2>/dev/null || true

# Start Ollama
docker run -d --name ollama --restart always --network llm-network \
  -v ollama-data:/root/.ollama \
  -p 11434:11434 \
  --log-driver=awslogs \
  --log-opt awslogs-group=${LOG_GROUP_NAME} \
  --log-opt awslogs-region=${REGION} \
  --log-opt awslogs-stream="$INSTANCE_ID/ollama" \
  ollama/ollama:latest

echo "Waiting for Ollama to initialize..."
sleep 10

# Pull the model first (with retries) before starting the LLM service
MODEL_NAME="${MODEL_NAME}"
MAX_ATTEMPTS=3
ATTEMPT=1

while [ $ATTEMPT -le $MAX_ATTEMPTS ]; do
  echo "Pulling model $MODEL_NAME (attempt $ATTEMPT/$MAX_ATTEMPTS)..."
  if docker exec ollama ollama pull $MODEL_NAME; then
    echo "Model pulled successfully"
    # Explicitly serve the model
    echo "Starting to serve the model..."
    docker exec -d ollama ollama serve $MODEL_NAME
    break
  else
    echo "Model pull attempt $ATTEMPT failed"
    if [ $ATTEMPT -eq $MAX_ATTEMPTS ]; then
      echo "Failed to pull model after $MAX_ATTEMPTS attempts"
      exit 1  # Fail explicitly
    else
      echo "Retrying in 10 seconds..."
      sleep 10
    fi
    ATTEMPT=$((ATTEMPT+1))
  fi
done

# Start LLM Service
docker run -d --name llm-service --restart always --network llm-network \
  -p ${PORT}:${PORT} \
  -e PORT=${PORT} \
  -e WORKER_THREADS=10 \
  -e OLLAMA_URL=http://ollama:11434 \
  -e MODEL_NAME=$MODEL_NAME \
  -e LOG_LEVEL=INFO \
  -e REFLECTION_ENABLED=true \
  -e GRPC_ENABLE_HTTP2=1 \
  -e GRPC_KEEPALIVE_TIME_MS=30000 \
  -e GRPC_KEEPALIVE_TIMEOUT_MS=20000 \
  -e GRPC_KEEPALIVE_PERMIT_WITHOUT_CALLS=1 \
  -e GRPC_HTTP2_MIN_SENT_PING_INTERVAL_WITHOUT_DATA_MS=30000 \
  -e GRPC_HTTP2_MAX_PINGS_WITHOUT_DATA=0 \
  -e STICKY_SESSION_COOKIE=LlmServiceStickiness \
  --log-driver=awslogs \
  --log-opt awslogs-group=${LOG_GROUP_NAME} \
  --log-opt awslogs-region=${REGION} \
  --log-opt awslogs-stream="$INSTANCE_ID/llm-service" \
  ${ECR_REPO}/llm-service:latest

if [ $? -ne 0 ]; then
  echo "Failed to start LLM service"
  exit 1
fi

echo "Service deployment complete" 