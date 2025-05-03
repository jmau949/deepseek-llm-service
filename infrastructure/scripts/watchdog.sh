#!/bin/bash

# Counter to track consecutive failures
OLLAMA_FAILS=0
LLM_SERVICE_FAILS=0
MAX_FAILS=3
CHECK_INTERVAL=300  # Check every 5 minutes
MODEL_NAME="${MODEL_NAME}"

while true; do
  # Check if Ollama container is running
  if ! docker ps | grep -q "ollama"; then
    echo "$(date): Ollama container not running, starting it..."
    docker start ollama 2>/dev/null || true
    sleep 10  # Give more time to initialize
  else
    # Check Ollama API health
    if curl -s -f http://localhost:11434/api/tags > /dev/null 2>&1; then
      # Reset failure counter on success
      OLLAMA_FAILS=0
      echo "$(date): Ollama is healthy"
      
      # Check if model is loaded and being served
      MODEL_CHECK=$(curl -s http://localhost:11434/api/tags | grep -c "$MODEL_NAME" || echo "0")
      if [ "$MODEL_CHECK" -eq "0" ]; then
        echo "$(date): Model $MODEL_NAME is not loaded, serving it now..."
        docker exec ollama ollama pull $MODEL_NAME >/dev/null 2>&1
        if [ $? -ne 0 ]; then
          echo "$(date): CRITICAL - Failed to pull model $MODEL_NAME"
          exit 1
        fi
        docker exec -d ollama ollama serve $MODEL_NAME
      fi
    else
      OLLAMA_FAILS=$((OLLAMA_FAILS+1))
      echo "$(date): Ollama health check failed ($OLLAMA_FAILS/$MAX_FAILS)"
      
      # Only restart after consecutive failures
      if [ $OLLAMA_FAILS -ge $MAX_FAILS ]; then
        echo "$(date): CRITICAL - Restarting Ollama after $MAX_FAILS consecutive failures"
        docker restart ollama 2>/dev/null || true
        if [ $? -ne 0 ]; then
          echo "$(date): CRITICAL - Failed to restart Ollama"
          exit 1
        fi
        OLLAMA_FAILS=0
        sleep 15  # Give more time to restart
        
        # Make sure model is loaded after restart
        echo "$(date): Ensuring model is loaded after restart..."
        docker exec ollama ollama pull $MODEL_NAME >/dev/null 2>&1
        if [ $? -ne 0 ]; then
          echo "$(date): CRITICAL - Failed to pull model after Ollama restart"
          exit 1
        fi
        docker exec -d ollama ollama serve $MODEL_NAME
      fi
    fi
  fi
  
  # Check if LLM service container is running
  if ! docker ps | grep -q "llm-service"; then
    echo "$(date): LLM service container not running, starting it..."
    docker start llm-service 2>/dev/null || true
    if [ $? -ne 0 ]; then
      echo "$(date): CRITICAL - Failed to start LLM service container"
      exit 1
    fi
    sleep 10  # Give more time to initialize
  else
    # Check LLM Service health - first try basic connectivity
    if nc -z localhost ${PORT} &>/dev/null; then
      # Port is open, which is a good first sign
      # Try the direct gRPC checks
      if grpcurl -plaintext localhost:${PORT} list llm.LLMService &>/dev/null; then
        LLM_SERVICE_FAILS=0
        echo "$(date): LLM service reflection API is working"
      elif grpcurl -plaintext -d "{}" localhost:${PORT} llm.LLMService/HealthCheck &>/dev/null; then
        LLM_SERVICE_FAILS=0
        echo "$(date): LLM service direct health check succeeded"
      else
        LLM_SERVICE_FAILS=$((LLM_SERVICE_FAILS+1))
        echo "$(date): LLM service health check failed ($LLM_SERVICE_FAILS/$MAX_FAILS) - port is open but service is not responding"
        
        # Only restart after consecutive failures
        if [ $LLM_SERVICE_FAILS -ge $MAX_FAILS ]; then
          echo "$(date): CRITICAL - Restarting LLM service after $MAX_FAILS consecutive failures"
          docker restart llm-service 2>/dev/null || true
          if [ $? -ne 0 ]; then
            echo "$(date): CRITICAL - Failed to restart LLM service"
            exit 1
          fi
          LLM_SERVICE_FAILS=0
          sleep 15  # Give more time to restart
        fi
      fi
    else
      LLM_SERVICE_FAILS=$((LLM_SERVICE_FAILS+1))
      echo "$(date): LLM service port ${PORT} is not responding ($LLM_SERVICE_FAILS/$MAX_FAILS)"
      
      # Only restart after consecutive failures
      if [ $LLM_SERVICE_FAILS -ge $MAX_FAILS ]; then
        echo "$(date): CRITICAL - Restarting LLM service after $MAX_FAILS consecutive failures"
        docker restart llm-service 2>/dev/null || true
        if [ $? -ne 0 ]; then
          echo "$(date): CRITICAL - Failed to restart LLM service"
          exit 1
        fi
        LLM_SERVICE_FAILS=0
        sleep 15  # Give more time to restart
      fi
    fi
  fi
  
  sleep $CHECK_INTERVAL
done 