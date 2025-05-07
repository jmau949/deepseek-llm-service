# DeepSeek LLM Service

A gRPC service that provides inference capabilities for DeepSeek language models within an AI chatbot architecture. The service is designed to be deployed behind an AWS Application Load Balancer with sticky sessions for conversation persistence.

## Architecture Overview

This service is part of a larger AI chatbot architecture:

```
┌─────────────┐    ┌───────────┐    ┌──────────────┐
│ React Client │───▶│ API Gateway│───▶│ DynamoDB    │
│ (Frontend)   │    │ WebSockets │    │ (Connections)│
└──────┬───────┘    └─────┬─────┘    └──────────────┘
       │                  │                  
       │                  ▼                  
       │           ┌──────────────┐         
       └──────────▶│ $message     │         
                   │ Lambda       │         
                   └──────┬───────┘         
                          │         ┌─ VPC ───────────────────┐
                          │         │                          │
                          ▼         │      ┌───────────────┐   │
                   ┌──────────────┐ │      │ LLM Service   │   │
                   │ Private ALB  │─┼─────▶│ GPU Instances │   │
                   └──────────────┘ │      └───────────────┘   │
                          ▲         │               │          │
                          │         │               │          │
                          │         │      ┌────────▼────────┐ │
                          │         │      │ NAT Gateway     │ │
                          └─────────┼──────┤ (External Access)│ │
                                    │      └─────────────────┘ │
                                    └──────────────────────────┘
```

## Project Structure

```
llm-service/
├── llm_service/               # Main package
│   ├── __init__.py            # Package initialization
│   ├── main.py                # Entry point
│   ├── service.py             # gRPC service implementation with sticky sessions
│   ├── config.py              # Configuration handling
│   └── utils/                 # Utility modules
│       ├── __init__.py        # Package initialization
│       ├── logging.py         # Logging utilities
│       └── ollama.py          # Ollama API client
│
├── proto/                     # Protocol Buffer definitions
│   └── llm.proto              # LLM service definition
│
├── tests/                     # Tests
│   ├── __init__.py            # Test package initialization
│   ├── test_service.py        # Service tests
│   └── test_ollama.py         # Ollama client tests
│
├── examples/                  # Example code
│   └── client.py              # Example client
│
├── scripts/                   # Utility scripts
│   └── generate_proto.py      # Script to generate Python code from proto
│
├── pyproject.toml             # Poetry configuration (dependencies, etc.)
├── Dockerfile                 # Container definition with HTTPS & sticky session support
└── README.md                  # Documentation
```

## Key Features

- **gRPC Service**: High-performance inference using gRPC and Protocol Buffers
- **Streaming Responses**: Support for streaming model outputs for responsive UX
- **Sticky Sessions**: Ensures conversation continuity through ALB sticky sessions
- **HTTPS Support**: TLS encryption for secure communication
- **Health Checks**: HTTPS-to-gRPC health check bridge for AWS ALB compatibility
- **Docker Support**: Containerized deployment with optimized configuration
- **Configuration Flexibility**: Environment variables for easy configuration

## Sticky Session Implementation

The service implements sticky sessions to ensure that client requests with ongoing conversations always route to the same server instance:

### 1. Cookie Management in gRPC

```python
# In service.py
def GenerateStream(self, request, context):
    # Extract or create session ID for sticky sessions
    session_id = self._get_or_create_session_id(context)
    
    # Set session cookie in metadata for sticky sessions
    if self.config.sticky_session_enabled and session_id:
        context.set_trailing_metadata([
            ('set-cookie', f'{self.config.sticky_session_cookie}={session_id}; Path=/; Max-Age=900; HttpOnly')
        ])
    
    # Process request...
```

### 2. Extracting Existing Session Cookies

```python
def _get_or_create_session_id(self, context):
    # Skip if sticky sessions are disabled
    if not self.config.sticky_session_enabled:
        return None
        
    try:
        # Extract session from gRPC metadata (cookie header)
        metadata = dict(context.invocation_metadata())
        cookie = metadata.get('cookie', '')
        
        # Parse the cookie string to find our session cookie
        if cookie and self.config.sticky_session_cookie in cookie:
            # Process cookie and extract session ID
            # ...
            
        # If no session cookie found, create a new one
        import uuid
        return str(uuid.uuid4())
            
    except Exception as e:
        logger.warning(f"Error processing session cookie: {e}")
        return None
```

### 3. AWS ALB Integration

The sticky session implementation is designed to work with AWS Application Load Balancer:

- The ALB is configured with app-cookie stickiness using the cookie name "LlmServiceStickiness"
- The service reads cookies from incoming gRPC metadata and sets them in trailing metadata
- Session cookies are returned with HTTP security attributes (HttpOnly)
- 15-minute expiration matches the ALB configuration

## HTTPS Health Check Bridge

The service includes a custom HTTPS-to-gRPC health check bridge that allows the AWS ALB to monitor the gRPC service:

1. **HTTPS Health Check Endpoint**: A lightweight Python HTTPS server that listens on port 443
2. **Self-Signed Certificate**: For TLS encryption of health check requests
3. **gRPC Status Check**: Proxies health requests to the gRPC service using grpcurl
4. **Cookie Support**: Sets sticky session cookies in health check responses

## HTTP Health Check Bridge

The service includes a custom HTTP-to-gRPC health check bridge that allows the AWS ALB to monitor the gRPC service:

1. **HTTP Health Check Endpoint**: A lightweight Python HTTP server that listens on port 80
2. **gRPC Status Check**: Proxies health requests to the gRPC service using grpcurl
3. **Cookie Support**: Sets sticky session cookies in health check responses

## Prerequisites

- [Python 3.8+](https://www.python.org/downloads/)
- [Poetry](https://python-poetry.org/docs/#installation)
- [Ollama](https://ollama.ai/download) (running locally or accessible via network)

## Quick Start Guide

### 1. Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/deepseek-llm-service.git
cd deepseek-llm-service/service

# Install dependencies with Poetry
poetry install

# Generate Protocol Buffer code
poetry run python scripts/generate_proto.py
```

### 2. Start the Server

#### On Linux/Mac:
```bash
MODEL_NAME="deepseek-r1:1.5b" STICKY_SESSION_ENABLED="true" poetry run python -m llm_service.main
```

#### On Windows (PowerShell):
```powershell
$env:MODEL_NAME = "deepseek-r1:1.5b"
$env:STICKY_SESSION_ENABLED = "true"
poetry run python -m llm_service.main
```

### 3. Using Docker

```bash
# Build the image
docker build -t llm-service:latest .

# Run with the specified model and sticky sessions enabled

docker run -p 127.0.0.1:50051:50051 -e MODEL_NAME="deepseek-r1:1.5b" -e STICKY_SESSION_ENABLED="true" -e STICKY_SESSION_COOKIE="LlmServiceStickiness" -e OLLAMA_URL="http://host.docker.internal:11434" -e PORT=50051 -e HOST=0.0.0.0 llm-service:latest
```

## Testing the Service

You can test the service using the provided example client:

```bash
poetry run python examples/client.py --stream --prompt "Write a function to calculate factorial"
```

### Testing Sticky Sessions

To test sticky sessions locally:

```bash
# First request - creates a session cookie
poetry run python examples/client.py --stream --cookie-jar cookies.txt --prompt "What is your name?"

# Second request - uses the session cookie
poetry run python examples/client.py --stream --cookie-jar cookies.txt --prompt "Do you remember my previous question?"
```

## Configuration Options

The service offers extensive configuration through environment variables:

### Server Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | gRPC server port | `50051` |
| `WORKER_THREADS` | Number of worker threads | `10` |
| `USE_TLS` | Enable TLS for gRPC | `false` |
| `TLS_CERT_PATH` | Path to TLS certificate | `None` |
| `TLS_KEY_PATH` | Path to TLS key | `None` |

### Model Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `OLLAMA_URL` | Ollama API endpoint | `http://localhost:11434` |
| `MODEL_NAME` | Model to use | `model-name` |
| `REQUEST_TIMEOUT` | Request timeout in seconds | `30` |

### Sticky Session Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `STICKY_SESSION_ENABLED` | Enable sticky sessions | `true` |
| `STICKY_SESSION_COOKIE` | Cookie name for sticky sessions | `LlmServiceStickiness` |

### HTTP/2 and gRPC Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `GRPC_ENABLE_HTTP2` | Enable HTTP/2 for gRPC | `1` |
| `GRPC_KEEPALIVE_TIME_MS` | Keepalive time in ms | `30000` |
| `GRPC_KEEPALIVE_TIMEOUT_MS` | Keepalive timeout in ms | `10000` |
| `GRPC_KEEPALIVE_PERMIT_WITHOUT_CALLS` | Allow keepalive without calls | `1` |
| `HTTP2_MIN_PING_INTERVAL_MS` | HTTP/2 min ping interval in ms | `10000` |
| `HTTP2_MAX_PINGS_WITHOUT_DATA` | Max pings without data | `0` |

### LLM Parameters

| Variable | Description | Default |
|----------|-------------|---------|
| `DEFAULT_TEMPERATURE` | Default temperature | `0.7` |
| `DEFAULT_MAX_TOKENS` | Default max tokens | `2048` |
| `DEFAULT_TOP_P` | Default top-p value | `0.95` |
| `DEFAULT_PRESENCE_PENALTY` | Default presence penalty | `0.0` |
| `DEFAULT_FREQUENCY_PENALTY` | Default frequency penalty | `0.0` |

## Cloud Deployment

When deployed to AWS, the service automatically:

1. Registers with an Application Load Balancer via Auto Scaling Groups
2. Serves HTTP health checks on port 80 for ALB health monitoring
3. Implements sticky sessions using the specified cookie name
4. Uses HTTP/2 with proper settings for gRPC over ALB
5. Supports trailing metadata for cookie setting

## Development Commands

| Command | Description |
|---------|-------------|
| `poetry add package-name` | Add a dependency |
| `poetry add --dev package-name` | Add a dev dependency |
| `poetry update` | Update dependencies |
| `poetry shell` | Activate the virtual environment |
| `poetry build` | Build the package |

## Monitoring

The service includes comprehensive logging:

- Request logging with prompt truncation for privacy
- Session ID tracking for sticky session debugging
- Error logging with full stack traces
- Performance metrics for request handling

CloudWatch logging is automatically configured when deployed to AWS through the infrastructure stack.

## API Documentation

### gRPC Methods

1. **GenerateStream**
   - Streams the model's response token by token
   - Supports sticky sessions via cookies
   - Returns trailing metadata with session cookies

2. **Generate**
   - Returns the complete model response in one call
   - Supports the same parameters as GenerateStream
   - Useful for non-streaming clients

### Request Parameters

```protobuf
message LLMRequest {
  string prompt = 1;
  
  message Parameters {
    float temperature = 1;
    int32 max_tokens = 2;
    float top_p = 3;
    float presence_penalty = 4;
    float frequency_penalty = 5;
  }
  
  Parameters parameters = 2;
}
```

## Troubleshooting

### Common Issues

1. **gRPC Connection Errors**
   - Check if the server is running
   - Verify port is correct and not blocked
   - Check TLS configuration if enabled

2. **Sticky Session Issues**
   - Verify STICKY_SESSION_ENABLED is true
   - Check cookie handling in client code
   - Look for Set-Cookie in trailing metadata

3. **Performance Problems**
   - Adjust worker thread count
   - Ensure appropriate instance size in AWS
   - Monitor CPU and memory usage

## Future Improvements

Potential enhancements to consider:

1. **Context Management**: Implement server-side conversation context tracking
2. **Advanced Routing**: Session affinity based on conversation context
3. **Authentication**: Integrate with API Gateway authentication mechanisms
4. **Prometheus Metrics**: Export metrics for detailed performance monitoring
5. **Session Persistence**: DynamoDB backing for session state beyond instance lifecycle