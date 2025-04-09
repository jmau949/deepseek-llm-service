## Testing the Service

Once you have the server running, you can test it using the provided example client or by writing your own client. Below are detailed instructions for both approaches.

### 1. Using the Example Client (Recommended)

The repository includes an example client that makes it easy to test the service. Open a new terminal window (keep the server running in the original terminal) and run:

#### On Linux/Mac:
```bash
cd llm-service
poetry run python examples/client.py --stream --prompt "Write a function to calculate factorial"
```

#### On Windows (PowerShell):
```powershell
cd llm-service
poetry run python examples/client.py --stream --prompt "Write a function to calculate factorial"
```

You should see the model's response streaming to your terminal.

### 2. Testing with a Custom Client

If you prefer to write your own client or test with other tools:

#### Using Python:
```python
import grpc
from proto import llm_pb2, llm_pb2_grpc

# Connect to the service
channel = grpc.insecure_channel('localhost:50051')
stub = llm_pb2_grpc.LLMServiceStub(channel)

# Create a request
request = llm_pb2.LLMRequest(
    prompt="Write a function to calculate factorial",
    parameters=llm_pb2.LLMRequest.Parameters(
        temperature=0.7,
        max_tokens=1000,
        top_p=0.95
    )
)

# Streaming request
for response in stub.GenerateStream(request):
    print(response.text, end="", flush=True)
    if response.is_complete:
        print("\nGeneration complete!")
```

#### Using grpcurl (Command Line):
If you have grpcurl installed, you can test the service directly from the command line:

```bash
# List available services
grpcurl -plaintext localhost:50051 list

# List methods in the service
grpcurl -plaintext localhost:50051 list llm.LLMService

# Call the Generate method
grpcurl -plaintext -d '{"prompt": "Write a function to calculate factorial", "parameters": {"temperature": 0.7, "max_tokens": 1000}}' localhost:50051 llm.LLMService/Generate
```

### 3. Troubleshooting

If you encounter issues with the test client:

1. **Check server logs**: Make sure the server is running and not showing errors
2. **Verify port**: Ensure the client is connecting to the same port the server is using (default: 50051)
3. **Check proto generation**: If you get import errors, make sure you've run the proto generation script:
   ```bash
   poetry run python scripts/generate_proto.py
   ```
4. **Import path**: If you're writing a custom client outside the repo, make sure the proto directory is in your Python path```markdown
# LLM Service

A gRPC service that provides a standardized interface to language models running on Ollama.

## Project Structure

```
llm-service/
├── llm_service/               # Main package
│   ├── __init__.py            # Package initialization
│   ├── main.py                # Entry point
│   ├── service.py             # gRPC service implementation
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
├── Dockerfile                 # Container definition
└── README.md                  # Documentation
```

## Prerequisites

- [Python 3.8+](https://www.python.org/downloads/)
- [Poetry](https://python-poetry.org/docs/#installation)
- [Ollama](https://ollama.ai/download) (running locally or accessible via network)

## Quick Start Guide

### 1. Prerequisites

- Python 3.8+ installed
- Poetry installed
- Ollama installed and running with a language model (e.g., deepseek-r1:1.5b)

### 2. Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/llm-service.git
cd llm-service

# Install dependencies with Poetry
poetry install

# Generate Protocol Buffer code
poetry run python scripts/generate_proto.py
```

### 3. Start the Server

#### On Linux/Mac:
```bash
MODEL_NAME="deepseek-r1:1.5b" poetry run python -m llm_service.main
```

#### On Windows (PowerShell):
```powershell
$env:MODEL_NAME = "deepseek-r1:1.5b"
poetry run python -m llm_service.main
```

You should see output like:
```
2025-04-07 XX:XX:XX,XXX - llm_service - INFO - Logging initialized with level=INFO
2025-04-07 XX:XX:XX,XXX - llm_service - INFO - Starting LLM Service
2025-04-07 XX:XX:XX,XXX - llm_service - INFO - Configuration: port=50051, workers=10, ollama_url=http://localhost:11434, model=deepseek-r1:1.5b
2025-04-07 XX:XX:XX,XXX - llm_service - INFO - Server started, listening on port 50051
```

### 4. Test the Service

Open a new terminal window and run:

#### On Linux/Mac:
```bash
poetry run python examples/client.py --stream --prompt "Write a function to calculate factorial"
```

#### On Windows (PowerShell):
```powershell
poetry run python examples/client.py --stream --prompt "Write a function to calculate factorial"
```

### 5. Expected Result

You should see the model generating text in real-time, like:
```
Sending streaming request to localhost:50051...
def factorial(n):
    if n == 0 or n == 1:
        return 1
    else:
        return n * factorial(n-1)

# Example usage:
print(factorial(5))  # Output: 120

Generation complete!
```


### Configuration Options

Set these environment variables to configure the service:

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | gRPC server port | `50051` |
| `WORKER_THREADS` | Number of worker threads | `10` |
| `OLLAMA_URL` | Ollama API endpoint | `http://localhost:11434` |
| `MODEL_NAME` | Model to use | `model-name` |
| `LOG_LEVEL` | Logging level | `INFO` |

## Testing

```bash
# Run all tests
poetry run pytest

# Run with coverage report
poetry run pytest --cov=llm_service tests/

# Run specific test file
poetry run pytest tests/test_service.py
```

## Using Docker

### Build

```bash
docker build -t llm-service:latest .
```

### Docker

```bash
# Build the image
docker build -t llm-service:latest .

# Run with the specified model
docker run -p 50051:50051 -e MODEL_NAME="deepseek-r1:1.5b" -e OLLAMA_URL="http://host.docker.internal:11434" llm-service:latest
```

## Development Commands

| Command | Description |
|---------|-------------|
| `poetry add package-name` | Add a dependency |
| `poetry add --dev package-name` | Add a dev dependency |
| `poetry update` | Update dependencies |
| `poetry shell` | Activate the virtual environment |
| `poetry build` | Build the package |

### Example Client Code

Here's a simple Python client to test the service:

```python
import grpc
from proto import llm_pb2, llm_pb2_grpc

# Connect to the service
channel = grpc.insecure_channel('localhost:50051')
stub = llm_pb2_grpc.LLMServiceStub(channel)

# Create a request
request = llm_pb2.LLMRequest(
    prompt="Write a function to calculate fibonacci numbers",
    parameters=llm_pb2.LLMRequest.Parameters(
        temperature=0.7,
        max_tokens=1000,
        top_p=0.95
    )
)

# For streaming responses
try:
    for response in stub.GenerateStream(request):
        print(response.text, end="", flush=True)
        if response.is_complete:
            print("\nGeneration complete!")
except grpc.RpcError as e:
    print(f"RPC error: {e.code()}: {e.details()}")
```

Or use the provided example client:

```bash
# Run the example client
MODEL_NAME="deepseek-r1:1.5b" poetry run python examples/client.py --stream
```

## License

[Your license here]
```