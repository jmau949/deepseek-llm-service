#!/usr/bin/env python3
"""
Example client for the LLM gRPC service.
"""

import argparse
import grpc
import sys
import os

# Add the project root to the path so we can import the proto modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the generated proto code
from proto import llm_pb2, llm_pb2_grpc


def main():
    """Run the example client."""
    parser = argparse.ArgumentParser(description="Example client for LLM gRPC service")
    parser.add_argument(
        "--server", type=str, default="localhost:50051", help="Server address"
    )
    parser.add_argument(
        "--prompt", type=str, default="Write a function to calculate fibonacci numbers",
        help="Prompt to send to the LLM"
    )
    parser.add_argument(
        "--temperature", type=float, default=0.7, help="Temperature"
    )
    parser.add_argument(
        "--max-tokens", type=int, default=1000, help="Maximum tokens to generate"
    )
    parser.add_argument(
        "--stream", action="store_true", help="Use streaming RPC"
    )
    
    args = parser.parse_args()

    # Create a gRPC channel
    channel = grpc.insecure_channel(args.server)
    
    # Create a stub (client)
    stub = llm_pb2_grpc.LLMServiceStub(channel)
    
    # Create a request
    request = llm_pb2.LLMRequest(
        prompt=args.prompt,
        parameters=llm_pb2.LLMRequest.Parameters(
            temperature=args.temperature,
            max_tokens=args.max_tokens,
            top_p=0.95,
            presence_penalty=0.0,
            frequency_penalty=0.0
        )
    )
    
    try:
        if args.stream:
            # For streaming responses
            print(f"Sending streaming request to {args.server}...")
            for response in stub.GenerateStream(request):
                print(response.text, end="", flush=True)
                if response.is_complete:
                    print("\n\nGeneration complete!")
        else:
            # For complete responses
            print(f"Sending request to {args.server}...")
            response = stub.Generate(request)
            print(response.text)
            print("\nGeneration complete!")
    except grpc.RpcError as e:
        print(f"RPC error: {e.code()}: {e.details()}")
    finally:
        channel.close()


if __name__ == "__main__":
    main()