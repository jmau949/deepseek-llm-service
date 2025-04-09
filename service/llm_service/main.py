#!/usr/bin/env python3
"""
LLM gRPC Service Entry Point
----------------------------
Main entry point for the LLM gRPC service.
"""

import argparse
import sys

from llm_service.config import Config
from llm_service.service import serve
from llm_service.utils.logging import setup_logging


def main():
    """Main entry point for the service."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="LLM gRPC Service")
    parser.add_argument(
        "--config", type=str, default=None, help="Path to configuration file"
    )
    parser.add_argument(
        "--port", type=int, default=None, help="Port to listen on (overrides config)"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="Number of worker threads (overrides config)",
    )
    parser.add_argument(
        "--ollama-url",
        type=str,
        default=None,
        help="Ollama API URL (overrides config)",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Model name to use (overrides config)",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging level (overrides config)",
    )
    
    args = parser.parse_args()

    # Set up logging
    logger = setup_logging(args.log_level)
    logger.info("Starting LLM Service")

    try:
        # Load configuration
        config = Config.load(args.config)
        
        # Override config with command line arguments if provided
        if args.port is not None:
            config.port = args.port
        if args.workers is not None:
            config.worker_threads = args.workers
        if args.ollama_url is not None:
            config.ollama_url = args.ollama_url
        if args.model is not None:
            config.model_name = args.model
        if args.log_level is not None:
            config.log_level = args.log_level

        # Log the configuration
        logger.info(
            f"Configuration: port={config.port}, "
            f"workers={config.worker_threads}, "
            f"ollama_url={config.ollama_url}, "
            f"model={config.model_name}"
        )

        # Start the server
        serve(config)
    except Exception as e:
        logger.error(f"Failed to start service: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()