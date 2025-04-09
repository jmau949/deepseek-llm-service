#!/usr/bin/env python3
"""
Generate Python code from Protocol Buffer files.
"""

import os
import sys
import subprocess
import logging
from pathlib import Path

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("proto-generator")


def main():
    """Generate Python code from proto files."""
    # Get the repo root directory
    repo_root = Path(__file__).parent.parent.absolute()
    
    # Define directories
    proto_dir = repo_root / "proto"
    output_dir = repo_root / "proto"
    
    # Create output directory if it doesn't exist
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Find all proto files
    proto_files = list(proto_dir.glob("*.proto"))
    
    if not proto_files:
        logger.error(f"No proto files found in {proto_dir}")
        sys.exit(1)
    
    logger.info(f"Found {len(proto_files)} proto files: {[f.name for f in proto_files]}")
    
    for proto_file in proto_files:
        logger.info(f"Processing {proto_file.name}...")
        
        try:
            # Generate Python code using grpcio-tools
            args = [
                sys.executable,
                "-m",
                "grpc_tools.protoc",
                f"--proto_path={proto_dir}",
                f"--python_out={output_dir}",
                f"--grpc_python_out={output_dir}",
                str(proto_file),
            ]
            
            logger.info(f"Running command: {' '.join(args)}")
            subprocess.check_call(args)
            logger.info(f"Successfully generated code for {proto_file.name}")
            
            # Fix imports in the generated code (needed for Python 3)
            fix_imports(output_dir, proto_file.stem)
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to generate code: {e}")
            sys.exit(1)
    
    logger.info("All proto files processed successfully!")
    
    # Create an __init__.py file to make the directory a package
    init_file = output_dir / "__init__.py"
    if not init_file.exists():
        with open(init_file, "w") as f:
            f.write('"""Generated Protocol Buffer code."""\n')
    
    logger.info(f"Created package __init__.py at {init_file}")


def fix_imports(output_dir, proto_name):
    """
    Fix imports in the generated Python code.
    
    gRPC tools generate import statements that don't work with Python 3 module system.
    This function fixes the import statements to use relative imports.
    
    Args:
        output_dir: Directory containing the generated code
        proto_name: Name of the proto file (without extension)
    """
    pb2_file = output_dir / f"{proto_name}_pb2.py"
    grpc_file = output_dir / f"{proto_name}_pb2_grpc.py"
    
    # Fix imports in the gRPC file
    if grpc_file.exists():
        with open(grpc_file, "r") as f:
            content = f.read()
        
        # Replace "import xxx_pb2" with "from . import xxx_pb2"
        content = content.replace(
            f"import {proto_name}_pb2",
            f"from . import {proto_name}_pb2",
        )
        
        with open(grpc_file, "w") as f:
            f.write(content)
        
        logger.info(f"Fixed imports in {grpc_file}")


if __name__ == "__main__":
    main()