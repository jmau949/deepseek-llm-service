"""
Logging Utilities
----------------
Utilities for setting up logging.
"""

import os
import logging
import sys
from typing import Optional


def setup_logging(
    log_level: Optional[str] = None,
    log_format: Optional[str] = None
) -> logging.Logger:
    # Get log level from environment or parameter
    level_str = log_level or os.environ.get('LOG_LEVEL', 'INFO')
    level = getattr(logging, level_str.upper(), logging.INFO)
    
    # Get log format from environment or parameter
    format_str = log_format or os.environ.get(
        'LOG_FORMAT',
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Configure just the llm_service logger, not the root logger
    logger = logging.getLogger('llm_service')
    logger.setLevel(level)
    
    # Remove any existing handlers to avoid duplication on restart
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Add a new handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(format_str))
    logger.addHandler(handler)
    
    # Log initial configuration
    logger.info(f"Logging initialized with level={level_str}")
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger with the specified name.
    
    Args:
        name: Logger name
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)