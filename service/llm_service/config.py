"""
Configuration Module
-------------------
Loads and validates configuration for the LLM gRPC service.
"""

import os
import logging
import yaml
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class Config:
    """Configuration settings for the LLM gRPC service."""
    
    # Server settings
    port: int = 50051
    worker_threads: int = 10
    use_tls: bool = False
    tls_cert_path: Optional[str] = None
    tls_key_path: Optional[str] = None
    
    # Ollama settings
    ollama_url: str = "http://localhost:11434"
    model_name: str = "model-name"
    request_timeout: int = 30
    
    # LLM default parameters
    default_temperature: float = 0.7
    default_max_tokens: int = 2048
    default_top_p: float = 0.95
    default_presence_penalty: float = 0.0
    default_frequency_penalty: float = 0.0
    
    # Logging settings
    log_level: str = "INFO"
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    @classmethod
    def load(cls, config_path: Optional[str] = None) -> 'Config':
        """
        Load configuration from a file or environment variables.
        
        Args:
            config_path: Path to a YAML or JSON configuration file
            
        Returns:
            Config object with the loaded settings
        """
        # Start with default config
        config = cls()
        
        # Load from file if provided
        if config_path:
            config = config._load_from_file(config_path)
            
        # Override with environment variables
        config = config._load_from_env()
        
        # Validate the configuration
        config._validate()
        
        return config
    
    def _load_from_file(self, config_path: str) -> 'Config':
        """
        Load configuration from a file.
        
        Args:
            config_path: Path to the configuration file
            
        Returns:
            Config object with settings from the file
        """
        try:
            with open(config_path, 'r') as f:
                config_data = yaml.safe_load(f)
                
            # Update attributes from the loaded data
            for key, value in config_data.items():
                if hasattr(self, key):
                    setattr(self, key, value)
                else:
                    logger.warning(f"Unknown configuration key: {key}")
                    
            logger.info(f"Loaded configuration from {config_path}")
            
        except Exception as e:
            logger.error(f"Failed to load configuration from {config_path}: {e}")
            logger.info("Using default configuration with environment overrides")
            
        return self
    
    def _load_from_env(self) -> 'Config':
        """
        Override configuration with environment variables.
        
        Returns:
            Config object with settings from environment variables
        """
        # Server settings
        if 'PORT' in os.environ:
            self.port = int(os.environ['PORT'])
            
        if 'WORKER_THREADS' in os.environ:
            self.worker_threads = int(os.environ['WORKER_THREADS'])
            
        if 'USE_TLS' in os.environ:
            self.use_tls = os.environ['USE_TLS'].lower() in ('true', 'yes', '1')
            
        if 'TLS_CERT_PATH' in os.environ:
            self.tls_cert_path = os.environ['TLS_CERT_PATH']
            
        if 'TLS_KEY_PATH' in os.environ:
            self.tls_key_path = os.environ['TLS_KEY_PATH']
            
        # Ollama settings
        if 'OLLAMA_URL' in os.environ:
            self.ollama_url = os.environ['OLLAMA_URL']
            
        if 'MODEL_NAME' in os.environ:
            self.model_name = os.environ['MODEL_NAME']
            
        if 'REQUEST_TIMEOUT' in os.environ:
            self.request_timeout = int(os.environ['REQUEST_TIMEOUT'])
            
        # LLM default parameters
        if 'DEFAULT_TEMPERATURE' in os.environ:
            self.default_temperature = float(os.environ['DEFAULT_TEMPERATURE'])
            
        if 'DEFAULT_MAX_TOKENS' in os.environ:
            self.default_max_tokens = int(os.environ['DEFAULT_MAX_TOKENS'])
            
        if 'DEFAULT_TOP_P' in os.environ:
            self.default_top_p = float(os.environ['DEFAULT_TOP_P'])
            
        if 'DEFAULT_PRESENCE_PENALTY' in os.environ:
            self.default_presence_penalty = float(os.environ['DEFAULT_PRESENCE_PENALTY'])
            
        if 'DEFAULT_FREQUENCY_PENALTY' in os.environ:
            self.default_frequency_penalty = float(os.environ['DEFAULT_FREQUENCY_PENALTY'])
            
        # Logging settings
        if 'LOG_LEVEL' in os.environ:
            self.log_level = os.environ['LOG_LEVEL']
            
        if 'LOG_FORMAT' in os.environ:
            self.log_format = os.environ['LOG_FORMAT']
            
        return self
    
    def _validate(self):
        """
        Validate the configuration.
        
        Raises:
            ValueError: If the configuration is invalid
        """
        # Validate server settings
        if self.port < 1 or self.port > 65535:
            raise ValueError(f"Invalid port number: {self.port}")
            
        if self.worker_threads < 1:
            raise ValueError(f"Invalid worker thread count: {self.worker_threads}")
            
        if self.use_tls and (not self.tls_cert_path or not self.tls_key_path):
            raise ValueError("TLS is enabled but cert or key path is missing")
            
        # Validate Ollama settings
        if not self.ollama_url or not self.ollama_url.startswith(('http://', 'https://')):
            raise ValueError(f"Invalid Ollama URL: {self.ollama_url}")
            
        if not self.model_name:
            raise ValueError("Model name is required")
            
        if self.request_timeout < 1:
            raise ValueError(f"Invalid request timeout: {self.request_timeout}")
            
        # Validate LLM parameters
        if self.default_temperature < 0 or self.default_temperature > 2:
            raise ValueError(f"Invalid temperature: {self.default_temperature}")
            
        if self.default_max_tokens < 1:
            raise ValueError(f"Invalid max tokens: {self.default_max_tokens}")
            
        if self.default_top_p <= 0 or self.default_top_p > 1:
            raise ValueError(f"Invalid top-p: {self.default_top_p}")