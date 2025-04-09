"""
Ollama API Client
----------------
Client for interacting with the Ollama API.
"""

import json
import logging
import requests
from typing import Dict, Generator, Any, Optional
from dataclasses import dataclass
from requests.exceptions import RequestException, Timeout

logger = logging.getLogger(__name__)


@dataclass
class LLMChunk:
    """Data class for storing chunks of text from the LLM."""
    text: str
    is_complete: bool


class OllamaClient:
    """
    Client for interacting with the Ollama API.
    
    This client handles:
    - Streaming requests to the Ollama API
    - Non-streaming requests
    - Error handling and retries
    """
    
    def __init__(self, base_url: str, model_name: str, timeout: int = 30):
        """
        Initialize the Ollama client.
        
        Args:
            base_url: Base URL for the Ollama API
            model_name: Name of the LLM model to use
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip('/')
        self.model_name = model_name
        self.timeout = timeout
        self.session = requests.Session()
        
        # Verify that the Ollama API is available
        self._check_connection()
        
    def _check_connection(self):
        """Verify that the Ollama API is available."""
        try:
            response = self.session.get(f"{self.base_url}/api/tags", timeout=5)
            response.raise_for_status()
            
            # Check if the model is available
            models = response.json().get("models", [])
            model_names = [m.get("name") for m in models]
            
            if not any(self.model_name in name for name in model_names):
                logger.warning(
                    f"Model '{self.model_name}' not found in Ollama. "
                    f"Available models: {', '.join(model_names)}"
                )
                logger.info(f"Model '{self.model_name}' will be pulled on first request if needed")
                
        except RequestException as e:
            logger.warning(f"Could not connect to Ollama API at {self.base_url}: {e}")
            logger.info("Proceeding anyway, will retry when handling requests")
    
    def generate(self, prompt: str, parameters: Dict[str, Any]) -> str:
        """
        Generate a complete response from the LLM.
        
        Args:
            prompt: The input prompt
            parameters: Generation parameters
            
        Returns:
            The complete generated text
            
        Raises:
            RequestException: If there's an error communicating with the Ollama API
        """
        # Prepare the request for Ollama
        ollama_request = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "options": parameters
        }
        
        logger.debug(f"Sending non-streaming request to Ollama: {ollama_request}")
        
        try:
            # Make request to Ollama
            response = self.session.post(
                f"{self.base_url}/api/generate",
                json=ollama_request,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            response_data = response.json()
            
            logger.debug(f"Received response from Ollama: {response_data}")
            
            return response_data.get("response", "")
            
        except Timeout:
            logger.error(f"Request to Ollama timed out after {self.timeout}s")
            raise
            
        except RequestException as e:
            logger.error(f"Error communicating with Ollama API: {e}")
            raise
    
    def generate_stream(self, prompt: str, parameters: Dict[str, Any]) -> Generator[LLMChunk, None, None]:
        """
        Stream the LLM response as it's generated.
        
        Args:
            prompt: The input prompt
            parameters: Generation parameters
            
        Yields:
            LLMChunk objects containing text chunks and completion status
            
        Raises:
            RequestException: If there's an error communicating with the Ollama API
        """
        # Prepare the request for Ollama
        ollama_request = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": True,
            "options": parameters
        }
        
        logger.debug(f"Sending streaming request to Ollama: {ollama_request}")
        
        try:
            # Make streaming request to Ollama
            response = self.session.post(
                f"{self.base_url}/api/generate",
                json=ollama_request,
                stream=True,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            # Stream the chunks back to the client
            for line in response.iter_lines():
                if not line:
                    continue
                    
                try:
                    chunk_data = json.loads(line)
                    
                    # Check if this is a content chunk
                    if "response" in chunk_data:
                        is_complete = chunk_data.get("done", False)
                        
                        yield LLMChunk(
                            text=chunk_data["response"],
                            is_complete=is_complete
                        )
                        
                    # If we've reached the end, break
                    if chunk_data.get("done", False):
                        break
                        
                except json.JSONDecodeError as e:
                    logger.error(f"Error parsing streaming response: {e}")
                    logger.debug(f"Problematic line: {line}")
                    continue
                    
        except Timeout:
            logger.error(f"Streaming request to Ollama timed out after {self.timeout}s")
            raise
            
        except RequestException as e:
            logger.error(f"Error in streaming request to Ollama API: {e}")
            raise