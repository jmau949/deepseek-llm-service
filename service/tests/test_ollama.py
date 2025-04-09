"""Tests for the LLM service."""

import unittest
from unittest.mock import patch, MagicMock, Mock

import grpc

from llm_service.config import Config
from llm_service.service import LLMService


class TestLLMService(unittest.TestCase):
    """Test cases for the LLM service."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create a test configuration
        self.config = Config()
        self.config.ollama_url = "http://test-ollama:11434"
        self.config.model_name = "test-model"
        
        # Mock the OllamaClient
        self.ollama_client_patch = patch('llm_service.service.OllamaClient')
        self.mock_ollama_client = self.ollama_client_patch.start()
        
        # Create a mock instance for the OllamaClient
        self.mock_client_instance = MagicMock()
        self.mock_ollama_client.return_value = self.mock_client_instance
        
        # Create the service with the mock client
        self.service = LLMService(self.config)
        
        # Create a mock context
        self.context = MagicMock()
        
        # Mock the protocol buffer modules
        self.llm_pb2_patch = patch('llm_service.service.llm_pb2')
        self.mock_llm_pb2 = self.llm_pb2_patch.start()
        
        # Create mock request objects
        self.mock_request = Mock()
        self.mock_request.prompt = "Test prompt"
        self.mock_request.parameters = Mock()
        self.mock_request.parameters.temperature = 0.7
        self.mock_request.parameters.max_tokens = 100
        self.mock_request.parameters.top_p = 0.9
        self.mock_request.parameters.presence_penalty = 0.0
        self.mock_request.parameters.frequency_penalty = 0.0
        
        # Set up response objects
        self.mock_llm_pb2.LLMResponse.side_effect = lambda **kwargs: Mock(**kwargs)
        self.mock_llm_pb2.LLMCompleteResponse.side_effect = lambda **kwargs: Mock(**kwargs)
        
    def tearDown(self):
        """Tear down test fixtures."""
        self.ollama_client_patch.stop()
        self.llm_pb2_patch.stop()
        
    def test_generate_stream(self):
        """Test the streaming generation method."""
        from llm_service.utils.ollama import LLMChunk
        
        # Set up the mock client to return chunks
        self.mock_client_instance.generate_stream.return_value = [
            LLMChunk(text="Hello", is_complete=False),
            LLMChunk(text=" world", is_complete=False),
            LLMChunk(text="!", is_complete=True)
        ]
        
        # Call the service method
        response_iterator = self.service.GenerateStream(self.mock_request, self.context)
        
        # Get responses from the iterator
        responses = list(response_iterator)
        
        # Verify the responses
        self.assertEqual(len(responses), 3)
        
        # Verify the mock was called with the right parameters
        self.mock_client_instance.generate_stream.assert_called_once()
        args, kwargs = self.mock_client_instance.generate_stream.call_args
        self.assertEqual(args[0], "Test prompt")
        
        # Check that the LLMResponse was created with the right parameters
        self.mock_llm_pb2.LLMResponse.assert_any_call(text="Hello", is_complete=False)
        self.mock_llm_pb2.LLMResponse.assert_any_call(text=" world", is_complete=False)
        self.mock_llm_pb2.LLMResponse.assert_any_call(text="!", is_complete=True)
        
    def test_generate(self):
        """Test the non-streaming generation method."""
        # Set up the mock client to return a response
        self.mock_client_instance.generate.return_value = "Hello world!"
        
        # Call the service method
        response = self.service.Generate(self.mock_request, self.context)
        
        # Verify the response
        self.mock_llm_pb2.LLMCompleteResponse.assert_called_with(text="Hello world!")
        
        # Verify the mock was called with the right parameters
        self.mock_client_instance.generate.assert_called_once()
        args, kwargs = self.mock_client_instance.generate.call_args
        self.assertEqual(args[0], "Test prompt")
        
    def test_generate_stream_error(self):
        """Test error handling in the streaming method."""
        # Set up the mock client to raise an exception
        self.mock_client_instance.generate_stream.side_effect = Exception("Test error")
        
        # Call the service method
        response_iterator = self.service.GenerateStream(self.mock_request, self.context)
        
        # Try to get responses from the iterator
        responses = list(response_iterator)
        
        # Verify that no responses were returned
        self.assertEqual(len(responses), 0)
        
        # Verify that the context was aborted with the right error
        self.context.abort.assert_called_once()
        args, kwargs = self.context.abort.call_args
        self.assertEqual(args[0], grpc.StatusCode.INTERNAL)
        self.assertIn("Test error", args[1])
        
    def test_generate_error(self):
        """Test error handling in the non-streaming method."""
        # Set up the mock client to raise an exception
        self.mock_client_instance.generate.side_effect = Exception("Test error")
        
        # Call the service method
        with self.assertRaises(Exception):
            self.service.Generate(self.mock_request, self.context)
        
        # Verify that the context was aborted with the right error
        self.context.abort.assert_called_once()
        args, kwargs = self.context.abort.call_args
        self.assertEqual(args[0], grpc.StatusCode.INTERNAL)
        self.assertIn("Test error", args[1])


if __name__ == "__main__":
    unittest.main()