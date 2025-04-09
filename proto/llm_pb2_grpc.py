# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc

from . import llm_pb2 as llm__pb2


class LLMServiceStub(object):
    """LLM service definition
    """

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.GenerateStream = channel.unary_stream(
                '/llm.LLMService/GenerateStream',
                request_serializer=llm__pb2.LLMRequest.SerializeToString,
                response_deserializer=llm__pb2.LLMResponse.FromString,
                )
        self.Generate = channel.unary_unary(
                '/llm.LLMService/Generate',
                request_serializer=llm__pb2.LLMRequest.SerializeToString,
                response_deserializer=llm__pb2.LLMCompleteResponse.FromString,
                )


class LLMServiceServicer(object):
    """LLM service definition
    """

    def GenerateStream(self, request, context):
        """Generate a response in a streaming fashion
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def Generate(self, request, context):
        """Generate a complete response without streaming (optional)
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_LLMServiceServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'GenerateStream': grpc.unary_stream_rpc_method_handler(
                    servicer.GenerateStream,
                    request_deserializer=llm__pb2.LLMRequest.FromString,
                    response_serializer=llm__pb2.LLMResponse.SerializeToString,
            ),
            'Generate': grpc.unary_unary_rpc_method_handler(
                    servicer.Generate,
                    request_deserializer=llm__pb2.LLMRequest.FromString,
                    response_serializer=llm__pb2.LLMCompleteResponse.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'llm.LLMService', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))


 # This class is part of an EXPERIMENTAL API.
class LLMService(object):
    """LLM service definition
    """

    @staticmethod
    def GenerateStream(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_stream(request, target, '/llm.LLMService/GenerateStream',
            llm__pb2.LLMRequest.SerializeToString,
            llm__pb2.LLMResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def Generate(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/llm.LLMService/Generate',
            llm__pb2.LLMRequest.SerializeToString,
            llm__pb2.LLMCompleteResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)
