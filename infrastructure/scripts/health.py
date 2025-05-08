#!/usr/bin/env python3
import subprocess, socket, json, uuid, time, threading, sys
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import RequestReceived
from http.cookies import SimpleCookie


PORT = 80
GRPC_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 50051
COOKIE_NAME = "LlmServiceStickiness"

def check_health():
    """Check if the gRPC service is healthy"""
    # First check if the gRPC port is open
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect(('localhost', GRPC_PORT))
        port_open = True
    except Exception as e:
        print(f"Error connecting to gRPC port: {e}")
        return False
    finally:
        s.close()
    
    # Try standard reflection API
    try:
        result = subprocess.run(["grpcurl", "-plaintext", f"localhost:{GRPC_PORT}", "list", "llm.LLMService"], 
                              capture_output=True, timeout=2)
        if result.returncode != 0:
            print(f"gRPC reflection check failed: {result.stderr.decode()}")
            return False
        return True
    except Exception as e:
        print(f"Error checking gRPC reflection: {e}")
        return False

def handle_h2_connection(sock, address):
    """Handle a single HTTP/2 connection"""
    config = H2Configuration(client_side=False)
    conn = H2Connection(config=config)
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())
    
    try:
        while True:
            data = sock.recv(65535)
            if not data:
                break
                
            events = conn.receive_data(data)
            
            for event in events:
                if isinstance(event, RequestReceived):
                    stream_id = event.stream_id
                    headers = dict(event.headers)
                    path = headers.get(b':path', b'/').decode('utf-8')
                    
                    if path == '/health':
                        is_healthy = check_health()
                        status = 200 if is_healthy else 503
                        message = b'{"status":"healthy"}' if is_healthy else b'{"status":"unhealthy"}'
                    else:
                        status = 200
                        message = b'{"status":"ok"}'
                        
                    response_headers = [
                        (b':status', str(status).encode('utf-8')),
                        (b'content-type', b'application/json'),
                        (b'content-length', str(len(message)).encode('utf-8')),
                        (b'server', b'health-proxy-h2'),
                    ]
                    
                    # Add cookie header for session stickiness
                    cookie_header = f'{COOKIE_NAME}={uuid.uuid4()}; Path=/; Max-Age=900; HttpOnly'.encode('utf-8')
                    response_headers.append((b'set-cookie', cookie_header))
                    
                    conn.send_headers(stream_id, response_headers)
                    conn.send_data(stream_id, message, end_stream=True)
                    
            sock.sendall(conn.data_to_send())
    except Exception as e:
        print(f"Error in HTTP/2 connection: {e}")
        raise  # Re-raise to ensure the error is visible
    finally:
        sock.close()

if __name__ == "__main__":
    # Ensure the required libraries are available
    required_libraries = ["h2"]
    for lib in required_libraries:
        try:
            __import__(lib)
        except ImportError:
            print(f"Error: Required library '{lib}' is missing. Please install it with 'pip install {lib}'")
            sys.exit(1)

    # Start HTTP/2 server
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        sock.bind(('', PORT))
        sock.listen(5)
        
        print(f"Starting HTTP/2 server on port {PORT}...")
        
        # Accept connections in a loop
        while True:
            client, addr = sock.accept()
            client_thread = threading.Thread(target=handle_h2_connection, args=(client, addr))
            client_thread.daemon = True
            client_thread.start()
    except Exception as e:
        print(f"Critical error in HTTP/2 server: {e}")
        sys.exit(1)  # Exit with error to make failure obvious 