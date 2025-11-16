
import json
import socket
from colorama import Fore

def send_message(sock, message_dict):
    """Converts a dictionary to JSON, prefixed with 4-byte length."""
    try:
        message_json = json.dumps(message_dict).encode('utf-8')
        message_length = len(message_json).to_bytes(4, 'big')
        sock.sendall(message_length + message_json)
        return True
    except Exception as e:
        print(Fore.RED + f"Error sending message: {e}")
        return False

def receive_message(sock):
    """Reads a 4-byte length-prefixed JSON message and returns a dict."""
    try:
        # Read the length prefix
        length_bytes = sock.recv(4)
        if not length_bytes:
            return None  # Connection closed
        
        message_length = int.from_bytes(length_bytes, 'big')
        
        # Read the full message
        message_data = b""
        while len(message_data) < message_length:
            chunk = sock.recv(message_length - len(message_data))
            if not chunk:
                return None  # Connection closed unexpectedly
            message_data += chunk
            
        return json.loads(message_data.decode('utf-8'))
    
    except json.JSONDecodeError:
        print(Fore.RED + "Error: Received malformed JSON.")
        return None
    except socket.timeout:
        print(Fore.YELLOW + "Socket timed out.")
        return None
    except Exception as e:
        print(Fore.RED + f"Error receiving message: {e}")
        return None