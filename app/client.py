"""
The main Secure Chat Client application.
"""
import socket
import threading
import json
import base64
import time
import getpass
import config 
from colorama import Fore, Style, init


from app.common import protocol, utils
from app.crypto import pki, dh, aes, sign
from app.storage.transcript import TranscriptManager

init(autoreset=True)
#Loading Client Certificates
CLIENT_CERT_FILE = f"certs/{config.CLIENT_CN}.crt"
CLIENT_KEY_FILE = f"certs/{config.CLIENT_CN}.key"
CA_CERT_FILE = "certs/ca.crt"

try:
    client_private_key = sign.load_private_key(CLIENT_KEY_FILE)
    client_cert = pki.load_cert(CLIENT_CERT_FILE)
    client_cert_pem = pki.get_cert_pem(client_cert)
    client_fingerprint = pki.get_cert_fingerprint(client_cert)
    ca_cert = pki.load_cert(CA_CERT_FILE)
    print(Fore.GREEN + "Client certificate and private key loaded.")
except Exception as e:
    print(Fore.RED + f"Fatal: Could not load client certificates: {e}")
    print(Fore.YELLOW + "Please run the 'gen_ca.py' and 'gen_cert.py' scripts first.")
    exit(1)

# Global Variables
server_pub_key = None
session_key = None
transcript_manager = None
client_seqno = 0
server_seqno = 0
server_fingerprint = ""
connection_active = threading.Event()

def receive_handler(sock): #Thread function to handle incoming messages from server
    global server_seqno, server_fingerprint
    
    while connection_active.is_set():
        try:
            msg = protocol.receive_message(sock)
            if not msg:
                print(Fore.RED + "\n[Connection closed by server]")
                connection_active.clear()
                break

            msg_type = msg.get("type")
            
            if msg_type == "msg":
                seqno = msg.get("seqno")
                ts = msg.get("ts")
                ct_b64 = msg.get("ct") # base64
                sig_b64 = msg.get("sig") # base64
                
                # Checking sequence number for replay attacks
                if seqno <= server_seqno:
                    print(Fore.YELLOW + f"\n[REPLAY detected. Ignoring message {seqno}]")
                    continue
                server_seqno = seqno
                
                # Verifies signature to detect tampering
                data_to_verify = f"{seqno}{ts}{ct_b64}"
                if not sign.verify_signature(server_pub_key, base64.b64decode(sig_b64), data_to_verify.encode('utf-8')):
                    print(Fore.RED + f"\n[TAMPERING detected. Invalid signature from server. Dropping.]")
                    connection_active.clear()
                    break
                
                #  Decrypting the message
                decrypted_bytes = aes.decrypt_aes_cbc(session_key, base64.b64decode(ct_b64))
                if not decrypted_bytes:
                    print(Fore.RED + "\n[Decryption failed!]")
                    continue
                    
                plaintext = decrypted_bytes.decode('utf-8')
                print(Fore.CYAN + f"\nServer: {plaintext}")
                print(Fore.WHITE + "You: ", end="", flush=True) # Reprompt
                
                # Logging to transcript
                transcript_manager.add_message(seqno, ts, ct_b64, sig_b64, server_fingerprint)

            elif msg_type == "receipt":
                print(Fore.GREEN + "\n[Received server's session receipt. Verifying...]")
                
                server_transcript_hash = msg.get("transcript_sha256")
                server_receipt_sig = base64.b64decode(msg.get("sig"))
                
                if not sign.verify_signature(server_pub_key, server_receipt_sig, server_transcript_hash.encode('utf-8')):
                    print(Fore.RED + "[Server SessionReceipt verification FAILED.]")
                else:
                    print(Fore.GREEN + "[Server SessionReceipt verified.]")
                
                print("[Session ended.]")
                connection_active.clear()
                break

            elif msg_type == "error":
                print(Fore.RED + f"\n[SERVER ERROR]: {msg.get('message')}")
                if msg.get('message') in ["REPLAY", "SIG_FAIL"]:
                    print("[Closing connection due to critical error]")
                    connection_active.clear()
                    break

        except Exception as e:
            if connection_active.is_set():
                print(Fore.RED + f"\n[Receive Error]: {e}")
            break

def main():
    global server_pub_key, session_key, transcript_manager, client_seqno, server_fingerprint, connection_active

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        # 1. Connection Establishment & Authentication
        sock.connect((config.SERVER_HOST, config.SERVER_PORT))
        print(f"Connected to {config.SERVER_HOST}:{config.SERVER_PORT}")
        
        # Send Client Hello
        protocol.send_message(sock, {
            "type": "hello",
            "client_cert": base64.b64encode(client_cert_pem).decode('utf-8')
        })
        
        #  Receive Server Hello & Verify Certificate
        msg = protocol.receive_message(sock)
        if not msg or msg.get("type") != "server_hello":
            if msg.get("type") == "error":
                print(Fore.RED + f"Server rejected connection: {msg.get('message')}")
            else:
                print(Fore.RED + "Did not receive 'server_hello'. Aborting.")
            return

        server_cert_pem = base64.b64decode(msg.get("server_cert"))
        server_cert = pki.load_cert_from_pem(server_cert_pem)
        
        is_valid, reason = pki.verify_certificate(server_cert, ca_cert, config.SERVER_CN)
        if not is_valid:
            print(Fore.RED + f"Server certificate invalid ({reason}). Aborting.")
            return
            
        print(Fore.GREEN + f"Server certificate verified (CN={config.SERVER_CN}).")
        server_pub_key = server_cert.public_key()
        server_fingerprint = pki.get_cert_fingerprint(server_cert)
        transcript_manager = TranscriptManager(peer_name="server", our_cert_fingerprint=client_fingerprint)

        #  Temporary Diffie Hilman Key Exchange for Authentication
        print("Establishing temporary key for auth...")
        auth_priv_key, auth_pub_key_int = dh.generate_dh_keypair()
        
        protocol.send_message(sock, {
            "type": "auth_dh_init",
            "A_client": str(auth_pub_key_int)
        })
        
        msg = protocol.receive_message(sock)
        if not msg or msg.get("type") != "auth_dh_reply":
            print(Fore.RED + "Failed to complete auth DH exchange.")
            return
            
        peer_public_key_int = int(msg.get("B_server"))
        auth_shared_secret_int = dh.derive_shared_secret(auth_priv_key, peer_public_key_int)
        auth_key = dh.derive_session_key(auth_shared_secret_int)
        print(Fore.GREEN + "Temporary auth key established.")

        #(Register or Login)
        action = ""
        while action not in ["1", "2"]:
            action = input("Select action:\n1. Register\n2. Login\n> ")
        
        auth_payload = {}
        email = input("Email: ")
        password = getpass.getpass("Password: ")
        
        if action == "1": # Register
            username = input("Username: ")
            auth_payload = {
                "type": "register",
                "email": email,
                "username": username,
                "password": password # Send plaintext password (encrypted)
            }
        
        else: # Login
            auth_payload = {
                "type": "login",
                "email": email,
                "password": password # Send plaintext password (encrypted)
            }
        
        # Send Encrypted Auth Credentials
        payload_json = json.dumps(auth_payload).encode('utf-8')
        encrypted_payload = aes.encrypt_aes_cbc(auth_key, payload_json)
        
        protocol.send_message(sock, {
            "type": "auth_cred_encrypted",
            "payload": base64.b64encode(encrypted_payload).decode('utf-8')
        })
        
        # Getting Auth Response
        msg = protocol.receive_message(sock)
        if not msg or msg.get("status") != "ok":
            print(Fore.RED + f"Authentication failed: {msg.get('message')}")
            if action == "1" and "exists" in msg.get('message', ''):
                print(Fore.YELLOW + "Note: This email or username is already taken.")
            return
        
        print(Fore.GREEN + f"Authentication successful: {msg.get('message')}")

        # Session Key Exchange for Data Plane
        print("Starting session key exchange...")
        session_priv_key, session_pub_key_int = dh.generate_dh_keypair()

        protocol.send_message(sock, {
            "type": "dh_client",
            "g": dh.DH_PARAMS.parameter_numbers().g,
            "p": dh.DH_PARAMS.parameter_numbers().p,
            "A": str(session_pub_key_int)
        })
        
        msg = protocol.receive_message(sock)
        if not msg or msg.get("type") != "dh_server":
            print(Fore.RED + "Failed to complete session DH exchange.")
            return
            
        peer_public_key_int = int(msg.get("B"))
        shared_secret_int = dh.derive_shared_secret(session_priv_key, peer_public_key_int)
        session_key = dh.derive_session_key(shared_secret_int)
        
        print(Fore.GREEN + "Session key established. Secure chat is active.")
        print(Fore.YELLOW + "Type '!!quit' to end session.")

        # 2. Data Plane (Secure Chat)
        connection_active.set()
        receiver = threading.Thread(target=receive_handler, args=(sock,))
        receiver.daemon = True
        receiver.start()
        
        while connection_active.is_set():
            plaintext = input(Fore.WHITE + "You: ")
            
            if not connection_active.is_set():
                break # Receiver thread might have closed connection
                
            if plaintext == "!!quit":
                break
            
            client_seqno += 1
            ts = int(time.time() * 1000)
            
            ct_bytes = aes.encrypt_aes_cbc(session_key, plaintext)
            ct_b64 = base64.b64encode(ct_bytes).decode('utf-8')
            
            data_to_sign = f"{client_seqno}{ts}{ct_b64}"
            sig_bytes = sign.sign_data(client_private_key, data_to_sign.encode('utf-8'))
            sig_b64 = base64.b64encode(sig_bytes).decode('utf-8')
            
            protocol.send_message(sock, {
                "type": "msg",
                "seqno": client_seqno,
                "ts": ts,
                "ct": ct_b64,
                "sig": sig_b64
            })
            # 2. [ATTACK] Send the *exact same message* again
            #Uncomment the following lines to enable the replay attack
            """print(Fore.YELLOW + f"[ATTACK: Re-sending seqno {client_seqno}...] ")
            time.sleep(0.1) # small delay
            protocol.send_message(sock, {
                "type": "msg",
                "seqno": client_seqno,
                "ts": ts,
                "ct": ct_b64,
                "sig": sig_b64
            })"""
            # --- END OF ATTACK ---
            # Log to transcript
            transcript_manager.add_message(client_seqno, ts, ct_b64, sig_b64, client_fingerprint)

        # NonRepudiation: Send Session Receipt
        if connection_active.is_set(): # Only if we initiated the quit
            print("Sending session receipt...")
            
            client_receipt = transcript_manager.generate_receipt(
                client_private_key,
                first_seq=1 if client_seqno > 0 else 0,
                last_seq=client_seqno
            )
            protocol.send_message(sock, client_receipt)
            
            # Save our receipt and transcript for verification
            transcript_manager.save_session(
                receipt_dict=client_receipt,
                our_cert_file=CLIENT_CERT_FILE,
                peer_cert_file=f"certs/{config.SERVER_CN}.crt"
            )
            print(Fore.GREEN + "Run 'python verify_transcript.py' to verify.")

        # Wait for receiver to finish (e.g., get server's receipt)
        receiver.join()

    except Exception as e:
        print(Fore.RED + f"Main Client Error: {e}")
    finally:
        sock.close()
        print("Connection closed.")

if __name__ == "__main__":
    main()