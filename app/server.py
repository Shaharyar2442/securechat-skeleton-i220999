"""
The main Secure Chat Server application.
"""
import socket
import threading
import json
import base64
import time
import config  # Root config
from colorama import Fore, Style, init

# Import app modules
from app.common import protocol, utils
from app.crypto import pki, dh, aes, sign
from app.storage import db
from app.storage.transcript import TranscriptManager

init(autoreset=True)
#Loading Server Certificates
SERVER_CERT_FILE = f"certs/{config.SERVER_CN}.crt"
SERVER_KEY_FILE = f"certs/{config.SERVER_CN}.key"
CA_CERT_FILE = "certs/ca.crt"

try:
    server_private_key = sign.load_private_key(SERVER_KEY_FILE)
    server_cert = pki.load_cert(SERVER_CERT_FILE)
    server_cert_pem = pki.get_cert_pem(server_cert)
    server_fingerprint = pki.get_cert_fingerprint(server_cert)
    ca_cert = pki.load_cert(CA_CERT_FILE)
    print(Fore.GREEN + "Server certificate and private key loaded.")
except Exception as e:
    print(Fore.RED + f"Fatal: Could not load server certificates: {e}")
    print(Fore.YELLOW + "Please run the 'gen_ca.py' and 'gen_cert.py' scripts first.")
    exit(1)

def handle_client(conn, addr):
    print(Fore.CYAN + f"[NEW CONNECTION] {addr} connected.")
    
    client_cert = None
    session_key = None
    transcript_manager = None
    client_seqno = 0
    server_seqno = 0

    try:
        #Control Plane
        # HELLO & Certificate Exchange
        msg = protocol.receive_message(conn)
        if not msg or msg.get("type") != "hello":
            print(Fore.YELLOW + f"{addr}: Did not send 'hello'. Dropping.")
            return

        client_cert_pem = base64.b64decode(msg.get("client_cert"))
        client_cert = pki.load_cert_from_pem(client_cert_pem)
        
        # Verifying Client Certificate
        is_valid, reason = pki.verify_certificate(client_cert, ca_cert, config.CLIENT_CN)
        if not is_valid:
            print(Fore.YELLOW + f"{addr}: Invalid certificate ({reason}). Dropping.")
            protocol.send_message(conn, {"type": "error", "message": f"BAD_CERT: {reason}"})
            return
        
        client_pub_key = client_cert.public_key()
        client_fingerprint = pki.get_cert_fingerprint(client_cert)
        transcript_manager = TranscriptManager(peer_name="client", our_cert_fingerprint=server_fingerprint)
        print(Fore.GREEN + f"{addr}: Client certificate verified (CN={config.CLIENT_CN}).")
        
        #  Sending Server Hello
        protocol.send_message(conn, {
            "type": "server_hello",
            "server_cert": base64.b64encode(server_cert_pem).decode('utf-8')
        })

        #  Temporary DH for Auth
        print(f"{addr}: Starting temporary DH for auth...")
        msg = protocol.receive_message(conn)
        if not msg or msg.get("type") != "auth_dh_init":
            print(Fore.YELLOW + f"{addr}: Expected 'auth_dh_init'. Dropping.")
            return
            
        peer_public_key_int = int(msg.get("A_client"))
        auth_priv_key, auth_pub_key_int = dh.generate_dh_keypair()
        
        auth_shared_secret_int = dh.derive_shared_secret(auth_priv_key, peer_public_key_int)
        auth_key = dh.derive_session_key(auth_shared_secret_int)
        
        protocol.send_message(conn, {"type": "auth_dh_reply", "B_server": str(auth_pub_key_int)})
        print(f"{addr}: Temporary auth key established.")

        # Receiving Encrypted Credentials from client
        msg = protocol.receive_message(conn)
        if not msg or msg.get("type") != "auth_cred_encrypted":
            print(Fore.YELLOW + f"{addr}: Expected 'auth_cred_encrypted'. Dropping.")
            return

        encrypted_payload = base64.b64decode(msg.get("payload"))
        decrypted_payload_bytes = aes.decrypt_aes_cbc(auth_key, encrypted_payload)
        
        if not decrypted_payload_bytes:
            print(Fore.RED + f"{addr}: Failed to decrypt auth payload. Wrong key or tampered.")
            protocol.send_message(conn, {"type": "auth_response", "status": "error", "message": "Decryption failed"})
            return
            
        auth_data = json.loads(decrypted_payload_bytes.decode('utf-8'))
        
        #  Processing Registration or Login
        auth_type = auth_data.get("type")
        email = auth_data.get("email")
        password = auth_data.get("password") # Client sends plaintext password (encrypted)
        
        if auth_type == "register":
            print(f"{addr}:Processing registration for {email}...")
            username = auth_data.get("username")
            
            # Server generates salt and hash (as per 2.2.5)
            salt = utils.generate_salt()
            pwd_hash = utils.hash_password(salt, password)
            
            success, message = db.register_user(email, username, salt, pwd_hash)
            if success:
                print(Fore.GREEN + f"{addr}: User {username} registered.")
                protocol.send_message(conn, {"type": "auth_response", "status": "ok", "message": "Registration successful"})
            else:
                print(Fore.YELLOW + f"{addr}: Registration failed: {message}")
                protocol.send_message(conn, {"type": "auth_response", "status": "error", "message": message})
                return # Failed auth

        elif auth_type == "login":
            print(f"{addr}: Processing login for {email}...")
            user, message = db.get_user(email)
            if not user:
                print(Fore.YELLOW + f"{addr}: Login failed: {message}")
                protocol.send_message(conn, {"type": "auth_response", "status": "error", "message": message})
                return
            
            # Re-compute hash using stored salt and client-sent password
            stored_salt = user['salt']
            stored_pwd_hash = user['pwd_hash']
            client_computed_hash = utils.hash_password(stored_salt, password)

            if client_computed_hash == stored_pwd_hash:
                 print(Fore.GREEN + f"{addr}: Login successful for {email}.")
                 protocol.send_message(conn, {"type": "auth_response", "status": "ok", "message": "Login successful"})
            else:
                 print(Fore.YELLOW + f"{addr}: Login failed for {email}. Password mismatch.")
                 protocol.send_message(conn, {"type": "auth_response", "status": "error", "message": "Invalid password"})
                 return
            
        else:
            print(Fore.YELLOW + f"{addr}: Unknown auth type '{auth_type}'.")
            protocol.send_message(conn, {"type": "auth_response", "status": "error", "message": "Unknown auth type"})
            return

        #  Key Agreement
        print(f"{addr}: Starting session DH key exchange...")
        msg = protocol.receive_message(conn)
        if not msg or msg.get("type") != "dh_client":
            print(Fore.YELLOW + f"{addr}: Expected 'dh_client'. Dropping.")
            return

        peer_public_key_int = int(msg.get("A"))
        session_priv_key, session_pub_key_int = dh.generate_dh_keypair()
        
        shared_secret_int = dh.derive_shared_secret(session_priv_key, peer_public_key_int)
        session_key = dh.derive_session_key(shared_secret_int)
        
        protocol.send_message(conn, {"type": "dh_server", "B": str(session_pub_key_int)})
        print(Fore.GREEN + f"{addr}: Session key established.")

        # Secure Chat Loop
        while True:
            msg = protocol.receive_message(conn)
            if not msg:
                print(f"{addr}: Client closed connection.")
                break
                
            msg_type = msg.get("type")
            
            if msg_type == "msg":
                seqno = msg.get("seqno")
                ts = msg.get("ts")
                ct_b64 = msg.get("ct") # base64
                sig_b64 = msg.get("sig") # base64
                
                #  Checking sequence number
                if seqno <= client_seqno:
                    print(Fore.YELLOW + f"{addr}: REPLAY attack detected. Expected > {client_seqno}, got {seqno}.")
                    protocol.send_message(conn, {"type": "error", "message": "REPLAY"})
                    continue
                client_seqno = seqno
                
                #  Verifying signature
                data_to_verify = f"{seqno}{ts}{ct_b64}"
                
                if not sign.verify_signature(client_pub_key, base64.b64decode(sig_b64), data_to_verify.encode('utf-8')):
                    print(Fore.RED + f"{addr}: TAMPERING detected. Signature verification failed.")
                    protocol.send_message(conn, {"type": "error", "message": "SIG_FAIL"})
                    continue

                # Decrypting message
                decrypted_bytes = aes.decrypt_aes_cbc(session_key, base64.b64decode(ct_b64))
                if not decrypted_bytes:
                    print(Fore.RED + f"{addr}: Decryption failed.")
                    continue
                    
                plaintext = decrypted_bytes.decode('utf-8')
                print(f"{addr} (Client): {plaintext}")
                
                #  Log to transcript
                transcript_manager.add_message(seqno, ts, ct_b64, sig_b64, client_fingerprint)
                
                #  Respond 
                server_seqno += 1
                server_ts = int(time.time() * 1000)
                response_text = f"Server acknowledges: '{plaintext}'"
                
                response_ct_bytes = aes.encrypt_aes_cbc(session_key, response_text)
                response_ct_b64 = base64.b64encode(response_ct_bytes).decode('utf-8')
                
                data_to_sign = f"{server_seqno}{server_ts}{response_ct_b64}"
                response_sig_bytes = sign.sign_data(server_private_key, data_to_sign.encode('utf-8'))
                response_sig_b64 = base64.b64encode(response_sig_bytes).decode('utf-8')
                
                protocol.send_message(conn, {
                    "type": "msg",
                    "seqno": server_seqno,
                    "ts": server_ts,
                    "ct": response_ct_b64,
                    "sig": response_sig_b64
                })
                
                #  Logging server's own message
                transcript_manager.add_message(server_seqno, server_ts, response_ct_b64, response_sig_b64, server_fingerprint)
            
            elif msg_type == "receipt":
                #  Non-Repudiation (Teardown) 
                print(f"{addr}: Received client receipt. Verifying...")
                
                #  Verifying client's receipt
                client_transcript_hash = msg.get("transcript_sha256")
                client_receipt_sig = base64.b64decode(msg.get("sig"))
                
                if not sign.verify_signature(client_pub_key, client_receipt_sig, client_transcript_hash.encode('utf-8')):
                    print(Fore.RED + f"{addr}: Client SessionReceipt verification FAILED.")
                else:
                    print(Fore.GREEN + f"{addr}: Client SessionReceipt verified.")
                
                #  Generating and sending server's receipt
                server_receipt = transcript_manager.generate_receipt(
                    server_private_key, 
                    first_seq=1 if server_seqno > 0 else 0,
                    last_seq=server_seqno
                )
                protocol.send_message(conn, server_receipt)
                
                print(f"{addr}: Sent server receipt. Closing session.")
                break # End session
            
            else:
                print(Fore.YELLOW + f"{addr}: Unknown message type: {msg_type}")

    except Exception as e:
        print(Fore.RED + f"Error handling client {addr}: {e}")
    finally:
        conn.close()
        print(Fore.CYAN + f"[CONNECTION CLOSED] {addr}")

def main():
    # Making sure the  DB is ready
    db.create_users_table()
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.bind((config.SERVER_HOST, config.SERVER_PORT))
        server_socket.listen(5)
        print(Fore.GREEN + f"Server listening on {config.SERVER_HOST}:{config.SERVER_PORT}...")
        
        while True:
            conn, addr = server_socket.accept()
            # Start a new thread for each client
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.daemon = True
            client_thread.start()
            
    except Exception as e:
        print(Fore.RED + f"Server Error: {e}")
    finally:
        server_socket.close()
        print("Server shutting down.")

if __name__ == "__main__":
    main()