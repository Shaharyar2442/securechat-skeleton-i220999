
import json
import base64
import sys
from colorama import Fore, Style, init


import os
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

try:
    from app.common import utils
    from app.crypto import pki, sign
except ImportError:
    print(Fore.RED + "Error: Could not import app modules.")
    print("Please run this script from the root of the 'securechat-skeleton' directory.")
    sys.exit(1)

init(autoreset=True)

def verify_session(receipt_file):
    print(f"Verifying session using receipt: {receipt_file}")
    
    try:
        with open(receipt_file, 'r') as f:
            receipt = json.load(f)
            
        transcript_file = receipt['transcript_file']
        our_cert_file = receipt['our_cert_file']
        receipt_hash = receipt['receipt_hash']
        receipt_sig_b64 = receipt['signature_b64']
        
        print(f" - Loading transcript: {transcript_file}")
        with open(transcript_file, 'r') as f:
            transcript_data = f.read()
            
        print(f" - Loading our certificate: {our_cert_file}")
        our_cert = pki.load_cert(our_cert_file)
        our_public_key = our_cert.public_key()
        
    except FileNotFoundError as e:
        print(Fore.RED + f"Error: File not found. {e}")
        print(Fore.YELLOW + "Did you run a client session to generate the files?")
        return
    except Exception as e:
        print(Fore.RED + f"Error loading files: {e}")
        return

    print("\n--- Verifying Session Receipt ---")
    
    computed_hash = utils.sha256_hex(transcript_data)
    
    print(f"  - Computed Hash: {computed_hash}")
    print(f"  - Receipt Hash:  {receipt_hash}")
    
    if computed_hash != receipt_hash:
        print(Fore.RED + "  - HASH MISMATCH! Transcript may have been tampered with.")
        # We can stop here, the signature will fail anyway
    else:
        print(Fore.GREEN + "  - Hash MATCH: Transcript integrity confirmed.")
        
    print("  - Verifying signature over receipt hash...")
    receipt_sig = base64.b64decode(receipt_sig_b64)
    
    if sign.verify_signature(our_public_key, receipt_sig, receipt_hash.encode('utf-8')):
        print(Fore.GREEN + "  - Receipt signature is VALID.")
    else:
        print(Fore.RED + "  - Receipt signature is INVALID.")
        
    print("\n--- Tamper Test ---")
    print("  - Simulating transcript modification...")
    tampered_data = transcript_data + "\n!!TAMPERED!!"
    tampered_hash = utils.sha256_hex(tampered_data)
    
    print(f"  - Tampered Hash: {tampered_hash}")
    print(f"  - Receipt Hash:  {receipt_hash}")
    
    if tampered_hash != receipt_hash:
        print(Fore.GREEN + "  - SUCCESS: Tampered hash does not match receipt hash.")
    else:
        print(Fore.RED + "  - FAILURE: Tampered hash matches receipt?!")
        
    print("\nVerification complete.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python verify_transcript.py <receipt_file.json>")
        print("Example: python verify_transcript.py server_session_receipt.json")
    else:
        verify_session(sys.argv[1])