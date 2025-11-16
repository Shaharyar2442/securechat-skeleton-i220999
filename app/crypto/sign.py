"""
Handles loading RSA private keys and creating/verifying digital signatures.
"""
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

def load_private_key(key_file):
    """Loads a PEM-encoded private key."""
    with open(key_file, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None, # Assuming no password for entity keys
            backend=default_backend()
        )
    return private_key

def sign_data(private_key, data):
    """Signs data using RSA-PSS with SHA-256."""
    if isinstance(data, str):
        data = data.encode('utf-8')
        
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key, signature, data):
    """Verifies an RSA-PSS SHA-256 signature."""
    if isinstance(data, str):
        data = data.encode('utf-8')
        
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        print(f"Signature verification error: {e}")
        return False