"""
Common helper/utility functions:
- Millisecond timestamp
- Base64 encoding/decoding
- SHA-256 hashing
- Salt generation
- Salted password hashing
"""

import time
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def now_ms():
    """Returns the current time as an integer in milliseconds."""
    return int(time.time() * 1000)

def b64e(data: bytes) -> str:
    """Base64 encodes bytes into a UTF-8 string."""
    return base64.b64encode(data).decode('utf-8')

def b64d(data: str) -> bytes:
    """Base64 decodes a UTF-8 string into bytes."""
    try:
        return base64.b64decode(data)
    except Exception as e:
        print(f"Error decoding base64 data: {e}")
        return b""

def sha256_hex(data: bytes) -> str:
    """Computes a SHA-256 hash of data and returns a hex string."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    return digest.finalize().hex()

# --- Functions required for registration/login ---

def generate_salt(size=16) -> bytes:
    """Generates a cryptographically strong random salt."""
    return os.urandom(size)

def hash_password(salt: bytes, password: str) -> str:
    """Computes SHA-256(salt || password) and returns a hex string."""
    if isinstance(password, str):
        password = password.encode('utf-8')
    if not isinstance(salt, bytes):
        raise TypeError("Salt must be bytes")
        
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(salt)
    digest.update(password)
    return digest.finalize().hex()