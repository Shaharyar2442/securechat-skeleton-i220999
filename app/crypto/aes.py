"""
Handles AES-128-CBC encryption and decryption with PKCS#7 padding.
"""
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend

def encrypt_aes_cbc(key, plaintext):
    """ This Encrypts plaintext using AES-128-CBC with PKCS#7 padding."""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
        
    # 1. Apply PKCS#7 padding
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    # 2. Generate a random 16-byte IV
    iv = os.urandom(16)
    
    # 3. Encrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # 4. Return IV + Ciphertext
    return iv + ciphertext

def decrypt_aes_cbc(key, iv_plus_ciphertext):
    """Decrypts IV + Ciphertext using AES-128-CBC and unpads."""
    try:
        # 1. Split IV and Ciphertext
        iv = iv_plus_ciphertext[:16]
        ciphertext = iv_plus_ciphertext[16:]
        
        # 2. Decrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # 3. Unpad
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext
    except Exception as e:
        print(f"AES Decryption/Unpadding Error: {e}")
        return None
