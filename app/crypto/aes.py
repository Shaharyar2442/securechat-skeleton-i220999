"""
Handles AES-128-CBC encryption and decryption with PKCS#7 padding.
"""
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend

def encrypt_aes_cbc(key, plaintext):
    #This function encrypts plaintext using AES-128-CBC with PKCS#7 padding.
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
        
    #Padding, IV generation, encryption
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    iv = os.urandom(16)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Returning IV and ciphertext concatenated
    return iv + ciphertext

def decrypt_aes_cbc(key, iv_plus_ciphertext):
    #This function decrypts AES-128-CBC encrypted data with PKCS#7 padding.
    try:
        #Extractiing and separating IV and ciphertext
        iv = iv_plus_ciphertext[:16]
        ciphertext = iv_plus_ciphertext[16:]
        
        # Decrypting
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Unpadding
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext
    except Exception as e:
        print(f"AES Decryption/Unpadding Error: {e}")
        return None
