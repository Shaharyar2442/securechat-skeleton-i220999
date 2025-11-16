"""
Handles Diffie-Hellman key exchange and session key derivation.
"""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend

# Use pre-defined parameters (Group 14) for security and simplicity.
DH_PARAMS = dh.load_parameters(
    b"-----BEGIN DH PARAMETERS-----\n"
    b"MIIBCAKCAQEA///////////JD9QIASKD6A0uJ+JbVo/1Z1r/f1Ayl36d+tHTSg9I\n"
    b"5pZ8+bJJyN2T/Ex9vAgtCC6mvyyS5lJj9aUfF3E+CnsxOKVzJGRziVl8K3sVskYS\n"
    b"zDhiC4PIfpDjZAqAHM8GCNfFf8Nqf/MhXfPmbBEOVvInyT3D2dGvgaUB2QkGYP2s\n"
    b"uS/E/Pq03RhSctUfOaN2J9I5AByySjY0z5Yf3rNfXSpRErxS+J0RknYra/vlS+fU\n"
    b"xRzLkf3M/BvN1Yt5/PtxfHPaBqctpDqTjQ1ZJ5eBq/sWbFhBTRrgrB/dFhG+\n"
    b"n0h8YlQ8tA1sTMrO/yP0b+lPNSyWUj1tN/p6/wGvGqPSpvIY/dSn/M9C/UfR+v3U\n"
    b"GfEsMPP8MHWfFqK/bBLM9TzVpP0XQ+I7CtA1mcqjM5E+L9nN/W/tHkE/WkGAAwIB\n"
    b"AQI=\n"
    b"-----END DH PARAMETERS-----\n",
    default_backend()
)

def generate_dh_keypair():
    """Generates a DH private/public key pair."""
    private_key = DH_PARAMS.generate_private_key()
    public_key_int = private_key.public_key().public_numbers().y
    return private_key, public_key_int

def derive_shared_secret(private_key, peer_public_key_int):
    """Derives the DH shared secret as an integer (Ks)."""
    pn = DH_PARAMS.parameter_numbers()
    peer_public_numbers = dh.DHPublicNumbers(peer_public_key_int, pn)
    peer_public_key = peer_public_numbers.public_key(default_backend())
    
    # This 'shared_secret' is the big-endian byte representation of Ks
    shared_secret_bytes = private_key.exchange(peer_public_key)
    
    shared_secret_int = int.from_bytes(shared_secret_bytes, 'big')
    return shared_secret_int

def derive_session_key(shared_secret_int):
    """Derives AES key as K = Trunc16(SHA256(big-endian(Ks)))."""
    # Convert int to big-endian bytes
    ks_bytes = shared_secret_int.to_bytes(
        (shared_secret_int.bit_length() + 7) // 8, 'big'
    )
    
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(ks_bytes)
    full_hash = digest.finalize()
    
    # Truncate to 16 bytes for AES-128
    return full_hash[:16]