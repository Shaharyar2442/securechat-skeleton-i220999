
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend

# Using pre-defined parameters (Group 14) for security and simplicity.
DH_PARAMS = dh.DHParameterNumbers(
    p=int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
        16
    ),
    g=2
).parameters(default_backend())

def generate_dh_keypair():
    #Generated a DiffieHilmen private/public key pair.
    private_key = DH_PARAMS.generate_private_key()
    public_key_int = private_key.public_key().public_numbers().y
    return private_key, public_key_int

def derive_shared_secret(private_key, peer_public_key_int):
    #Derives the DH shared secret as an integer (Ks).
    pn = DH_PARAMS.parameter_numbers()
    peer_public_numbers = dh.DHPublicNumbers(peer_public_key_int, pn)
    peer_public_key = peer_public_numbers.public_key(default_backend())
    
    shared_secret_bytes = private_key.exchange(peer_public_key) # This 'shared_secret' is the big-endian byte representation of Ks
    
    shared_secret_int = int.from_bytes(shared_secret_bytes, 'big')
    return shared_secret_int

def derive_session_key(shared_secret_int): #Function to derive AES session key from DH shared secret
    ks_bytes = shared_secret_int.to_bytes(
        (shared_secret_int.bit_length() + 7) // 8, 'big'
    )
    
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(ks_bytes)
    full_hash = digest.finalize()
    
    # Truncate to 16 bytes for AES-128
    return full_hash[:16]