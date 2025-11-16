"""
Handles X.509 Certificate loading and verification.
"""
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

def load_cert(cert_file):
    """Loads a PEM-encoded X.509 certificate from a file."""
    with open(cert_file, "rb") as f:
        cert_pem = f.read()
    return x509.load_pem_x509_certificate(cert_pem, default_backend())

def load_cert_from_pem(cert_pem):
    """Loads a PEM-encoded X.509 certificate from bytes."""
    return x509.load_pem_x509_certificate(cert_pem, default_backend())

def get_cert_pem(cert):
    """Converts a certificate object to PEM bytes."""
    return cert.public_bytes(serialization.Encoding.PEM)

def get_cert_fingerprint(cert):
    """Returns the SHA-256 fingerprint of a certificate."""
    return cert.fingerprint(hashes.SHA256()).hex()

def verify_certificate(cert_to_verify, ca_cert, expected_cn):
    """
    Verifies a certificate.
    Checks:
    1. Signature chain (signed by trusted CA)
    2. Expiry date
    3. Common Name (CN)
    """
    try:
        # 1. Check signature
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            cert_to_verify.signature,
            cert_to_verify.tbs_certificate_bytes,
            cert_to_verify.signature_algorithm_padding,
            cert_to_verify.signature_hash_algorithm,
        )
        
        # 2. Check expiry
        now = datetime.datetime.now(datetime.timezone.utc)
        if now < cert_to_verify.not_valid_before_utc or now > cert_to_verify.not_valid_after_utc:
            print(f"Certificate validation failed: Certificate is expired or not yet valid.")
            return False, "Certificate expired"
            
        # 3. Check Common Name
        cn = cert_to_verify.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if cn != expected_cn:
            print(f"Certificate validation failed: CN mismatch. Expected '{expected_cn}', got '{cn}'.")
            return False, "Certificate CN mismatch"
        
        print(f"Certificate for '{cn}' successfully verified.")
        return True, "Certificate valid"
        
    except InvalidSignature:
        print("Certificate validation failed: Invalid signature (not signed by our CA).")
        return False, "Invalid signature"
    except Exception as e:
        print(f"Certificate validation error: {e}")
        return False, str(e)