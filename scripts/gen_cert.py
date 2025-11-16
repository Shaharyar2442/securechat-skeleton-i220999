# scripts/gen_cert.py
import os
import sys
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
    load_pem_private_key
)
from cryptography.hazmat.backends import default_backend
import datetime

# Importing CA password from gen_ca
try:
    from gen_ca import CA_PASSWORD
except ImportError:
    print("Could not import CA_PASSWORD. Please ensure gen_ca.py is in the same directory.")
    CA_PASSWORD = b"my_secure_ca_password_123!" # Fallback, must match gen_ca.py

# Directory to store certs
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERT_DIR = os.path.join(PROJECT_ROOT, "certs")

CA_KEY_FILE = os.path.join(CERT_DIR, "ca.key")
CA_CERT_FILE = os.path.join(CERT_DIR, "ca.crt")

def generate_cert(common_name, filename_prefix):
    print(f"Generating certificate for: {common_name}")

    #  Loading CA private key and certificate
    if not os.path.exists(CA_KEY_FILE) or not os.path.exists(CA_CERT_FILE):
        print("CA key or certificate not found. Please run 'python scripts/gen_ca.py' first.")
        return

    try:
        with open(CA_KEY_FILE, "rb") as f:
            ca_private_key = load_pem_private_key(
                f.read(),
                password=CA_PASSWORD,
                backend=default_backend()
            )
        
        with open(CA_CERT_FILE, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    except Exception as e:
        print(f"Error loading CA files: {e}")
        print("Make sure your CA_PASSWORD in gen_ca.py is correct.")
        return

    #  Generating new private key for the entity (server/client)
    entity_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # 3. Storing  entity's private key (unencrypted)
    key_file = os.path.join(CERT_DIR, f"{filename_prefix}.key")
    with open(key_file, "wb") as f:
        f.write(entity_private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption()
        ))
    print(f"Entity private key saved to {key_file}")

    #  Create a certificate for the entity, signed by the CA
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST NUCES"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    issuer = ca_cert.subject

    entity_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        entity_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        # Valid for 1 year
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(common_name)]),
        critical=False,
    ).sign(ca_private_key, hashes.SHA256(), default_backend())

    #  Storing the  entity's certificate
    cert_file = os.path.join(CERT_DIR, f"{filename_prefix}.crt")
    with open(cert_file, "wb") as f:
        f.write(entity_cert.public_bytes(Encoding.PEM))
    print(f"Entity certificate saved to {cert_file}")
    print(f"Certificate generation for {common_name} complete.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python scripts/gen_cert.py <common_name> <filename_prefix>")
        print("Example: python scripts/gen_cert.py server server")
        print("Example: python scripts/gen_cert.py client client")
        sys.exit(1)
    
    common_name = sys.argv[1]
    filename_prefix = sys.argv[2]
    generate_cert(common_name, filename_prefix)