# scripts/gen_ca.py
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    BestAvailableEncryption
)
from cryptography.hazmat.backends import default_backend
import datetime


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERT_DIR = os.path.join(PROJECT_ROOT, "certs")

CA_KEY_FILE = os.path.join(CERT_DIR, "ca.key")
CA_CERT_FILE = os.path.join(CERT_DIR, "ca.crt")
CA_PASSWORD = b"my_secure_ca_password_123!" # Change this if you want

def generate_ca():
    print("Generating Root CA...")
    
    os.makedirs(CERT_DIR, exist_ok=True)

    # Private key generation
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )

    # Private key storage (encrypted)
    with open(CA_KEY_FILE, "wb") as f:
        f.write(ca_private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=BestAvailableEncryption(CA_PASSWORD)
        ))
    print(f"CA Private Key saved to {CA_KEY_FILE} (encrypted)")

    # Create self-signed CA certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST NUCES"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"My SecureChat Root CA"),
    ])

    ca_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        # Valid for 5 years
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=5*365)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(ca_private_key, hashes.SHA256(), default_backend())

    #  Storing CA Certificate
    with open(CA_CERT_FILE, "wb") as f:
        f.write(ca_cert.public_bytes(Encoding.PEM))
    print(f"CA Certificate saved to {CA_CERT_FILE}")
    print("Root CA generation complete.")

if __name__ == "__main__":
    if os.path.exists(CA_KEY_FILE) or os.path.exists(CA_CERT_FILE):
        print(f"CA files already exist in '{CERT_DIR}'. To regenerate, please delete them first.")
    else:
        generate_ca()