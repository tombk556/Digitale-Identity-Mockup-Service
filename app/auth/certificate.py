import os
import datetime
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import CertificateBuilder, Name, NameAttribute

def generate_user_certificate(id: str) -> tuple[bytes, bytes]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = Name([
        NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        NameAttribute(NameOID.ORGANIZATION_NAME, u"MyApp"),
        NameAttribute(NameOID.COMMON_NAME, id),
    ])
    
    cert = CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        1000
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).sign(private_key, SHA256())

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_pem = cert.public_bytes(serialization.Encoding.PEM)

    return private_key_pem, public_key_pem


def create_file(id: str, name: str):
    PRIVATE_KEY_DIRECTORY = "/Users/tom/Documents/AWI Msc./3. Semester/Digitale Wirtschaft & Verwaltung/Fallbeispiel 3/Mockup/app/tmp"
    
    private_key, public_key = generate_user_certificate(id)

    private_key_filename = f"{name}_private_key.pem"
    private_key_path = os.path.join(PRIVATE_KEY_DIRECTORY, private_key_filename)
    with open(private_key_path, "wb") as key_file:
        key_file.write(private_key)
    
    download_url = private_key_path
    
    return download_url, public_key.decode("utf-8")