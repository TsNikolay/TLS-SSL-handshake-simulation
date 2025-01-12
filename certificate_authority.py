import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import CertificateBuilder, NameOID
from cryptography import x509
from datetime import datetime, timedelta, timezone
from cryptography.x509 import load_pem_x509_csr
from cryptography.x509 import load_pem_x509_certificate


# Генерація ключів CA
ca_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
ca_public_key = ca_private_key.public_key()

# Генерація самопідписанного сертифіката CA
ca_certificate = (
    CertificateBuilder()
    .subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "UA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Certification Authority"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost CA"),
        ])
    )
    .issuer_name(
        x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "UA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Certification Authority"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost CA"),
        ])
    )
    .public_key(ca_public_key)
    .serial_number(1000)
    .not_valid_before(datetime.now(timezone.utc))
    .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
    .sign(ca_private_key, hashes.SHA256())
)

def sign_csr(csr):
    # Підписання CSR и повернення сертифіката
    certificate = (
        CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_certificate.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(ca_private_key, hashes.SHA256())
    )
    return certificate

def verify_certificate(certificate):
    # Перевірка підпису сертифікату через CA
    try:
        ca_certificate.public_key().verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm,
        )
        return True
    except Exception as e:
        print(f"Помилка перевірки сертифікату{e}")
        return False

# Центр сертификації
ca_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ca_socket.bind(('localhost', 65431))
ca_socket.listen(1)
print("Центр сертификації запущений и очікує підключення...")

while True:
    conn, addr = ca_socket.accept()
    print(f"Підключився клієнт або сервер: {addr}")
    data = conn.recv(4096)
    try:
        if b"-----BEGIN CERTIFICATE REQUEST-----" in data:
            # Обробка CSR від сервера
            print("Отримано CSR.")
            csr = load_pem_x509_csr(data)
            signed_cert = sign_csr(csr)
            conn.sendall(signed_cert.public_bytes(serialization.Encoding.PEM))
            print("Підписаний сертифікат відправлений.")
        elif b"-----BEGIN CERTIFICATE-----" in data:
            # Обробка сертифіката від клієнта
            print("Отримано сертифікат для перевірки.")
            certificate = load_pem_x509_certificate(data)
            if verify_certificate(certificate):
                conn.sendall(b"cert_valid")
                print("Сертифікат дійсний.")
            else:
                conn.sendall(b"cert_invalid")
                print("Сертифікат не дійсний.")
        else:
            print("Невідомий формат даних.")
            conn.sendall(b"UNKNOWN_DATA")
    except Exception as e:
        print(f"Помилка обробки даних: {e}")
        conn.sendall(b"ERROR")
    finally:
        conn.close()


