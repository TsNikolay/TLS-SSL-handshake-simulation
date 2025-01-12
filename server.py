import socket
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import NameOID, CertificateSigningRequestBuilder, load_pem_x509_certificate
import os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509

# Генерація пари ключів для сервера
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()

# Створення CSR
csr = CertificateSigningRequestBuilder().subject_name(
    x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "UA"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Kyiv"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Kyiv"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Server Organization"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
).sign(private_key, hashes.SHA256())

# Підключення до CA
ca_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ca_conn.connect(('localhost', 65431))
print("Підключено до центру сертифікації.")

# Відправка CSR до CA
csr_pem = csr.public_bytes(serialization.Encoding.PEM)
ca_conn.sendall(csr_pem)
print("CSR надіслано до центру сертифікації.")

# Отримання підписаного сертифіката
cert_pem = ca_conn.recv(4096)
server_certificate = load_pem_x509_certificate(cert_pem)
print("Сертифікат отримано від центру сертифікації.")
ca_conn.close()

# Сервер
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('localhost', 65432))
server.listen(1)
print("Сервер запущено і чекає на підключення клієнта...")

conn, addr = server.accept()
print(f"Клієнт підключився: {addr}")

# Отримання "hello_client" від клієнта
data = conn.recv(1024).decode()
hello_client = data
print(f"Отримано від клієнта: {hello_client}")

# Формування даних для клієнта
hello_server = os.urandom(16).hex()
response = {
    "hello_server": hello_server,
    "public_key": public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode(),
    "certificate": server_certificate.public_bytes(serialization.Encoding.PEM).decode()
}

conn.sendall(json.dumps(response).encode())
print("Відправлено клієнту: hello_server + публічний ключ + сертифікат")


# Отримання зашифрованого premaster secret
encrypted_premaster = conn.recv(1024)
premaster_secret = private_key.decrypt(
    encrypted_premaster,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print(f"Розшифровано premaster secret: {premaster_secret.hex()}")

# Генерація симетричного ключа
key_material = hello_client.encode() + hello_server.encode() + premaster_secret
session_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"handshake data",
).derive(key_material)
print(f"Згенеровано симетричний ключ: {session_key.hex()}")

# Обмін повідомленням "готовий"
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
encryptor = cipher.encryptor()
ready_message = "готовий".encode()
encrypted_ready = iv + encryptor.update(ready_message) + encryptor.finalize()
conn.sendall(encrypted_ready)
print("Відправлено зашифроване повідомлення 'готовий' клієнту")

# Отримання зашифрованого повідомлення "готовий" від клієнта
ciphertext = conn.recv(1024)
iv = ciphertext[:16]
encrypted_message = ciphertext[16:]

cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
decryptor = cipher.decryptor()
client_ready_message = decryptor.update(encrypted_message) + decryptor.finalize()
print(f"Розшифроване повідомлення від клієнта: {client_ready_message.decode()}")


# Отримання зашифрованого повідомлення від клієнта
ciphertext = conn.recv(1024)
iv = ciphertext[:16]
encrypted_message = ciphertext[16:]

cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
decryptor = cipher.decryptor()
final_message = decryptor.update(encrypted_message) + decryptor.finalize()
print(f"Розшифроване повідомлення від клієнта: {final_message.decode()}")

conn.close()
