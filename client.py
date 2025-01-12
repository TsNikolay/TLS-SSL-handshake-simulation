import socket
import json
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import load_pem_x509_certificate
import os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Клієнт
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('localhost', 65432))
print("Підключено до сервера.")

# Клієнт надсилає серверу випадковий рядок ("привіт клієнта").
hello_client = os.urandom(16).hex()
client.sendall(hello_client.encode())
print(f"Відправлено серверу: {hello_client}")

# Отримання привіт, публічний ключ, cертифікат від серверу
data = client.recv(4096).decode()
response = json.loads(data)

hello_server = response["hello_server"]
server_public_key_pem = response["public_key"]
server_cert_pem = response["certificate"]
print(f"Отримано від сервера: hello_server = {hello_server}")

server_public_key = serialization.load_pem_public_key(
    server_public_key_pem.encode()
)
print("Публічний ключ сервера завантажено.")

server_certificate = load_pem_x509_certificate(server_cert_pem.encode())
print("Сертифікат сервера завантажено.")

# Підключення до CA для перевірки сертифіката
ca_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ca_conn.connect(('localhost', 65431))
ca_conn.sendall(server_cert_pem.encode())  # Надсилання сертифіката до CA
response = ca_conn.recv(1024).decode()
ca_conn.close()

if response != "cert_valid":
    print("Сертифікат недійсний!")
    client.close()
    exit()
print("Сертифікат сервера дійсний.")

# Генерація premaster secret
premaster_secret = os.urandom(32)
encrypted_premaster = server_public_key.encrypt(
    premaster_secret,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
client.sendall(encrypted_premaster)
print("Зашифрований premaster secret надіслано серверу.")

# Генерація симетричного ключа
key_material = hello_client.encode() + hello_server.encode() + premaster_secret
session_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"handshake data",
).derive(key_material)
print(f"Згенеровано симетричний ключ: {session_key.hex()}")

# Отримання та розшифрування повідомлення "готовий"
ciphertext = client.recv(1024)
iv = ciphertext[:16]
encrypted_message = ciphertext[16:]

cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
decryptor = cipher.decryptor()
message = decryptor.update(encrypted_message) + decryptor.finalize()
print(f"Отримано розшифроване повідомлення від сервера: {message.decode()}")

# Надсилання повідомлення "готовий" серверу
ready_message = "готовий".encode()
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
encryptor = cipher.encryptor()
encrypted_ready = iv + encryptor.update(ready_message) + encryptor.finalize()
client.sendall(encrypted_ready)
print("Повідомлення 'готовий' надіслано серверу.")


# Надсилання повідомлення серверу
final_message = "Це повідомлення від клієнта!".encode()
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
encryptor = cipher.encryptor()
encrypted_message = iv + encryptor.update(final_message) + encryptor.finalize()
client.sendall(encrypted_message)
print("Повідомлення надіслано серверу.")

client.close()
