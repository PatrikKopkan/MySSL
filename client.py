import socket
import config1 as config
from OpenSSL import crypto
import certificate
import sys
import string
import random
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

from Crypto.PublicKey import RSA


with open(config.cert_path) as file:
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, file.read())

with open(config.privkey_path) as file:
    privkey = crypto.load_privatekey(crypto.FILETYPE_PEM, file.read())


def send(socket, msg: bytes):
    msg = bytes(f"{len(msg):<{HEADERSIZE}}", "utf-8") + msg

    socket.send(msg)


def handle_message(s):
    full_msg = b''
    new_msg = True
    while True:
        msg = s.recv(16)
        if msg:
            if new_msg:
                print("new msg len:", msg[:HEADERSIZE])
                msglen = int(msg[:HEADERSIZE])
                new_msg = False

                print(f"full message length: {msglen}")

            full_msg += msg

            # print(len(full_msg))

            if len(full_msg)-HEADERSIZE == msglen:
                print("full msg recvd")
                new_msg = True
                return full_msg[HEADERSIZE:]


HEADERSIZE = 10

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((socket.gethostname(), 1242))
print("navazani spojeni")


server_cert = handle_message(s).decode()
print(server_cert)

server_cert = crypto.load_certificate(crypto.FILETYPE_PEM, server_cert)
if not certificate.verify_cert(server_cert):
    print("Server certificate is false, ending connection")
    sys.exit(1)
print("Server certificate is alright")
server_cert.get_pubkey()

print("sending certificate")
msg = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
msg = bytes(f"{len(msg):<{HEADERSIZE}}", "utf-8") + msg

s.send(msg)


enc_session_key = handle_message(s)
privkey = RSA.import_key(crypto.dump_privatekey(crypto.FILETYPE_PEM, privkey))
cipher_rsa = PKCS1_OAEP.new(privkey)
session_key = cipher_rsa.decrypt(enc_session_key)

while True:
    msg = handle_message(s)
    if msg:
        nonce, tag, ciphertext = msg[0:16], msg[16:32], msg[32:]

        cipher = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)
        print(data.decode())
