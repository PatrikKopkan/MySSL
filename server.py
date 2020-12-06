import socket
from OpenSSL import crypto
import config2 as config
import sys
import certificate
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

HEADERSIZE = 10


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

            print(len(full_msg))

            if len(full_msg) - HEADERSIZE == msglen:
                print("full msg recvd")
                # print(full_msg[HEADERSIZE:])
                new_msg = True
                return full_msg[HEADERSIZE:]


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((socket.gethostname(), 1242))
s.listen(5)



with open(config.cert_path) as file:
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, file.read())

with open(config.privkey_path) as file:
    privkey = crypto.load_privatekey(crypto.FILETYPE_PEM, file.read())


def send(socket, msg: bytes):
    msg = bytes(f"{len(msg):<{HEADERSIZE}}", "utf-8") + msg

    socket.send(msg)


# now our endpoint knows about the OTHER endpoint.
clientsocket, address = s.accept()

print(f"Connection from {address} has been established.")

msg = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
msg = bytes(f"{len(msg):<{HEADERSIZE}}", "utf-8") + msg

clientsocket.send(msg)

client_cert = handle_message(clientsocket).decode()
client_cert = crypto.load_certificate(crypto.FILETYPE_PEM, client_cert)
if not certificate.verify_cert(client_cert):
    print("Client certificate is false, ending connection")
    clientsocket.close()
    sys.exit(1)
print("Client certificate is alright")
client_pubkey = client_cert.get_pubkey()
client_pubkey = RSA.import_key(crypto.dump_publickey(crypto.FILETYPE_PEM, client_pubkey))

session_key = get_random_bytes(16)

# Encrypt the session key with the public RSA key
cipher_rsa = PKCS1_OAEP.new(client_pubkey)
enc_session_key = cipher_rsa.encrypt(session_key)

send(clientsocket, enc_session_key)
print("sending crypted aes key")

cipher = AES.new(session_key, AES.MODE_EAX)

while True:
    data = input("Enter message: ")
    if data:
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())

        send(clientsocket, cipher.nonce + tag + ciphertext)
        cipher = AES.new(session_key, AES.MODE_EAX)




