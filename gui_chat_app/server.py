
import socket
import threading
import json
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode, b64decode

HOST = '127.0.0.1'
PORT = 12345

clients = {}  # {client_socket: username}
client_public_keys = {}  # {client_socket: RSA public key (for encryption)}

server_key = RSA.generate(2048)
server_public_key_pem = server_key.publickey().export_key()

def send_encrypted(client, data):
    # Encrypt data with client's public key (RSA)
    if client in client_public_keys:
        cipher_rsa = PKCS1_OAEP.new(client_public_keys[client])
        encrypted_data = cipher_rsa.encrypt(data.encode('utf-8'))
        client.send(b64encode(encrypted_data))
    else:
        client.send(data.encode('utf-8'))  # fallback no encryption

def broadcast(message, sender_socket=None):
    for client in clients:
        if client != sender_socket:
            try:
                send_encrypted(client, message)
            except:
                remove_client(client)

def remove_client(client):
    if client in clients:
        username = clients[client]
        print(f"[DISCONNECT] {username}")
        broadcast(f"[{username} left the chat]", None)
        del clients[client]
        if client in client_public_keys:
            del client_public_keys[client]
        client.close()

def handle_client(client):
    try:
        # existing code here...
        # Step 1: Send server public key
        client.send(server_public_key_pem)

        # Step 2: Receive client's public key
        client_pub_pem = client.recv(4096)
        client_pub_key = RSA.import_key(client_pub_pem)
        client_public_keys[client] = client_pub_key

        # Step 3: Receive username (encrypted)
        encrypted_username = client.recv(1024)
        cipher_rsa = PKCS1_OAEP.new(server_key)
        username = cipher_rsa.decrypt(b64decode(encrypted_username)).decode('utf-8')

        clients[client] = username
        print(f"[NEW CONNECTION] {username}")
        broadcast(f"[{username} joined the chat]", client)

        # main loop here...

    except Exception as e:
        print(f"Error in client handler: {e}")
        remove_client(client)


def start():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[STARTED] Server listening on {HOST}:{PORT}")
    while True:
        client_socket, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(client_socket,))
        thread.start()

if __name__ == "__main__":
    start()
