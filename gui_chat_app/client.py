import socket
import threading
import tkinter as tk
from tkinter import simpledialog, scrolledtext, messagebox, filedialog
import json
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode, b64decode
import os

HOST = '127.0.0.1'
PORT = 12345

class ClientApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Secure Chat Client")
        self.root.geometry("500x500")

        # Chat display area (read-only)
        self.chat_area = scrolledtext.ScrolledText(self.root, state='disabled', wrap=tk.WORD)
        self.chat_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Message input box
        self.msg_entry = tk.Entry(self.root)
        self.msg_entry.pack(padx=10, pady=(0, 10), fill=tk.X)
        self.msg_entry.bind("<Return>", lambda event: self.send_message())

        # Send button
        send_button = tk.Button(self.root, text="Send", command=self.send_message)
        send_button.pack(padx=10, pady=(0, 10))

        # Initially hide main window while getting username
        self.root.withdraw()

        # Ask username on main thread before starting networking
        self.username = simpledialog.askstring("Username", "Enter your username:", parent=self.root)
        if not self.username:
            messagebox.showerror("Error", "Username is required!")
            self.root.destroy()
            return

        # Show main window after username input
        self.root.deiconify()

        # Setup socket and crypto variables
        self.client_socket = None
        self.server_public_key = None
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey()

        # Start connection and communication thread
        threading.Thread(target=self.setup_encryption_and_login, daemon=True).start()

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()

    def setup_encryption_and_login(self):
        try:
            # Connect to server
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((HOST, PORT))

            # Step 1: Receive server public key
            server_pub_pem = self.client_socket.recv(4096)
            self.server_public_key = RSA.import_key(server_pub_pem)

            # Step 2: Send client public key
            client_pub_pem = self.public_key.export_key()
            self.client_socket.send(client_pub_pem)

            # Step 3: Encrypt username with server public key and send
            cipher_rsa = PKCS1_OAEP.new(self.server_public_key)
            encrypted_username = b64encode(cipher_rsa.encrypt(self.username.encode('utf-8')))
            self.client_socket.send(encrypted_username)

            self.display_message(f"[System] Connected to server as {self.username}")

            # Start listening thread for incoming messages
            threading.Thread(target=self.receive_messages, daemon=True).start()

        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect to server:\n{e}")
            self.root.destroy()

    def send_message(self):
        message = self.msg_entry.get().strip()
        if message == "":
            return
        self.msg_entry.delete(0, tk.END)

        try:
            # Prepare JSON message with timestamp
            timestamp = datetime.now().strftime("%H:%M:%S")
            msg_dict = {
                'username': self.username,
                'timestamp': timestamp,
                'message': message
            }
            msg_json = json.dumps(msg_dict)

            # Encrypt message with server public key
            cipher_rsa = PKCS1_OAEP.new(self.server_public_key)
            encrypted_msg = b64encode(cipher_rsa.encrypt(msg_json.encode('utf-8')))
            self.client_socket.send(encrypted_msg)

            # Display own message locally
            self.display_message(f"[{timestamp}] You: {message}")

        except Exception as e:
            messagebox.showerror("Send Error", f"Failed to send message:\n{e}")
            self.client_socket.close()
            self.root.destroy()

    def receive_messages(self):
        try:
            cipher_rsa = PKCS1_OAEP.new(self.private_key)
            while True:
                encrypted_msg = self.client_socket.recv(4096)
                if not encrypted_msg:
                    break

                # Decrypt message with client's private key
                msg_json = cipher_rsa.decrypt(b64decode(encrypted_msg)).decode('utf-8')
                msg_dict = json.loads(msg_json)

                username = msg_dict.get('username', 'Unknown')
                timestamp = msg_dict.get('timestamp', '')
                message = msg_dict.get('message', '')

                # Display incoming message
                if username != self.username:
                    self.display_message(f"[{timestamp}] {username}: {message}")

        except Exception as e:
            self.display_message(f"[System] Disconnected from server.")
            self.client_socket.close()
            self.root.destroy()

    def display_message(self, msg):
        self.chat_area.config(state='normal')
        self.chat_area.insert(tk.END, msg + '\n')
        self.chat_area.yview(tk.END)
        self.chat_area.config(state='disabled')

    def on_closing(self):
        try:
            if self.client_socket:
                self.client_socket.close()
        except:
            pass
        self.root.destroy()

if __name__ == "__main__":
    ClientApp()
