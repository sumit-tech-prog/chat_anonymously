import socket
import threading
import struct
import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import sys
import traceback

# ---------- Helper functions for length-prefixed messaging ----------
def send_data(sock: socket.socket, data: bytes):
    length = struct.pack(">I", len(data))
    sock.sendall(length + data)

def recv_all(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed")
        buf += chunk
    return buf

def recv_data(sock: socket.socket) -> bytes:
    header = recv_all(sock, 4)
    length = struct.unpack(">I", header)[0]
    return recv_all(sock, length)

# ---------- SecureChatApp Class ----------
class SecureChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat (AES-GCM + RSA)")
        self.sock = None
        self.conn = None
        self.is_server = messagebox.askyesno("Role", "Are you the server?")
        self.server_ip = None
        self.server_port = 9999

        if self.is_server:
            self.server_ip = self.get_local_ip()
            messagebox.showinfo("Server Info",
                                f"Your IP: {self.server_ip}\nPort: {self.server_port}\n\n"
                                "Run Cloudflared:\n"
                                "./cloudflared-linux-amd64 tunnel --url tcp://localhost:9999")
        else:
            self.server_ip = simpledialog.askstring("Server IP",
                                                     "Enter server IP (e.g., backed-pastor-ste-combined.trycloudflare.com):")
            if not self.server_ip:
                messagebox.showerror("Error", "Server IP required!")
                sys.exit(1)
            self.server_port = simpledialog.askinteger("Server Port", "Enter server port (e.g., 9999):", minvalue=1, maxvalue=65535)
            if not self.server_port:
                self.server_port = 9999

        # GUI Setup
        self.chat_display = scrolledtext.ScrolledText(root, width=60, height=20, state=tk.DISABLED)
        self.chat_display.grid(row=0, column=0, columnspan=2, padx=10, pady=10)
        self.message_entry = tk.Entry(root, width=50)
        self.message_entry.grid(row=1, column=0, padx=10, pady=10)
        self.message_entry.bind("<Return>", lambda e: self.send_message())
        self.send_button = tk.Button(root, text="Send", command=self.send_message)
        self.send_button.grid(row=1, column=1, padx=10, pady=10)

        # Cryptographic keys
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        self.other_public_key = None
        self.aes_key = None
        self.aesgcm = None

        # Start networking
        if self.is_server:
            threading.Thread(target=self.start_server, daemon=True).start()
        else:
            threading.Thread(target=self.connect_to_server, daemon=True).start()

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def append_chat(self, text):
        self.root.after(0, lambda: self._append_chat(text))

    def _append_chat(self, text):
        self.chat_display.configure(state=tk.NORMAL)
        self.chat_display.insert(tk.END, text)
        self.chat_display.configure(state=tk.DISABLED)
        self.chat_display.see(tk.END)

    # Server methods
    def start_server(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.server_ip, self.server_port))
            self.sock.listen(1)
            self.append_chat(f"Server listening on {self.server_ip}:{self.server_port}\n")
            self.conn, addr = self.sock.accept()
            self.append_chat(f"Client connected from {addr}\n")
            self.exchange_public_keys_server()
            self.aes_key = AESGCM.generate_key(bit_length=256)
            encrypted_aes = self.other_public_key.encrypt(
                self.aes_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            send_data(self.conn, encrypted_aes)
            self.aesgcm = AESGCM(self.aes_key)
            self.append_chat("AES key securely sent to client.\n")
            threading.Thread(target=self.receive_messages, daemon=True).start()
        except Exception as e:
            self.append_chat(f"Server error: {e}\n")

    def exchange_public_keys_server(self):
        pub_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        send_data(self.conn, pub_pem)
        other_pem = recv_data(self.conn)
        self.other_public_key = serialization.load_pem_public_key(other_pem)

    # Client methods
    def connect_to_server(self):
        try:
            self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.conn.connect((self.server_ip, self.server_port))
            self.append_chat(f"Connected to server {self.server_ip}:{self.server_port}\n")
            other_pem = recv_data(self.conn)
            self.other_public_key = serialization.load_pem_public_key(other_pem)
            pub_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            send_data(self.conn, pub_pem)
            encrypted_aes = recv_data(self.conn)
            self.aes_key = self.private_key.decrypt(
                encrypted_aes,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            self.aesgcm = AESGCM(self.aes_key)
            self.append_chat("AES key received from server.\n")
            threading.Thread(target=self.receive_messages, daemon=True).start()
        except Exception as e:
            self.append_chat(f"Client error: {e}\n")

    # Messaging
    def send_message(self):
        msg = self.message_entry.get().strip()
        if not msg or not self.conn or not self.aesgcm:
            return
        try:
            nonce = os.urandom(12)
            ct = self.aesgcm.encrypt(nonce, msg.encode("utf-8"), None)
            send_data(self.conn, nonce + ct)
            self.append_chat(f"You: {msg}\n")
            self.message_entry.delete(0, tk.END)
        except Exception as e:
            self.append_chat(f"Send error: {e}\n")

    def receive_messages(self):
        try:
            while True:
                data = recv_data(self.conn)
                nonce, ct = data[:12], data[12:]
                pt = self.aesgcm.decrypt(nonce, ct, None)
                self.append_chat(f"Other: {pt.decode('utf-8')}\n")
        except Exception as e:
            self.append_chat(f"Connection error: {e}\n")

# Run
if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChatApp(root)
    root.protocol("WM_DELETE_WINDOW", root.quit)
    root.mainloop()
