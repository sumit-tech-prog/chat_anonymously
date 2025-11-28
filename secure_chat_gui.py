# secure_chat.py
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
    # send 4-byte length then data
    length = struct.pack(">I", len(data))
    sock.sendall(length + data)

def recv_all(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed while reading data")
        buf += chunk
    return buf

def recv_data(sock: socket.socket) -> bytes:
    header = recv_all(sock, 4)
    length = struct.unpack(">I", header)[0]
    if length == 0:
        return b""
    return recv_all(sock, length)

# ---------- Networking / Cryptography logic ----------
PORT = 9999
SERVER_IP_DEFAULT = None  # will be auto-detected for server display

def get_local_ip():
    # Attempt to get non-loopback local IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

class SecureChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat (AES-GCM + RSA)")
        self.sock = None
        self.conn = None  # used by server for accepted connection or by client as the socket
        self.is_server = messagebox.askyesno("Role", "Are you the server (receiver)?")
        self.server_ip = None
        if self.is_server:
            self.server_ip = get_local_ip()
        else:
            # ask client for server IP
            self.server_ip = simpledialog.askstring("Server IP", "Enter server IP address:", parent=self.root)
            if not self.server_ip:
                messagebox.showerror("Error", "Server IP required for client mode.")
                sys.exit(1)

        # GUI
        self.chat_display = scrolledtext.ScrolledText(root, width=60, height=20, state=tk.DISABLED)
        self.chat_display.grid(row=0, column=0, columnspan=2, padx=10, pady=10)

        self.message_entry = tk.Entry(root, width=50)
        self.message_entry.grid(row=1, column=0, padx=10, pady=10)
        self.message_entry.bind("<Return>", lambda e: self.send_message())

        self.send_button = tk.Button(root, text="Send", command=self.send_message)
        self.send_button.grid(row=1, column=1, padx=10, pady=10)

        # Cryptographic keys (generated in memory)
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        self.other_public_key = None
        self.aes_key = None  # will be bytes
        self.aesgcm = None

        # Start networking threads
        if self.is_server:
            self.append_chat(f"Starting server on {self.server_ip}:{PORT}\n")
            threading.Thread(target=self.start_server, daemon=True).start()
        else:
            threading.Thread(target=self.connect_to_server, daemon=True).start()

        # For safe UI updates from threads
        self.ui_lock = threading.Lock()

    def append_chat(self, text):
        def _append():
            self.chat_display.configure(state=tk.NORMAL)
            self.chat_display.insert(tk.END, text)
            self.chat_display.configure(state=tk.DISABLED)
            self.chat_display.see(tk.END)
        self.root.after(0, _append)

    # SERVER
    def start_server(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.server_ip, PORT))
            self.sock.listen(1)
            self.append_chat("Server listening, waiting for client...\n")
            conn, addr = self.sock.accept()
            self.conn = conn
            self.append_chat(f"Client connected from {addr}\n")

            # Exchange public keys: send our public key, then receive theirs
            self.exchange_public_keys_server()

            # server generates AES key and sends it encrypted with client's public key
            self.aes_key = AESGCM.generate_key(bit_length=256)
            encrypted_aes = self.other_public_key.encrypt(
                self.aes_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                             algorithm=hashes.SHA256(), label=None)
            )
            send_data(self.conn, encrypted_aes)
            self.aesgcm = AESGCM(self.aes_key)
            self.append_chat("AES key generated and securely sent to client.\n")

            # Start receiving messages
            threading.Thread(target=self.receive_messages, daemon=True).start()
        except Exception as e:
            self.append_chat("Server error: " + str(e) + "\n")
            traceback.print_exc()

    def exchange_public_keys_server(self):
        # send our public key pem
        pub_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        send_data(self.conn, pub_pem)
        # receive client's public key pem
        other_pem = recv_data(self.conn)
        self.other_public_key = serialization.load_pem_public_key(other_pem)
        self.append_chat("Exchanged public keys with client.\n")

    # CLIENT
    def connect_to_server(self):
        try:
            self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.conn.connect((self.server_ip, PORT))
            self.append_chat(f"Connected to server {self.server_ip}:{PORT}\n")

            # Exchange public keys: receive server's public key, then send ours
            other_pem = recv_data(self.conn)
            self.other_public_key = serialization.load_pem_public_key(other_pem)
            # send ours
            pub_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            send_data(self.conn, pub_pem)
            self.append_chat("Exchanged public keys with server.\n")

            # receive encrypted AES, decrypt
            encrypted_aes = recv_data(self.conn)
            self.aes_key = self.private_key.decrypt(
                encrypted_aes,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                             algorithm=hashes.SHA256(), label=None)
            )
            self.aesgcm = AESGCM(self.aes_key)
            self.append_chat("Received AES key from server.\n")

            # Start receiving messages
            threading.Thread(target=self.receive_messages, daemon=True).start()
        except Exception as e:
            self.append_chat("Client error: " + str(e) + "\n")
            traceback.print_exc()

    # Sending encrypted messages using AES-GCM with a 12-byte nonce
    def send_message(self):
        msg = self.message_entry.get().strip()
        if not msg:
            return
        if not self.conn or not self.aesgcm:
            messagebox.showwarning("Not connected", "Connection or encryption not ready yet.")
            return
        try:
            nonce = os.urandom(12)
            ct = self.aesgcm.encrypt(nonce, msg.encode("utf-8"), None)
            payload = nonce + ct  # receiver knows first 12 bytes are nonce
            send_data(self.conn, payload)
            self.append_chat(f"You: {msg}\n")
            self.message_entry.delete(0, tk.END)
        except Exception as e:
            self.append_chat("Send error: " + str(e) + "\n")
            traceback.print_exc()

    def receive_messages(self):
        try:
            while True:
                data = recv_data(self.conn)
                if not data:
                    continue
                # first 12 bytes nonce
                if len(data) < 12:
                    self.append_chat("Received malformed packet.\n")
                    continue
                nonce = data[:12]
                ct = data[12:]
                try:
                    pt = self.aesgcm.decrypt(nonce, ct, None)
                    text = pt.decode("utf-8", errors="replace")
                    self.append_chat(f"Other: {text}\n")
                except Exception as e:
                    self.append_chat("Decrypt error or tampered message: " + str(e) + "\n")
        except ConnectionError:
            self.append_chat("Connection closed by peer.\n")
        except Exception as e:
            self.append_chat("Receive error: " + str(e) + "\n")
            traceback.print_exc()

# ---------- Run ----------
if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChatApp(root)
    root.protocol("WM_DELETE_WINDOW", root.quit)
    root.mainloop()
