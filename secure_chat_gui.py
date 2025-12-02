#!/usr/bin/env python3
"""
Secure Chat (AES-GCM + RSA) with optional auto-ngrok TCP tunnel.
- Server will bind to 0.0.0.0:9999
- If ngrok is installed and authtoken configured, the app will start `ngrok tcp 9999`
  and display the public tcp host:port in the GUI.
- Client should connect to that host:port.
"""

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
import subprocess
import time
import requests
import shutil

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

# ---------- ngrok helper ----------
def start_ngrok_tcp(local_port, max_wait=12):
    """
    Start ngrok tcp <local_port> as a background process and query the local API
    to extract public tcp host:port. Returns (public_host, public_port, proc).
    Raises RuntimeError if ngrok not found or tunnel not ready.
    """
    NGROK_CMD = shutil.which("ngrok") or "/usr/local/bin/ngrok"
    if not os.path.exists(NGROK_CMD):
        raise RuntimeError("ngrok binary not found. Please install ngrok and set authtoken.")
    # Start ngrok
    proc = subprocess.Popen([NGROK_CMD, "tcp", str(local_port)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    api = "http://127.0.0.1:4040/api/tunnels"
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            r = requests.get(api, timeout=1)
            data = r.json()
            for t in data.get("tunnels", []):
                public_url = t.get("public_url")
                if public_url and public_url.startswith("tcp://"):
                    host_port = public_url[len("tcp://"):]
                    host, port = host_port.split(":")
                    return host, int(port), proc
        except Exception:
            pass
        time.sleep(0.5)
    # failed -> kill process
    try:
        proc.kill()
    except Exception:
        pass
    raise RuntimeError("ngrok tunnel did not appear within timeout. Check ngrok authtoken and network.")

# ---------- SecureChatApp Class ----------
class SecureChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat (AES-GCM + RSA)")
        self.sock = None
        self.conn = None
        self.ngrok_proc = None
        # ask role
        self.is_server = messagebox.askyesno("Role", "Are you the server?")
        self.server_ip = None
        self.server_port = 9999

        if self.is_server:
            # bind to all interfaces
            # NOTE: we present the local IP so user knows LAN address, but bind uses 0.0.0.0
            self.server_ip = "0.0.0.0"
            # get a local ip for info display (not for bind)
            self.local_info_ip = self.get_local_ip_info()
            messagebox.showinfo("Server Info",
                                f"Your local IP: {self.local_info_ip}\nPort: {self.server_port}\n\n"
                                "If you want automatic public endpoint, install ngrok and set authtoken.\n"
                                "Otherwise run ngrok manually: ngrok tcp 9999")
        else:
            # client: ask for host and port (we added retry so it's OK if ngrok still starting)
            self.server_ip = simpledialog.askstring("Server Host",
                                                     "Enter server host (e.g., 0.tcp.ngrok.io or domain):")
            if not self.server_ip:
                messagebox.showerror("Error", "Server host required!")
                sys.exit(1)
            self.server_port = simpledialog.askinteger("Server Port", "Enter server port (e.g., 15123):", minvalue=1, maxvalue=65535)
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
            # optionally start ngrok automatically (best-effort)
            try:
                host, port, proc = start_ngrok_tcp(self.server_port, max_wait=12)
                self.ngrok_proc = proc
                self.append_chat(f"Auto-ngrok started. Public endpoint: {host}:{port}\n")
                self.append_chat("Tell your friend to connect to that host & port.\n")
            except Exception as e:
                self.append_chat(f"Auto-ngrok not started: {e}\n")
                self.append_chat("You can manually run: ngrok tcp 9999\n")
            threading.Thread(target=self.start_server, daemon=True).start()
        else:
            # client: use retrying connect
            threading.Thread(target=self.connect_with_retry_wrapper, daemon=True).start()

        # ensure tidy cleanup on close
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        try:
            if self.conn:
                try:
                    self.conn.close()
                except:
                    pass
            if self.sock:
                try:
                    self.sock.close()
                except:
                    pass
            if self.ngrok_proc:
                try:
                    self.append_chat("Terminating ngrok...\n")
                    self.ngrok_proc.terminate()
                except:
                    pass
        except Exception:
            pass
        self.root.quit()

    def get_local_ip_info(self):
        # try to detect a useful local IP to display (not used for bind)
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
            self.append_chat(f"Server listening on 0.0.0.0:{self.server_port}\n")
            self.append_chat("Waiting for client to connect...\n")
            self.conn, addr = self.sock.accept()
            self.append_chat(f"Client connected from {addr}\n")
            # exchange keys and start encrypted session
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
    def connect_with_retry_wrapper(self):
        try:
            self.conn = self.connect_with_retry(self.server_ip, self.server_port, retries=12, delay=2)
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

    def connect_with_retry(self, host, port, retries=6, delay=2):
        import time, socket
        last_exc = None
        for i in range(retries):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(8)
                s.connect((host, port))
                s.settimeout(None)
                return s
            except Exception as e:
                last_exc = e
                self.append_chat(f"Connect attempt {i+1}/{retries} failed: {e}\n")
                time.sleep(delay)
        raise ConnectionError(f"All connect attempts failed. Last error: {last_exc}")

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
    root.mainloop()
