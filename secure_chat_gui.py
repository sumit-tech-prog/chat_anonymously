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
import subprocess
import time
import platform
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

# ---------- Cloudflare Tunnel Functions ----------
def check_cloudflared():
    """Check if cloudflared is installed and available"""
    try:
        subprocess.run(["cloudflared", "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except:
        return False

def download_cloudflared():
    """Download cloudflared based on the OS"""
    try:
        os_type = platform.system().lower()
        arch = "amd64"  # Default, adjust if needed

        if os_type == "windows":
            url = f"https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-{arch}.exe"
            filename = "cloudflared.exe"
        elif os_type == "linux":
            url = f"https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-{arch}"
            filename = "cloudflared"
        elif os_type == "darwin":
            url = f"https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-{arch}"
            filename = "cloudflared"
        else:
            return False

        print(f"Downloading cloudflared for {os_type}...")
        response = requests.get(url, stream=True)
        with open(filename, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        if os_type in ["linux", "darwin"]:
            os.chmod(filename, 0o755)

        return True
    except Exception as e:
        print(f"Error downloading cloudflared: {e}")
        return False

def start_cloudflared(port):
    """Start cloudflared tunnel and return the URL"""
    try:
        if not check_cloudflared():
            print("Cloudflared not found. Downloading...")
            if not download_cloudflared():
                return None

        # Determine the cloudflared binary name based on OS
        binary = "cloudflared.exe" if platform.system() == "Windows" else "./cloudflared"

        # Start cloudflared process
        process = subprocess.Popen(
            [binary, "tunnel", "--url", f"tcp://localhost:{port}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Wait for the URL to appear in stdout
        url = None
        for _ in range(20):  # Try for 20 seconds
            line = process.stdout.readline()
            if "trycloudflare.com" in line:
                url = line.split("trycloudflare.com")[1].split()[0].strip()
                url = f"https://{url}.trycloudflare.com"
                break
            time.sleep(1)

        return url, process
    except Exception as e:
        print(f"Error starting cloudflared: {e}")
        return None, None

# ---------- SecureChatApp Class ----------
class SecureChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat (AES-GCM + RSA + Cloudflare Tunnel)")
        self.sock = None
        self.conn = None
        self.cloudflared_process = None
        self.is_server = messagebox.askyesno("Role", "Are you the server?")
        self.server_ip = None
        self.server_port = 9999
        self.cloudflared_url = None

        if self.is_server:
            self.setup_server()
        else:
            self.setup_client()

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

    def setup_server(self):
        """Setup server and start cloudflared tunnel"""
        self.server_ip = self.get_local_ip()
        self.append_chat(f"Starting server on {self.server_ip}:{self.server_port}...\n")

        # Start cloudflared tunnel
        self.append_chat("Starting Cloudflare Tunnel...\n")
        self.cloudflared_url, self.cloudflared_process = start_cloudflared(self.server_port)

        if self.cloudflared_url:
            self.append_chat(f"Cloudflare Tunnel URL: {self.cloudflared_url}\n")
            self.append_chat(f"Port: {self.server_port}\n")
            messagebox.showinfo(
                "Server Info",
                f"Share this connection info with your partner:\n\n"
                f"Cloudflare URL: {self.cloudflared_url}\n"
                f"Port: {self.server_port}\n\n"
                "They should enter this in the client setup."
            )
        else:
            self.append_chat("Failed to start Cloudflare Tunnel. Using local IP instead.\n")
            messagebox.showinfo(
                "Server Info",
                f"Share this connection info with your partner:\n\n"
                f"Server IP: {self.server_ip}\n"
                f"Port: {self.server_port}\n\n"
                "They should enter this in the client setup."
            )

        # Start server socket
        threading.Thread(target=self.start_server, daemon=True).start()

    def setup_client(self):
        """Setup client with connection details"""
        self.server_ip = simpledialog.askstring(
            "Server Info",
            "Enter server address (e.g., backed-pastor-ste-combined.trycloudflare.com or IP):"
        )
        if not self.server_ip:
            messagebox.showerror("Error", "Server address required!")
            sys.exit(1)

        self.server_port = simpledialog.askinteger(
            "Server Port",
            "Enter server port (e.g., 9999):",
            minvalue=1,
            maxvalue=65535
        )
        if not self.server_port:
            self.server_port = 9999

        threading.Thread(target=self.connect_to_server, daemon=True).start()

    def get_local_ip(self):
        """Get the local IP address"""
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
            self.establish_aes_key_server()
            threading.Thread(target=self.receive_messages, daemon=True).start()
        except Exception as e:
            self.append_chat(f"Server error: {e}\n{traceback.format_exc()}\n")

    def exchange_public_keys_server(self):
        """Exchange public keys with client (server side)"""
        try:
            # Send our public key
            pub_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            send_data(self.conn, pub_pem)

            # Receive client's public key
            other_pem = recv_data(self.conn)
            self.other_public_key = serialization.load_pem_public_key(other_pem)
            self.append_chat("Public keys exchanged successfully.\n")
        except Exception as e:
            self.append_chat(f"Key exchange error: {e}\n")

    def establish_aes_key_server(self):
        """Establish AES key with client (server side)"""
        try:
            self.aes_key = AESGCM.generate_key(bit_length=256)
            encrypted_aes = self.other_public_key.encrypt(
                self.aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            send_data(self.conn, encrypted_aes)
            self.aesgcm = AESGCM(self.aes_key)
            self.append_chat("AES key securely sent to client.\n")
        except Exception as e:
            self.append_chat(f"AES key establishment error: {e}\n")

    # Client methods
    def connect_to_server(self):
        try:
            self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.append_chat(f"Connecting to {self.server_ip}:{self.server_port}...\n")
            self.conn.connect((self.server_ip, self.server_port))
            self.append_chat(f"Connected to server\n")

            # Exchange public keys
            self.exchange_public_keys_client()
            self.establish_aes_key_client()
            threading.Thread(target=self.receive_messages, daemon=True).start()
        except Exception as e:
            self.append_chat(f"Client error: {e}\n{traceback.format_exc()}\n")

    def exchange_public_keys_client(self):
        """Exchange public keys with server (client side)"""
        try:
            # Receive server's public key
            other_pem = recv_data(self.conn)
            self.other_public_key = serialization.load_pem_public_key(other_pem)

            # Send our public key
            pub_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            send_data(self.conn, pub_pem)
            self.append_chat("Public keys exchanged successfully.\n")
        except Exception as e:
            self.append_chat(f"Key exchange error: {e}\n")

    def establish_aes_key_client(self):
        """Establish AES key with server (client side)"""
        try:
            encrypted_aes = recv_data(self.conn)
            self.aes_key = self.private_key.decrypt(
                encrypted_aes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.aesgcm = AESGCM(self.aes_key)
            self.append_chat("AES key received from server.\n")
        except Exception as e:
            self.append_chat(f"AES key establishment error: {e}\n")

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

    def cleanup(self):
        """Clean up resources when closing"""
        if self.sock:
            self.sock.close()
        if self.conn:
            self.conn.close()
        if self.cloudflared_process:
            self.cloudflared_process.terminate()
        self.root.quit()

# Run
if __name__ == "__main__":
    # Check for requests module
    try:
        import requests
    except ImportError:
        print("Installing required modules...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])

    root = tk.Tk()
    app = SecureChatApp(root)
    root.protocol("WM_DELETE_WINDOW", app.cleanup)
    root.mainloop()
