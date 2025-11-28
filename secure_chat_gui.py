import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# --- GUI Setup ---
root = tk.Tk()
root.title("Secure Chat")

# Chat display
chat_display = scrolledtext.ScrolledText(root, width=50, height=20)
chat_display.grid(row=0, column=0, columnspan=2, padx=10, pady=10)

# Message entry
message_entry = tk.Entry(root, width=50)
message_entry.grid(row=1, column=0, padx=10, pady=10)

# Send button
def send_message():
    msg = message_entry.get()
    if msg:
        send_encrypted_message(msg)
        message_entry.delete(0, tk.END)

send_button = tk.Button(root, text="Send", command=send_message)
send_button.grid(row=1, column=1, padx=10, pady=10)

# --- Networking and Encryption ---
is_server = messagebox.askyesno("Role", "Are you the server (receiver)?")
server_ip = "192.168.1.100"  # Replace with the server's actual IP
port = 9999

# Generate RSA keys if they don't exist
if not os.path.exists("private_key.pem"):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

# Load keys
with open("private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(), password=None, backend=default_backend()
    )
with open("public_key.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(
        f.read(), backend=default_backend()
    )

# Exchange public keys (manually copy to the other system)
other_public_key = None
while not other_public_key:
    try:
        with open("other_public_key.pem", "rb") as f:
            other_public_key = serialization.load_pem_public_key(
                f.read(), backend=default_backend()
            )
    except FileNotFoundError:
        messagebox.showwarning("Warning", "Copy the other user's public_key.pem to this folder and rename it to other_public_key.pem")
        if not messagebox.askyesno("Retry", "Do you want to retry?"):
            exit()

# Generate AES key
aes_key = os.urandom(32)

# --- Socket Setup ---
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
conn = None

def start_server():
    global conn
    sock.bind((server_ip, port))
    sock.listen(1)
    chat_display.insert(tk.END, f"Server is listening on {server_ip}:{port}\n")
    conn, addr = sock.accept()
    chat_display.insert(tk.END, f"Connected to {addr}\n")
    # Send encrypted AES key
    encrypted_aes_key = other_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    conn.send(encrypted_aes_key)

def connect_to_server():
    global conn
    sock.connect((server_ip, port))
    # Receive encrypted AES key
    encrypted_aes_key = sock.recv(1024)
    global aes_key
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    conn = sock
    chat_display.insert(tk.END, f"Connected to server\n")

# --- Messaging ---
def send_encrypted_message(msg):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(msg.encode()) + encryptor.finalize()
    conn.send(iv + ciphertext)
    chat_display.insert(tk.END, f"You: {msg}\n")

def receive_messages():
    while True:
        try:
            encrypted_msg = conn.recv(1024)
            iv = encrypted_msg[:16]
            ciphertext = encrypted_msg[16:]
            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_msg = decryptor.update(ciphertext) + decryptor.finalize()
            chat_display.insert(tk.END, f"Other: {decrypted_msg.decode()}\n")
        except:
            break

# --- Start Server or Connect to Server ---
if is_server:
    threading.Thread(target=start_server, daemon=True).start()
else:
    threading.Thread(target=connect_to_server, daemon=True).start()

# Wait for connection to be established
while conn is None:
    root.update()

# Start receiving messages
threading.Thread(target=receive_messages, daemon=True).start()

root.mainloop()
