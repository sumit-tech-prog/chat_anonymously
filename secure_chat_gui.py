import tkinter as tk
from tkinter import messagebox, ttk, filedialog
from cryptography.fernet import Fernet, InvalidToken
import os
import pyperclip
import sys
import ctypes
import base64

# ---------------------------
# Secure Messaging Tool (Updated GUI)
# Features added:
# - Modern/futuristic styling
# - Non-blocking auto-dismissing toast (2 seconds) when copying encrypted text
# - Improved layout and UX
# - Minimal external dependency requirements: cryptography, pyperclip
# ---------------------------

# Hide terminal window (Windows)
if sys.platform == "win32":
    try:
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    except Exception:
        pass


class SecureMessagingTool:
    def __init__(self, key_file="encryption_key.txt"):
        self.key_file = key_file
        try:
            if not os.path.exists(self.key_file):
                self.key = Fernet.generate_key()
                with open(self.key_file, "wb") as f:
                    f.write(self.key)
                # show a one-time info (blocking) to inform user to share key
                messagebox.showinfo("Info", f"New key generated! Share {self.key_file} with your friend!")
            else:
                with open(self.key_file, "rb") as f:
                    self.key = f.read()
            # Validate key format
            if not isinstance(self.key, (bytes, bytearray)):
                self.key = self.key.encode()
            self.cipher_suite = Fernet(self.key)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load key: {e}")
            sys.exit(1)

    def encrypt_message(self, message: str) -> str:
        encrypted_message = self.cipher_suite.encrypt(message.encode())
        return encrypted_message.decode()

    def decrypt_message(self, encrypted_message: str) -> str:
        try:
            decrypted_message = self.cipher_suite.decrypt(encrypted_message.encode())
            return decrypted_message.decode()
        except InvalidToken:
            raise ValueError("Invalid encrypted message or wrong key!")

    def encrypt_file(self, input_file_path: str, output_file_path: str):
        with open(input_file_path, "rb") as f:
            file_data = f.read()
        encrypted_data = self.cipher_suite.encrypt(file_data)
        with open(output_file_path, "wb") as f:
            f.write(encrypted_data)

    def decrypt_file(self, input_file_path: str, output_file_path: str):
        with open(input_file_path, "rb") as f:
            encrypted_data = f.read()
        decrypted_data = self.cipher_suite.decrypt(encrypted_data)
        with open(output_file_path, "wb") as f:
            f.write(decrypted_data)


# ---------------------------
# Helper: Toast popup (auto-destroy)
# ---------------------------

def show_toast(root, message: str, duration=2000):
    """Creates a frameless toast-like Toplevel that auto-destroys after duration (ms)."""
    # Position toast centered above root window
    toast = tk.Toplevel(root)
    toast.overrideredirect(True)  # remove window decorations
    toast.attributes("-topmost", True)
    # Slight transparency for futuristic look
    try:
        toast.attributes("-alpha", 0.95)
    except Exception:
        pass

    # Styling
    frame = tk.Frame(toast, bg="#111827", bd=1, relief=tk.RIDGE)
    frame.pack(fill=tk.BOTH, expand=True)

    label = tk.Label(frame, text=message, font=("Helvetica", 10, "bold"), bg="#111827", fg="#a5b4fc", padx=12, pady=8)
    label.pack()

    # Place calculation
    root.update_idletasks()
    rx = root.winfo_rootx()
    ry = root.winfo_rooty()
    rw = root.winfo_width()
    rh = root.winfo_height()
    tw = toast.winfo_reqwidth()
    th = toast.winfo_reqheight()

    x = rx + (rw - tw) // 2
    y = ry + int(rh * 0.08)  # near top of app
    toast.geometry(f"+{x}+{y}")

    # destroy after duration (ms)
    toast.after(duration, toast.destroy)


# ---------------------------
# GUI Windows
# ---------------------------

class EncryptionWindow:
    def __init__(self, parent, secure_messaging_tool, root):
        self.parent = parent
        self.secure_messaging_tool = secure_messaging_tool
        self.root = root

        self.build_ui()

    def build_ui(self):
        self.parent.configure(bg="#0b1220")

        title = tk.Label(self.parent, text="Secure Messaging — Encryption", font=("Segoe UI", 16, "bold"), bg="#0b1220", fg="#e6f0ff")
        title.pack(pady=(14, 6))

        container = tk.Frame(self.parent, bg="#0b1220")
        container.pack(fill=tk.BOTH, expand=True, padx=16, pady=8)

        # Message entry area (multi-line)
        left = tk.Frame(container, bg="#0b1220")
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))

        msg_label = tk.Label(left, text="Enter message:", bg="#0b1220", fg="#dbeafe", font=("Segoe UI", 11, "bold"))
        msg_label.pack(anchor="w")

        self.message_text = tk.Text(left, height=8, bg="#081129", fg="#e6f0ff", insertbackground="#e6f0ff", wrap=tk.WORD, relief=tk.FLAT)
        self.message_text.pack(fill=tk.BOTH, expand=True, pady=(6, 8))

        btn_frame = tk.Frame(left, bg="#0b1220")
        btn_frame.pack(fill=tk.X)

        encrypt_btn = tk.Button(btn_frame, text="Encrypt", bg="#2563eb", fg="white", font=("Segoe UI", 10, "bold"), command=self.encrypt_message, bd=0, padx=12, pady=6)
        encrypt_btn.pack(side=tk.LEFT, padx=(0, 8))

        copy_btn = tk.Button(btn_frame, text="Copy Encrypted", bg="#10b981", fg="white", font=("Segoe UI", 10, "bold"), command=self.copy_code, bd=0, padx=12, pady=6)
        copy_btn.pack(side=tk.LEFT, padx=(0, 8))

        save_btn = tk.Button(btn_frame, text="Save .enc", bg="#ef4444", fg="white", font=("Segoe UI", 10, "bold"), command=self.save_encrypted_message, bd=0, padx=12, pady=6)
        save_btn.pack(side=tk.LEFT)

        # Right side: Encrypted output & file ops
        right = tk.Frame(container, bg="#071027")
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        enc_label = tk.Label(right, text="Encrypted output:", bg="#071027", fg="#dbeafe", font=("Segoe UI", 11, "bold"))
        enc_label.pack(anchor="w")

        self.encrypted_text = tk.Text(right, height=14, bg="#020617", fg="#c7d2fe", insertbackground="#c7d2fe", wrap=tk.WORD, relief=tk.FLAT)
        self.encrypted_text.pack(fill=tk.BOTH, expand=True, pady=(6, 8))

        file_label = tk.Label(right, text="File operations:", bg="#071027", fg="#dbeafe", font=("Segoe UI", 11, "bold"))
        file_label.pack(anchor="w", pady=(6, 4))

        file_frame = tk.Frame(right, bg="#071027")
        file_frame.pack(fill=tk.X)

        sel_file_btn = tk.Button(file_frame, text="Select File to Encrypt", bg="#7c3aed", fg="white", font=("Segoe UI", 10, "bold"), command=self.select_file_to_encrypt, bd=0, padx=10, pady=6)
        sel_file_btn.pack(side=tk.LEFT)

        self.status_var = tk.StringVar(value="Ready")
        status = tk.Label(self.parent, textvariable=self.status_var, bg="#0b1220", fg="#9ca3af", anchor="w")
        status.pack(fill=tk.X, side=tk.BOTTOM)

    def encrypt_message(self):
        message = self.message_text.get("1.0", tk.END).strip()
        if not message:
            messagebox.showerror("Error", "Message cannot be empty!")
            return
        try:
            encrypted_message = self.secure_messaging_tool.encrypt_message(message)
            self.encrypted_text.delete("1.0", tk.END)
            self.encrypted_text.insert(tk.END, encrypted_message)
            self.status_var.set("Text encrypted")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to encrypt: {e}")

    def copy_code(self):
        encrypted_message = self.encrypted_text.get("1.0", tk.END).strip()
        if not encrypted_message:
            messagebox.showerror("Error", "No message to copy!")
            return
        try:
            pyperclip.copy(encrypted_message)
            # Non-blocking toast (2 seconds)
            show_toast(self.root, "Encrypted message copied to clipboard", duration=2000)
            self.status_var.set("Copied to clipboard")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy: {e}")

    def save_encrypted_message(self):
        encrypted_message = self.encrypted_text.get("1.0", tk.END).strip()
        if not encrypted_message:
            messagebox.showerror("Error", "No encrypted message to save!")
            return
        output_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted Files", "*.enc"), ("Text Files", "*.txt")])
        if output_path:
            try:
                with open(output_path, "w") as f:
                    f.write(encrypted_message)
                self.status_var.set(f"Saved: {os.path.basename(output_path)}")
                show_toast(self.root, "Encrypted file saved", duration=2000)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save: {e}")

    def select_file_to_encrypt(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            output_path = filedialog.asksaveasfilename(defaultextension=".enc")
            if output_path:
                try:
                    self.secure_messaging_tool.encrypt_file(file_path, output_path)
                    message = f"File encrypted: {os.path.basename(output_path)}"
                    self.status_var.set(message)
                    show_toast(self.root, "File encrypted successfully", duration=2000)
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to encrypt file: {e}")


class DecryptionWindow:
    def __init__(self, parent, secure_messaging_tool, root):
        self.parent = parent
        self.secure_messaging_tool = secure_messaging_tool
        self.root = root
        self.build_ui()

    def build_ui(self):
        self.parent.configure(bg="#071027")

        title = tk.Label(self.parent, text="Secure Messaging — Decryption", font=("Segoe UI", 16, "bold"), bg="#071027", fg="#e6f0ff")
        title.pack(pady=(14, 6))

        container = tk.Frame(self.parent, bg="#071027")
        container.pack(fill=tk.BOTH, expand=True, padx=16, pady=8)

        enc_label = tk.Label(container, text="Paste encrypted text:", bg="#071027", fg="#dbeafe", font=("Segoe UI", 11, "bold"))
        enc_label.pack(anchor="w")

        self.encrypted_text = tk.Text(container, height=8, bg="#020617", fg="#c7d2fe", insertbackground="#c7d2fe", wrap=tk.WORD, relief=tk.FLAT)
        self.encrypted_text.pack(fill=tk.BOTH, expand=True, pady=(6, 8))

        btn_frame = tk.Frame(container, bg="#071027")
        btn_frame.pack(fill=tk.X)

        decrypt_btn = tk.Button(btn_frame, text="Decrypt", bg="#2563eb", fg="white", font=("Segoe UI", 10, "bold"), command=self.decrypt_message, bd=0, padx=12, pady=6)
        decrypt_btn.pack(side=tk.LEFT, padx=(0, 8))

        load_btn = tk.Button(btn_frame, text="Load .enc", bg="#ef4444", fg="white", font=("Segoe UI", 10, "bold"), command=self.load_encrypted_message, bd=0, padx=12, pady=6)
        load_btn.pack(side=tk.LEFT)

        out_label = tk.Label(container, text="Decrypted output:", bg="#071027", fg="#dbeafe", font=("Segoe UI", 11, "bold"))
        out_label.pack(anchor="w", pady=(12, 0))

        self.decrypted_text = tk.Text(container, height=8, bg="#081129", fg="#e6f0ff", insertbackground="#e6f0ff", wrap=tk.WORD, relief=tk.FLAT)
        self.decrypted_text.pack(fill=tk.BOTH, expand=True, pady=(6, 8))

    def decrypt_message(self):
        encrypted_message = self.encrypted_text.get("1.0", tk.END).strip()
        if not encrypted_message:
            messagebox.showerror("Error", "Encrypted message cannot be empty!")
            return
        try:
            decrypted_message = self.secure_messaging_tool.decrypt_message(encrypted_message)
            self.decrypted_text.delete("1.0", tk.END)
            self.decrypted_text.insert(tk.END, decrypted_message)
            show_toast(self.root, "Decryption successful", duration=2000)
        except ValueError as e:
            messagebox.showerror("Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt: {e}")

    def load_encrypted_message(self):
        file_path = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.enc"), ("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "r") as f:
                encrypted_message = f.read()
            self.encrypted_text.delete("1.0", tk.END)
            self.encrypted_text.insert(tk.END, encrypted_message)
            show_toast(self.root, "Loaded encrypted file", duration=1600)

    def select_file_to_decrypt(self):
        file_path = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.enc")])
        if file_path:
            output_path = filedialog.asksaveasfilename()
            if output_path:
                try:
                    self.secure_messaging_tool.decrypt_file(file_path, output_path)
                    show_toast(self.root, "File decrypted", duration=2000)
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to decrypt file: {e}")


# ---------------------------
# Banner (console) - kept for fun
# ---------------------------

def show_banner():
    banner = """
                ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗██████╗
                ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗
                ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  ██║  ██║
                ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  ██║  ██║
                ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗██████╔╝
                ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═════╝

                            ████████╗ ██████╗  ██████╗ ██╗
                            ╚══██╔══╝██╔═══██╗██╔═══██╗██║
                               ██║   ██║   ██║██║   ██║██║
                               ██║   ██║   ██║██║   ██║██║
                               ██║   ╚██████╔╝╚██████╔╝███████╗
                               ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
    """
    print(banner)


# ---------------------------
# Main
# ---------------------------
if __name__ == "__main__":
    show_banner()
    secure_messaging_tool = SecureMessagingTool()

    root = tk.Tk()
    root.title("Secure Messaging Tool - Professional Edition")
    root.geometry("1000x700")
    root.configure(bg="#081129")
    # Slight transparency to feel modern
    try:
        root.attributes("-alpha", 0.98)
    except Exception:
        pass

    # Notebook
    style = ttk.Style()
    # Use default theme but tweak colors
    style.theme_use("clam")
    style.configure("TNotebook", background="#081129", borderwidth=0)
    style.configure("TNotebook.Tab", background="#0b1220", foreground="#c7d2fe", padding=(12, 8))

    tab_control = ttk.Notebook(root)
    tab_control.pack(expand=1, fill="both", padx=12, pady=12)

    encryption_tab = tk.Frame(tab_control, bg="#0b1220")
    decryption_tab = tk.Frame(tab_control, bg="#071027")

    tab_control.add(encryption_tab, text="Encryption")
    tab_control.add(decryption_tab, text="Decryption")

    encryption_window = EncryptionWindow(encryption_tab, secure_messaging_tool, root)
    decryption_window = DecryptionWindow(decryption_tab, secure_messaging_tool, root)

    root.mainloop()
