import json
import re
import os
import tkinter as tk
from tkinter import messagebox

# Encryption and Decryption Ciphers
class Ciphers:
    @staticmethod
    def atbash_cipher(text):
        alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        reversed_alphabet = alphabet[::-1]
        return ''.join(reversed_alphabet[alphabet.index(c)] if c in alphabet else c for c in text.upper())

    @staticmethod
    def caesar_cipher(text, shift, mode='encrypt'):
        result = ''
        shift = shift % 26
        if mode == 'decrypt':
            shift = -shift
        for char in text:
            if char.isalpha():
                shift_base = ord('A') if char.isupper() else ord('a')
                result += chr((ord(char) - shift_base + shift) % 26 + shift_base)
            else:
                result += char
        return result

    @staticmethod
    def vigenere_cipher(text, key, mode='encrypt'):
        key = key.upper()
        result = []
        key_index = 0
        for char in text:
            if char.isalpha():
                shift = ord(key[key_index]) - ord('A')
                shift_base = ord('A') if char.isupper() else ord('a')
                if mode == 'decrypt':
                    shift = -shift
                result.append(chr((ord(char) - shift_base + shift) % 26 + shift_base))
                key_index = (key_index + 1) % len(key)
            else:
                result.append(char)
        return ''.join(result)

# User Management System
class UserSystem:
    def __init__(self, file_path='users.json'):
        # Set file path to users.json in the same directory as the script
        self.file_path = os.path.join(os.path.dirname(__file__), file_path)
        self.load_users()

    def load_users(self):
        # Load users from the JSON file
        if os.path.exists(self.file_path):
            with open(self.file_path, 'r') as f:
                try:
                    self.users = json.load(f)
                except json.JSONDecodeError:
                    self.users = {}
        else:
            self.users = {}

    def save_users(self):
        # Create an empty JSON file if it doesn't exist
        if not os.path.exists(self.file_path):
            with open(self.file_path, 'w') as f:
                json.dump({}, f)  # Create an empty JSON object

        with open(self.file_path, 'w') as f:
            json.dump(self.users, f)

    def register(self, username, password):
        # Check if username and password meet the requirements
        if not self.is_valid_username(username):
            return "Username must be at least 6 characters long."
        if not self.is_valid_password(password):
            return "Password must be at least 8 characters long with a combination of letters, numbers, and special characters."
        if username in self.users:
            return "Username already exists."
        
        self.users[username] = {"password": password, "attempts": 0, "blocked": False}
        self.save_users()
        return "Registration successful!"

    def is_valid_username(self, username):
        return len(username) >= 6

    def is_valid_password(self, password):
        return (len(password) >= 8 and 
                re.search(r'[A-Za-z]', password) and 
                re.search(r'\d', password) and 
                re.search(r'[@$!%*#?&]', password))

    def login(self, username, password):
        user = self.users.get(username)
        if not user:
            return "Username not found."
        if user['blocked']:
            return "User is blocked due to multiple failed attempts."

        if user['password'] == password:
            user['attempts'] = 0
            self.save_users()
            return "Login successful!"
        else:
            user['attempts'] += 1
            if user['attempts'] >= 3:
                user['blocked'] = True
            self.save_users()
            return "Incorrect password. You have {} attempts left.".format(3 - user['attempts'])

# GUI Application
class CipherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cipher Application")
        self.user_system = UserSystem()

        # Registration/Login Frame
        self.frame = tk.Frame(root)
        self.frame.pack(padx=20, pady=20)

        self.label = tk.Label(self.frame, text="Welcome! Please Register or Login")
        self.label.grid(row=0, column=0, columnspan=2)

        self.username_label = tk.Label(self.frame, text="Username:")
        self.username_label.grid(row=1, column=0)
        self.username_entry = tk.Entry(self.frame)
        self.username_entry.grid(row=1, column=1)

        self.password_label = tk.Label(self.frame, text="Password:")
        self.password_label.grid(row=2, column=0)
        self.password_entry = tk.Entry(self.frame, show="*")
        self.password_entry.grid(row=2, column=1)

        self.register_button = tk.Button(self.frame, text="Register", command=self.register)
        self.register_button.grid(row=3, column=0)

        self.login_button = tk.Button(self.frame, text="Login", command=self.login)
        self.login_button.grid(row=3, column=1)

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        result = self.user_system.register(username, password)
        messagebox.showinfo("Register", result)

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        result = self.user_system.login(username, password)
        if result == "Login successful!":
            messagebox.showinfo("Login", result)
            self.show_cipher_frame()
        else:
            messagebox.showwarning("Login", result)

    def show_cipher_frame(self):
        self.frame.pack_forget()  # Hide login frame
        cipher_frame = tk.Frame(self.root)
        cipher_frame.pack(padx=20, pady=20)

        cipher_label = tk.Label(cipher_frame, text="Select a Cipher")
        cipher_label.grid(row=0, column=0, columnspan=2)

        # Radio buttons for cipher selection
        self.cipher_type = tk.StringVar(value="atbash")
        tk.Radiobutton(cipher_frame, text="Atbash", variable=self.cipher_type, value="atbash").grid(row=1, column=0)
        tk.Radiobutton(cipher_frame, text="Caesar", variable=self.cipher_type, value="caesar").grid(row=1, column=1)
        tk.Radiobutton(cipher_frame, text="Vigenère", variable=self.cipher_type, value="vigenere").grid(row=1, column=2)

        self.mode_type = tk.StringVar(value="encrypt")
        tk.Radiobutton(cipher_frame, text="Encrypt", variable=self.mode_type, value="encrypt").grid(row=2, column=0)
        tk.Radiobutton(cipher_frame, text="Decrypt", variable=self.mode_type, value="decrypt").grid(row=2, column=1)

        self.input_label = tk.Label(cipher_frame, text="Input Text:")
        self.input_label.grid(row=3, column=0)
        self.input_entry = tk.Entry(cipher_frame)
        self.input_entry.grid(row=3, column=1)

        self.shift_label = tk.Label(cipher_frame, text="Shift (for Caesar):")
        self.shift_label.grid(row=4, column=0)
        self.shift_entry = tk.Entry(cipher_frame)
        self.shift_entry.grid(row=4, column=1)

        self.key_label = tk.Label(cipher_frame, text="Key (for Vigenère):")
        self.key_label.grid(row=5, column=0)
        self.key_entry = tk.Entry(cipher_frame)
        self.key_entry.grid(row=5, column=1)

        self.process_button = tk.Button(cipher_frame, text="Process", command=self.use_cipher)
        self.process_button.grid(row=6, column=0)

        self.copy_button = tk.Button(cipher_frame, text="Copy to Clipboard", command=self.copy_to_clipboard)
        self.copy_button.grid(row=6, column=1)

        self.output_text = tk.Text(cipher_frame, height=5, width=50)
        self.output_text.grid(row=7, column=0, columnspan=2)

    def use_cipher(self):
        text = self.input_entry.get()  # Text for encryption/decryption
        cipher = self.cipher_type.get()
        mode = self.mode_type.get()
        result = ""

        if cipher == "atbash":
            result = Ciphers.atbash_cipher(text)
        elif cipher == "caesar":
            try:
                shift = int(self.shift_entry.get())
                result = Ciphers.caesar_cipher(text, shift, mode)
            except ValueError:
                messagebox.showerror("Error", "Shift must be an integer.")
                return
        elif cipher == "vigenere":
            key = self.key_entry.get()
            result = Ciphers.vigenere_cipher(text, key, mode)

        # Display result in the output text area
        self.output_text.delete(1.0, tk.END)  # Clear previous output
        self.output_text.insert(tk.END, result)  # Insert new result

    def copy_to_clipboard(self):
        result = self.output_text.get(1.0, tk.END).strip()
        if result:
            self.root.clipboard_clear()  # Clear clipboard
            self.root.clipboard_append(result)  # Copy result to clipboard
            messagebox.showinfo("Copy to Clipboard", "Result copied to clipboard!")

# Running the application
if __name__ == "__main__":
    root = tk.Tk()
    app = CipherApp(root)
    root.mainloop()
