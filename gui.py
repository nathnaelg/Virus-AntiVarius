from tkinter import *
from tkinter import filedialog
import ttkbootstrap as tb
from PIL import Image, ImageTk
import os
import base64
from cryptography.fernet import Fernet

root = tb.Window(themename="superhero")

root.title("AV")
root.geometry("1540x950")

file_path = ""
upload_type = "file"  # Default upload type is file
encryption_key = None  # Encryption key will be generated

def generate_key():
    return Fernet.generate_key()

def load_key():
    with open("secret.key", "rb") as key_file:
        return key_file.read()

def save_key(key):
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

# Function to set up the key (generate if not exists)
def setup_key():
    global encryption_key
    if not os.path.exists("secret.key"):
        encryption_key = generate_key()
        save_key(encryption_key)
    else:
        encryption_key = load_key()

# Initialize the encryption key
setup_key()
cipher_suite = Fernet(encryption_key)

def file_dialog():
    global file_path
    if upload_type == "file":
        file_path = filedialog.askopenfilename()
    else:
        file_path = filedialog.askdirectory()
    if file_path:
        file_label.config(text="Chosen path: " + file_path)
    else:
        file_label.config(text="No path selected")

def toggle_upload_type():
    global upload_type
    if upload_type == "file":
        upload_type = "directory"
        toggle_button.config(text="Switch to File Upload")
    else:
        upload_type = "file"
        toggle_button.config(text="Switch to Directory Upload")

def encrypt_file(file_path):
    if os.path.isdir(file_path):
        for root_dir, _, files in os.walk(file_path):
            for file in files:
                full_path = os.path.join(root_dir, file)
                try:
                    with open(full_path, 'rb') as f:
                        file_data = f.read()
                    encrypted_data = cipher_suite.encrypt(file_data)
                    with open(full_path, 'wb') as f:
                        f.write(encrypted_data)
                    
                    # Encrypt the file name
                    encrypted_name = base64.urlsafe_b64encode(cipher_suite.encrypt(file.encode())).decode()
                    os.rename(full_path, os.path.join(root_dir, encrypted_name))

                    file_label.config(text=f"File Encrypted successfully.")
                except Exception as e:
                    file_label.config(text=f"Encryption failed: {e}")
    else:
        try:
            with open(file_path, 'rb') as file:
                file_data = file.read()
            encrypted_data = cipher_suite.encrypt(file_data)
            with open(file_path, 'wb') as file:
                file.write(encrypted_data)
            
            # Encrypt the file name
            dir_path, file_name = os.path.split(file_path)
            encrypted_name = base64.urlsafe_b64encode(cipher_suite.encrypt(file_name.encode())).decode()
            os.rename(file_path, os.path.join(dir_path, encrypted_name))
            
            file_label.config(text=f"File Encrypted successfully.")
        except Exception as e:
            file_label.config(text=f"Encryption failed: {e}")

def decrypt_file(file_path):
    if os.path.isdir(file_path):
        for root_dir, _, files in os.walk(file_path):
            for file in files:
                full_path = os.path.join(root_dir, file)
                try:
                    with open(full_path, 'rb') as f:
                        file_data = f.read()
                    decrypted_data = cipher_suite.decrypt(file_data)
                    with open(full_path, 'wb') as f:
                        f.write(decrypted_data)
                    
                    # Decrypt the file name
                    decrypted_name = cipher_suite.decrypt(base64.urlsafe_b64decode(file)).decode()
                    os.rename(full_path, os.path.join(root_dir, decrypted_name))
                    
                    file_label.config(text="File Decrypted successfully.")
                except Exception as e:
                    file_label.config(text="Decryption failed: {e}")
    else:
        try:
            with open(file_path, 'rb') as file:
                file_data = file.read()
            decrypted_data = cipher_suite.decrypt(file_data)
            with open(file_path, 'wb') as file:
                file.write(decrypted_data)
            
            # Decrypt the file name
            dir_path, file_name = os.path.split(file_path)
            decrypted_name = cipher_suite.decrypt(base64.urlsafe_b64decode(file_name)).decode()
            os.rename(file_path, os.path.join(dir_path, decrypted_name))
            
            file_label.config(text="File decrypted successfully.")
        except Exception as e:
            file_label.config(text="Decryption failed: {e}")

# Load your antivirus icon image using Pillow
antivirus_image = Image.open("images/logo.png")
antivirus_image = antivirus_image.resize((300, 300), Image.LANCZOS)
antivirus_icon = ImageTk.PhotoImage(antivirus_image)

# Create a label with the antivirus icon
icon_label = Label(image=antivirus_icon)
icon_label.pack(pady=50)

# Add a toggle button to switch between file and directory upload
toggle_button = tb.Button(text="Switch to Directory Upload", bootstyle="secondary", command=toggle_upload_type)
toggle_button.pack(pady=10)

file_label = tb.Label(text="", font=("Helvetica", 12), bootstyle="default")
file_label.pack(pady=10)

# Load your initial image
image = Image.open("images/upload_file.png")
image = image.resize((300, 260), Image.LANCZOS)  # Decrease size to 100x100 pixels
image = ImageTk.PhotoImage(image)

# Create a label with the image
image_button = tb.Label(image=image)
image_button.pack(pady=10)

# Bind the click event of the image to the file_dialog function
image_button.bind("<Button-1>", lambda event: file_dialog())

# Create a frame to hold the encrypt and decrypt buttons
button_frame = tb.Frame(root)
button_frame.pack(pady=10)

# Button to encrypt file
encrypt_button = tb.Button(button_frame, text="Encrypt", bootstyle="danger", command=lambda: encrypt_file(file_path))
encrypt_button.config(padding=(60, 25))
encrypt_button.pack(side=LEFT, padx=20)

# Button to decrypt file
decrypt_button = tb.Button(button_frame, text="Decrypt", bootstyle="success", command=lambda: decrypt_file(file_path))
decrypt_button.config(padding=(60, 25))
decrypt_button.pack(side=LEFT, padx=20)

root.mainloop()
