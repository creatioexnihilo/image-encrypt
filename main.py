import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import scrolledtext
from PIL import Image, ImageTk
import numpy as np
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# Define a signature to identify if an image was created by this application
APP_SIGNATURE = "APP_SIGNATURE"

class TextImageApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Text to Image Encryption/Decryption")

        # Maximize the window
        self.root.state('zoomed')
        self.root.configure(bg="#f0f0f0")

        # Initialize the GUI elements
        self.create_widgets()

    def create_widgets(self):
        # Title
        title_label = tk.Label(self.root, text="Text to Image Encryption & Decryption", 
                               font=("Helvetica", 18, "bold"), bg="#f0f0f0", pady=10)
        title_label.pack()

        # Text input for encryption
        self.label_input = tk.Label(self.root, text="Enter Text to Encrypt:", bg="#f0f0f0", font=("Arial", 12))
        self.label_input.pack(pady=10)

        # Larger text input with scroll for better usability
        self.text_input = scrolledtext.ScrolledText(self.root, height=15, width=100, font=("Arial", 10))
        self.text_input.pack(pady=10)

        # Button to clear the encryption input text
        self.clear_encrypt_button = tk.Button(self.root, text="Clear Text to Encrypt", command=self.clear_text_to_encrypt,
                                              bg="#FF9800", fg="white", font=("Arial", 12), padx=10, pady=5)
        self.clear_encrypt_button.pack(pady=5)

        # Key input for encryption/decryption
        self.label_key = tk.Label(self.root, text="Enter Encryption/Decryption Key:", bg="#f0f0f0", font=("Arial", 12))
        self.label_key.pack(pady=10)

        # Key input field
        self.key_input = tk.Entry(self.root, show="*", width=50, font=("Arial", 12))
        self.key_input.pack(pady=10)

        # Encrypt button
        self.encrypt_button = tk.Button(self.root, text="Encrypt Text to Image", command=self.encrypt_to_image,
                                        bg="#4CAF50", fg="white", font=("Arial", 12), padx=10, pady=5)
        self.encrypt_button.pack(pady=10)

        # Upload image to decrypt section
        self.label_upload = tk.Label(self.root, text="Upload Image to Decrypt:", bg="#f0f0f0", font=("Arial", 12))
        self.label_upload.pack(pady=10)

        # Upload image button
        self.upload_button = tk.Button(self.root, text="Upload Image", command=self.upload_image,
                                       bg="#2196F3", fg="white", font=("Arial", 12), padx=10, pady=5)
        self.upload_button.pack(pady=10)

        # Image display area (smaller size now)
        self.image_label = tk.Label(self.root, text="Image will be displayed here after upload", width=50, height=10, bg="#ddd")
        self.image_label.pack(pady=10)

        # Display decrypted text section
        self.decrypted_label = tk.Label(self.root, text="Decrypted Text:", bg="#f0f0f0", font=("Arial", 12))
        self.decrypted_label.pack(pady=10)

        # Larger decrypted text display box with scroll
        self.decrypted_text = scrolledtext.ScrolledText(self.root, height=10, width=100, font=("Arial", 10))
        self.decrypted_text.pack(pady=10)

        # Button to clear the decrypted text output
        self.clear_decrypt_button = tk.Button(self.root, text="Clear Decrypted Text", command=self.clear_decrypted_text,
                                              bg="#FF9800", fg="white", font=("Arial", 12), padx=10, pady=5)
        self.clear_decrypt_button.pack(pady=5)

        # Copy to clipboard button for the decrypted text
        self.copy_button = tk.Button(self.root, text="Copy Decrypted Text", command=self.copy_to_clipboard,
                                     bg="#FF9800", fg="white", font=("Arial", 12), padx=10, pady=5)
        self.copy_button.pack(pady=10)

    def encrypt_to_image(self):
        # Get the text from the text box
        input_text = self.text_input.get("1.0", "end-1c")
        key = self.key_input.get()

        if not input_text or not key:
            messagebox.showwarning("Input Error", "Please enter both text and a key to encrypt.")
            return

        try:
            # Encrypt the text using the provided key
            encrypted_text = self.encrypt_text(input_text, key)
        except Exception as e:
            messagebox.showerror("Encryption Error", f"Encryption failed: {e}")
            return

        # Combine the signature and the encrypted text
        full_text = APP_SIGNATURE + encrypted_text
        text_bytes = full_text.encode('utf-8')  # Convert text to bytes
        text_len = len(text_bytes)

        # Calculate the minimum image size needed for the text
        total_pixels_needed = (text_len + 2) // 3

        # Image dimensions (make it square)
        img_size = int(np.ceil(np.sqrt(total_pixels_needed)))

        # Create an empty RGB image
        img_array = np.zeros((img_size, img_size, 3), dtype=np.uint8)

        # Fill the image with the text bytes (spread across the RGB channels)
        for i in range(text_len):
            row = i // (img_size * 3)
            col = (i // 3) % img_size
            channel = i % 3
            img_array[row, col, channel] = text_bytes[i]

        # Convert the NumPy array to an image
        img = Image.fromarray(img_array)

        # Prompt the user for the save location and filename
        file_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])

        if not file_path:
            return  # If the user cancels the save dialog, just return

        # Save the image
        img.save(file_path)

        messagebox.showinfo("Success", f"Text has been encrypted into image: {file_path}")

    def upload_image(self):
        # Open file dialog to select an image
        file_path = filedialog.askopenfilename(filetypes=[("PNG Images", "*.png")])
        key = self.key_input.get()

        if not file_path or not key:
            messagebox.showwarning("Input Error", "Please upload an image and enter the key.")
            return

        try:
            # Open the image
            img = Image.open(file_path).convert("RGB")
            img_array = np.array(img)

            # Extract the text bytes from the image pixels
            text_bytes = []
            for row in img_array:
                for pixel in row:
                    text_bytes.extend(pixel[:3])  # Extract the RGB values as text bytes

            # Convert the bytes back to text
            full_text = bytes(text_bytes).decode('utf-8', errors='ignore')

            # Check if the image was created by the application
            if not full_text.startswith(APP_SIGNATURE):
                messagebox.showerror("Error", "This image was not created by this application!")
                return

            # Remove the signature and get the encrypted text
            encrypted_text = full_text[len(APP_SIGNATURE):]

            try:
                # Decrypt the text using the provided key
                decrypted_text = self.decrypt_text(encrypted_text, key)
            except Exception as e:
                messagebox.showerror("Decryption Error", f"Decryption failed: {e}")
                return

            # Display the image in the GUI without resizing
            img_display = ImageTk.PhotoImage(img)
            self.image_label.configure(image=img_display)
            self.image_label.image = img_display

            # Display the decrypted text
            self.decrypted_text.delete("1.0", tk.END)
            self.decrypted_text.insert(tk.END, decrypted_text)

        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt image: {e}")

    def copy_to_clipboard(self):
        # Copy the decrypted text to the clipboard
        decrypted_text = self.decrypted_text.get("1.0", tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(decrypted_text)
        self.root.update()  # Ensure the clipboard gets updated
        messagebox.showinfo("Success", "Decrypted text copied to clipboard!")

    def encrypt_text(self, plaintext, key):
        # Pad the plaintext to match AES block size
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()

        # Generate a random IV (initialization vector)
        iv = os.urandom(16)

        # Create an AES cipher in CBC mode with the key and IV
        cipher = Cipher(algorithms.AES(self._format_key(key)), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Encrypt the padded data
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # Combine IV and ciphertext, and encode in base64
        combined = iv + ciphertext
        return base64.b64encode(combined).decode('utf-8')

    def decrypt_text(self, encrypted_base64, key):
        # Decode the base64-encoded data
        encrypted_data = base64.b64decode(encrypted_base64)

        # Extract the IV and ciphertext
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        # Create an AES cipher in CBC mode with the key and IV
        cipher = Cipher(algorithms.AES(self._format_key(key)), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the ciphertext
        decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Unpad the decrypted data
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

        return decrypted_data.decode('utf-8')

    def _format_key(self, key):
        # Ensure the key is 32 bytes (AES-256), pad with zeros if necessary
        return key.ljust(32)[:32].encode('utf-8')

    def clear_text_to_encrypt(self):
        """Clears the text input for encryption."""
        self.text_input.delete("1.0", tk.END)

    def clear_decrypted_text(self):
        """Clears the decrypted text output."""
        self.decrypted_text.delete("1.0", tk.END)

# Main function to start the app
if __name__ == "__main__":
    root = tk.Tk()
    app = TextImageApp(root)
    root.mainloop()
