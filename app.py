from flask import Flask, render_template, request, send_file, redirect, url_for
from PIL import Image
import numpy as np
import os
import base64
from io import BytesIO
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = './static/images'
APP_SIGNATURE = "APP_SIGNATURE"

# Helper function to format the key
def _format_key(key):
    return key.ljust(32)[:32].encode('utf-8')

# Function to encrypt text
def encrypt_text(plaintext, key):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(_format_key(key)), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    combined = iv + ciphertext
    return base64.b64encode(combined).decode('utf-8')

# Function to decrypt text
def decrypt_text(encrypted_base64, key):
    encrypted_data = base64.b64decode(encrypted_base64)
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(_format_key(key)), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return decrypted_data.decode('utf-8')

# Home route
@app.route('/')
def index():
    return render_template('index.html')

# Route to handle encryption
@app.route('/encrypt', methods=['POST'])
def encrypt():
    text_to_encrypt = request.form['text']
    key = request.form['key']

    if not text_to_encrypt or not key:
        return render_template('index.html', error="Please provide both text and a key.")

    try:
        encrypted_text = encrypt_text(text_to_encrypt, key)
    except Exception as e:
        return render_template('index.html', error=f"Encryption failed: {e}")

    full_text = APP_SIGNATURE + encrypted_text
    text_bytes = full_text.encode('utf-8')
    text_len = len(text_bytes)

    # Calculate minimum image size
    total_pixels_needed = (text_len + 2) // 3
    img_size = int(np.ceil(np.sqrt(total_pixels_needed)))

    # Create image
    img_array = np.zeros((img_size, img_size, 3), dtype=np.uint8)
    for i in range(text_len):
        row = i // (img_size * 3)
        col = (i // 3) % img_size
        channel = i % 3
        img_array[row, col, channel] = text_bytes[i]

    img = Image.fromarray(img_array)

    # Save the image
    img_io = BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)

    return send_file(img_io, mimetype='image/png', as_attachment=True, download_name='encrypted_image.png')

# Route to handle decryption
@app.route('/decrypt', methods=['POST'])
def decrypt():
    key = request.form['key']
    image_file = request.files['image']

    if not key or not image_file:
        return render_template('index.html', error="Please provide both an image and a key.")

    try:
        img = Image.open(image_file).convert('RGB')
        img_array = np.array(img)

        text_bytes = []
        for row in img_array:
            for pixel in row:
                text_bytes.extend(pixel[:3])

        full_text = bytes(text_bytes).decode('utf-8', errors='ignore')

        if not full_text.startswith(APP_SIGNATURE):
            return render_template('index.html', error="This image was not created by this application!")

        encrypted_text = full_text[len(APP_SIGNATURE):]

        try:
            decrypted_text = decrypt_text(encrypted_text, key)
        except Exception as e:
            return render_template('index.html', error=f"Decryption failed: {e}")

        return render_template('index.html', decrypted_text=decrypted_text)

    except Exception as e:
        return render_template('index.html', error=f"Failed to decrypt image: {e}")

if __name__ == '__main__':
    app.run()
