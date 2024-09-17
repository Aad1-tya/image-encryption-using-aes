from flask import Flask, render_template, request, send_file
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os

app = Flask(__name__)

# Function to encrypt the image
def encrypt_image(image_data, key):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(image_data, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return iv + encrypted_data

# Function to decrypt the image
def decrypt_image(encrypted_data, key):
    iv = encrypted_data[:AES.block_size]
    encrypted_image_data = encrypted_data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_image_data), AES.block_size)
    return decrypted_data

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    if 'image' not in request.files:
        return "No file uploaded", 400

    image_file = request.files['image']
    if image_file.filename == '':
        return "No selected file", 400

    key = get_random_bytes(16)  # Generate a random AES key

    # Read the image data
    image_data = image_file.read()

    # Encrypt the image
    encrypted_data = encrypt_image(image_data, key)

    # Save encrypted image to disk
    encrypted_image_path = os.path.join('uploads', 'encrypted_image.enc')
    with open(encrypted_image_path, 'wb') as f:
        f.write(encrypted_data)

    # Ensure the full path is used for downloading
    full_encrypted_image_path = os.path.abspath(encrypted_image_path)

    # Return the encryption key (in hex) and provide the download link
    return render_template('key_display.html', key=key.hex(), encrypted_image_path=full_encrypted_image_path)

@app.route('/download/<path:filename>', methods=['GET'])
def download_file(filename):
    try:
        # Use send_file to serve the file for download
        return send_file(filename, as_attachment=True)
    except Exception as e:
        return str(e), 404

@app.route('/decrypt', methods=['POST'])
def decrypt():
    if 'encrypted_file' not in request.files or 'key' not in request.form:
        return "Missing file or key", 400

    encrypted_file = request.files['encrypted_file']
    key = bytes.fromhex(request.form['key'])

    # Read the encrypted image data
    encrypted_data = encrypted_file.read()

    # Decrypt the image
    decrypted_data = decrypt_image(encrypted_data, key)

    # Save decrypted image to disk
    decrypted_image_path = os.path.join('uploads', 'decrypted_image.jpg')
    with open(decrypted_image_path, 'wb') as f:
        f.write(decrypted_data)

    # Return the decrypted image to download
    return send_file(decrypted_image_path, as_attachment=True)

if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    app.run(debug=True)
