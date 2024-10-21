from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
import os

def encrypt_text(plain_text, key, iv):
    # Apply PKCS7 padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plain_text.encode()) + padder.finalize()

    # Create AES cipher in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Return HEX and Base64 encoded versions
    hex_encrypted = encrypted_data.hex()
    base64_encrypted = b64encode(encrypted_data).decode()
    return hex_encrypted, base64_encrypted

def decrypt_text(encrypted_data, key, iv, input_format='hex'):
    # Convert the encrypted data from the specified format
    if input_format == 'hex':
        encrypted_data = bytes.fromhex(encrypted_data)
    elif input_format == 'base64':
        encrypted_data = b64decode(encrypted_data)
    else:
        raise ValueError("Invalid input format. Use 'hex' or 'base64'.")

    # Create AES cipher in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove PKCS7 padding
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return decrypted_data.decode()

# Example usage
if __name__ == "__main__":
    # Original text
    original_text = "Welcome to Lagos"

    # Generate a random 256-bit key and a 16-byte IV
    key = os.urandom(32)  # 256-bit key
    iv = os.urandom(16)   # 16-byte IV for AES

    # Encrypt the text
    hex_encrypted, base64_encrypted = encrypt_text(original_text, key, iv)
    print(f"Original Text: {original_text}")
    print(f"Encrypted (HEX): {hex_encrypted}")
    print(f"Encrypted (Base64): {base64_encrypted}")

    # Decrypt the text from HEX format
    decrypted_hex = decrypt_text(hex_encrypted, key, iv, input_format='hex')
    print(f"Decrypted from HEX: {decrypted_hex}")

    # Decrypt the text from Base64 format
    decrypted_base64 = decrypt_text(base64_encrypted, key, iv, input_format='base64')
    print(f"Decrypted from Base64: {decrypted_base64}")

