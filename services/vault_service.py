import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from password and salt using PBKDF2 with SHA-256."""
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)

def encrypt_file_data(data: bytes, password: str) -> tuple[bytes, bytes, bytes]:
    """Encrypt original bytes using AES-256-CBC, returning (encrypted_data, salt, iv)."""
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(password, salt)
    
    # Pad plaintext data to AES block size (16 bytes)
    pad_len = 16 - (len(data) % 16)
    padded_data = data + bytes([pad_len] * pad_len)
    
    # Encrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    return encrypted_data, salt, iv

def decrypt_file_data(encrypted_data: bytes, password: str, salt: bytes, iv: bytes) -> bytes:
    """Decrypt cipher text using AES-256-CBC, checking padding bytes validity."""
    key = derive_key(password, salt)
    
    # Decrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # Unpad and validate
    if not padded_data:
        raise ValueError("Decrypted content is empty or invalid.")
        
    pad_len = padded_data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding length.")
        
    for b in padded_data[-pad_len:]:
        if b != pad_len:
            raise ValueError("Invalid padding bytes.")
            
    return padded_data[:-pad_len]

def calculate_sha256(data: bytes) -> str:
    """Calculate the SHA-256 hash of raw data."""
    return hashlib.sha256(data).hexdigest()
