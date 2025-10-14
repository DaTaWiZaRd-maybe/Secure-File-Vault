import os
from cryptography.hazmat.primitives.kdf.pdkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ___KEY_DERIVATION_ITERATIONS___
def derive_key(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    """Derives a secure key from a password using PBKDF2HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password)


# ___ENCRYPTION___
def encrypt_file(data: bytes, key: str) -> bytes:
    """Encrypts plaintext using AES-GCM with a key derived from the password."""
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    encrypted = aesgcm.encrypt(nonce, data, None)
    return nonce + encrypted


# ___DECRYPTION___
def decrypt_file(encrypted_data: bytes, key: str) -> bytes:
    """Decrypts ciphertext using AES-GCM with a key derived from the password."""
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)
