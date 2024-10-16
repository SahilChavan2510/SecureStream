# cryptography_utils.py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

# AES Encryption and Decryption
def encrypt_aes(message: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) not in {16, 24, 32}:
        raise ValueError("Invalid key length: must be 16, 24, or 32 bytes")
    if len(iv) != 16:
        raise ValueError("Invalid IV length: must be 16 bytes")
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message) + padder.finalize()
    
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    return base64.b64encode(encrypted_message)

def decrypt_aes(encrypted_message: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) not in {16, 24, 32}:
        raise ValueError("Invalid key length: must be 16, 24, or 32 bytes")
    if len(iv) != 16:
        raise ValueError("Invalid IV length: must be 16 bytes")
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_padded_message = decryptor.update(base64.b64decode(encrypted_message)) + decryptor.finalize()
    
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()
    return decrypted_message

# RSA Key Generation, Encryption, and Decryption
def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_rsa(message: bytes, public_key):
    try:
        return public_key.encrypt(
            message,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        raise ValueError("Encryption failed") from e

def decrypt_rsa(encrypted_message: bytes, private_key):
    try:
        return private_key.decrypt(
            encrypted_message,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        raise ValueError("Decryption failed") from e

# SHA-256 Hashing
def hash_sha256(message: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message)
    return digest.finalize()
