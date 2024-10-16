# app.py

import streamlit as st
import base64
from cryptography_utils import (
    encrypt_aes,
    decrypt_aes,
    hash_sha256,
    generate_rsa_keypair,
    encrypt_rsa,
    decrypt_rsa,
)
from cryptography.hazmat.primitives import serialization

# Initialize RSA keys in session state
if 'private_key' not in st.session_state:
    private_key, public_key = generate_rsa_keypair()
    st.session_state.private_key = private_key
    st.session_state.public_key = public_key

# Helper functions to display keys
def get_public_key_pem(public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode()

def get_private_key_pem(private_key):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem.decode()

# Streamlit App Layout
st.set_page_config(page_title="SecureText Encryption Tool", layout="wide")
st.title("🔒 SecureText Encryption Tool")

# Sidebar for Encryption Method Selection
st.sidebar.header("Encryption Method")
encryption_method = st.sidebar.radio(
    "Select Encryption Method:",
    ("AES", "RSA", "SHA-256")
)

st.sidebar.markdown("---")

# Display RSA Keys if RSA is selected
if encryption_method == "RSA":
    st.sidebar.subheader("RSA Keys")
    st.sidebar.text_area("Public Key (RSA):", get_public_key_pem(st.session_state.public_key), height=200)
    st.sidebar.text_area("Private Key (RSA):", get_private_key_pem(st.session_state.private_key), height=200)

st.markdown("## Input Parameters")

# Input Fields
message = st.text_area("Message:", height=100)

if encryption_method in {"AES", "RSA"}:
    if encryption_method == "AES":
        key_help = "Key must be 16, 24, or 32 bytes long."
        iv_help = "IV must be 16 bytes long."
    elif encryption_method == "RSA":
        key_help = "Public Key (RSA) is used for encryption."
        iv_help = "Private Key (RSA) is used for decryption."

    key_input = st.text_input("Key:", help=key_help)
    iv_input = st.text_input("IV:", help=iv_help) if encryption_method == "AES" else None
else:
    key_input = st.text_input("Key (not used in SHA-256):", disabled=True)
    iv_input = st.text_input("IV (not used in SHA-256):", disabled=True)

st.markdown("---")

# Action Buttons
col1, col2 = st.columns(2)
with col1:
    encrypt = st.button("🔒 Encrypt")
with col2:
    decrypt = st.button("🔓 Decrypt")

st.markdown("---")

# Result Display
if 'result' not in st.session_state:
    st.session_state.result = ""

# Encryption Functionality
if encrypt and message:
    try:
        method = encryption_method
        key = key_input.encode() if method in {"AES", "RSA"} else b''
        iv = iv_input.encode() if method == "AES" else b''
        msg = message.encode()

        if method == "AES":
            if len(key) not in {16, 24, 32}:
                st.error("Key must be 16, 24, or 32 bytes long.")
            elif len(iv) != 16:
                st.error("IV must be 16 bytes long.")
            else:
                encrypted = encrypt_aes(msg, key, iv)
                st.session_state.result = f"**Encrypted (AES):** {encrypted.decode()}"
        elif method == "RSA":
            if not key_input:
                st.error("Public Key is required for RSA encryption.")
            else:
                # Assuming key_input is the PEM format public key
                public_key = serialization.load_pem_public_key(key_input.encode())
                encrypted = encrypt_rsa(msg, public_key)
                encrypted_b64 = base64.b64encode(encrypted).decode()
                st.session_state.result = f"**Encrypted (RSA):** {encrypted_b64}"
        elif method == "SHA-256":
            hashed = hash_sha256(msg)
            hashed_b64 = base64.b64encode(hashed).decode()
            st.session_state.result = f"**Hash (SHA-256):** {hashed_b64}"
    except Exception as e:
        st.error(f"An error occurred during encryption: {e}")

# Decryption Functionality
if decrypt and message:
    try:
        method = encryption_method
        key = key_input.encode() if method in {"AES", "RSA"} else b''
        iv = iv_input.encode() if method == "AES" else b''
        msg = message.encode()

        if method == "AES":
            if len(key) not in {16, 24, 32}:
                st.error("Key must be 16, 24, or 32 bytes long.")
            elif len(iv) != 16:
                st.error("IV must be 16 bytes long.")
            else:
                decrypted = decrypt_aes(msg, key, iv)
                st.session_state.result = f"**Decrypted (AES):** {decrypted.decode()}"
        elif method == "RSA":
            if not key_input:
                st.error("Private Key is required for RSA decryption.")
            else:
                # Assuming key_input is the PEM format private key
                private_key = serialization.load_pem_private_key(key_input.encode(), password=None)
                encrypted_bytes = base64.b64decode(message)
                decrypted = decrypt_rsa(encrypted_bytes, private_key)
                st.session_state.result = f"**Decrypted (RSA):** {decrypted.decode()}"
        elif method == "SHA-256":
            st.warning("Hashing is not reversible.")
            st.session_state.result = "Hashing is not reversible."
    except Exception as e:
        st.error(f"An error occurred during decryption: {e}")

# Display Result
if st.session_state.result:
    st.markdown("### Result")
    st.success(st.session_state.result)
