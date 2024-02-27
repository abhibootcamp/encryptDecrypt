import streamlit as st
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# Function to generate RSA key pair
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Function to encrypt text using RSA
def encrypt_rsa(public_key, text):
    encrypted_text = public_key.encrypt(
        text.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=serialization.BestAvailableHash(default_backend())),
            algorithm=serialization.NoEncryption()
        )
    )
    return encrypted_text

# Function to decrypt text using RSA
def decrypt_rsa(private_key, encrypted_text):
    decrypted_text = private_key.decrypt(
        encrypted_text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=serialization.BestAvailableHash(default_backend())),
            algorithm=serialization.NoEncryption()
        )
    )
    return decrypted_text.decode()

# Function to encrypt text using AES
def encrypt_aes(key, text):
    cipher = Fernet(key)
    encrypted_text = cipher.encrypt(text.encode())
    return encrypted_text

# Function to decrypt text using AES
def decrypt_aes(key, encrypted_text):
    cipher = Fernet(key)
    decrypted_text = cipher.decrypt(encrypted_text)
    return decrypted_text.decode()

st.title("Text Encryption Using Cryptographic Algorithms")

# Select encryption algorithm
algorithm = st.selectbox("Select Encryption Algorithm", ["AES", "DES", "RSA"])

if algorithm == "RSA":
    # Generate RSA key pair
    private_key, public_key = generate_rsa_key_pair()

if st.button("Encrypt/Decrypt"):
    text = st.text_area("Enter Text")

    if text:
        if algorithm == "AES":
            key = st.text_input("Enter AES Key (16, 24, or 32 bytes)")
            if key:
                if len(key) not in [16, 24, 32]:
                    st.error("AES Key must be 16, 24, or 32 bytes long.")
                else:
                    if st.checkbox("Encrypt"):
                        encrypted_text = encrypt_aes(key.encode(), text)
                        st.write("Encrypted Text:", encrypted_text)
                    if st.checkbox("Decrypt"):
                        decrypted_text = decrypt_aes(key.encode(), encrypted_text)
                        st.write("Decrypted Text:", decrypted_text)
            else:
                st.warning("Please enter the AES key.")

        elif algorithm == "DES":
            st.warning("DES encryption/decryption is not implemented in this example.")

        elif algorithm == "RSA":
            if st.checkbox("Encrypt"):
                encrypted_text = encrypt_rsa(public_key, text)
                st.write("Encrypted Text:", encrypted_text)
            if st.checkbox("Decrypt"):
                decrypted_text = decrypt_rsa(private_key, encrypted_text)
                st.write("Decrypted Text:", decrypted_text)

    else:
        st.warning("Please enter text to encrypt/decrypt.")
