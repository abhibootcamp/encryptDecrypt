import streamlit as st
from cryptography.fernet import Fernet

# Function to generate AES key
def generate_aes_key():
    return Fernet.generate_key()

# Function to encrypt text using AES
def encrypt_text(key, text):
    cipher_suite = Fernet(key)
    encrypted_text = cipher_suite.encrypt(text.encode())
    return encrypted_text

# Function to decrypt text using AES
def decrypt_text(key, encrypted_text):
    cipher_suite = Fernet(key)
    decrypted_text = cipher_suite.decrypt(encrypted_text).decode()
    return decrypted_text

st.title("Text Encryption and Decryption")

# Generate AES key
key = generate_aes_key()

# User input for text
text = st.text_area("Enter Text:")

# Encryption button
if st.button("Encrypt"):
    if text:
        encrypted_text = encrypt_text(key, text)
        st.success("Text encrypted successfully!")
        st.write("Encrypted Text:", encrypted_text.decode())
    else:
        st.warning("Please enter text to encrypt.")

# Decryption button
if st.button("Decrypt"):
    encrypted_text = st.text_area("Enter Encrypted Text:")
    if encrypted_text:
        try:
            decrypted_text = decrypt_text(key, encrypted_text.encode())
            st.success("Text decrypted successfully!")
            st.write("Decrypted Text:", decrypted_text)
        except Exception as e:
            st.error("Decryption failed. Please check the input.")
    else:
        st.warning("Please enter encrypted text to decrypt.")
