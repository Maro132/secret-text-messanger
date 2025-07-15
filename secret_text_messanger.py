import streamlit as st
from cryptography.fernet import Fernet
# Removed: from cryptography.exceptions import InvalidToken - handled generally now

# Core encryption/decryption functions
def generate_encryption_key():
    return Fernet.generate_key().decode()

def encrypt_text(plaintext, key_str):
    f = Fernet(key_str.encode())
    return f.encrypt(plaintext.encode()).decode()

def decrypt_text(ciphertext, key_str):
    # This function will raise an exception if the key is invalid or ciphertext is corrupted
    f = Fernet(key_str.encode())
    return f.decrypt(ciphertext.encode()).decode()

# Streamlit UI setup
st.set_page_config(page_title="Secure Text Messenger", layout="centered")
st.title("Secure Text Messenger")

# Key Generation
st.header("Generate Key")
col1, col2 = st.columns([3, 1])
with col1:
    if 'current_key' not in st.session_state:
        st.session_state.current_key = ""
    key_input = st.text_input("Key", value=st.session_state.current_key, key="main_key_input")
with col2:
    if st.button("Generate New Key"):
        try:
            generated_key = generate_encryption_key()
            st.session_state.current_key = generated_key
            st.rerun() # Rerun to update the text_input value
        except Exception as e:
            st.error(f"Error generating key: {e}")

st.markdown("---")

# Encryption Section
st.header("Encrypt Text")
plaintext_input = st.text_area("Plaintext", height=100, placeholder="Enter text to encrypt here...")
if st.button("Encrypt Text", type="primary"):
    if plaintext_input and key_input:
        try:
            encrypted_output = encrypt_text(plaintext_input, key_input)
            st.success("Encryption successful!")
            st.text_area("Encrypted Text", value=encrypted_output, height=100, disabled=True)
        except Exception as e:
            st.error(f"Encryption error: {e}. Ensure the key and text are correct.")
    else:
        st.warning("Please enter plaintext and key for encryption.")

st.markdown("---")

# Decryption Section
st.header("Decrypt Text")
decrypt_ciphertext_input = st.text_area("Ciphertext", height=100, placeholder="Enter ciphertext to decrypt here...")
decrypt_key_input = st.text_input("Key for Decryption", key="decrypt_key_field")
if st.button("Decrypt Text", type="secondary"):
    if decrypt_ciphertext_input and decrypt_key_input:
        try:
            decrypted_output = decrypt_text(decrypt_ciphertext_input, decrypt_key_input)
            st.success("Decryption successful!")
            st.text_area("Decrypted Text", value=decrypted_output, height=100, disabled=True)
        except Exception as e: # Catching general Exception now
            if "InvalidToken" in str(e): # Check if the error message contains "InvalidToken"
                st.error("Error: Invalid key or corrupted ciphertext.")
            else:
                st.error(f"Decryption error: {e}. Ensure the key and ciphertext are correct.")
    else:
        st.warning("Please enter ciphertext and key for decryption.")

st.markdown("---")
st.info("Note: This app uses secure Fernet encryption. The key is essential for decryption.")
