import streamlit as st
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken

# Core encryption/decryption functions
def generate_encryption_key():
    return Fernet.generate_key().decode()

def encrypt_text(plaintext, key_str):
    f = Fernet(key_str.encode())
    return f.encrypt(plaintext.encode()).decode()

def decrypt_text(ciphertext, key_str):
    f = Fernet(key_str.encode())
    return f.decrypt(ciphertext.encode()).decode()

# Streamlit UI setup
st.set_page_config(page_title="Secure Text Messenger", layout="centered")
st.title("Secure Text Messenger")

# Key Generation Section
st.header("Generate Key")
col_key_gen_input, col_key_gen_btn = st.columns([3, 1])
with col_key_gen_input:
    # Using st.session_state to preserve key value across reruns
    if 'current_key' not in st.session_state:
        st.session_state.current_key = ""
    # This is the main key display/input field
    global_key_display_input = st.text_input("Generated Key", value=st.session_state.current_key, key="global_key_display")
with col_key_gen_btn:
    st.markdown("<br>", unsafe_allow_html=True) # Add some vertical space to align button
    if st.button("Generate New Key"):
        try:
            generated_key = generate_encryption_key()
            st.session_state.current_key = generated_key
            # Also update the encryption and decryption key fields directly
            st.session_state.encryption_key_field = generated_key
            st.session_state.decryption_key_field = generated_key
            st.rerun() # Rerun to update the text_input values
        except Exception as e:
            st.error(f"Error generating key: {e}")

st.markdown("---")

# Encryption Section
st.header("Encrypt Text")
col_encrypt_text, col_encrypt_key = st.columns([2, 1]) # Two columns for side-by-side input

with col_encrypt_text:
    plaintext_input = st.text_area("Plaintext", height=100, placeholder="Enter text to encrypt here...", key="plaintext_input_area")

with col_encrypt_key:
    # Initialize session state for this specific key field if not present
    if 'encryption_key_field' not in st.session_state:
        st.session_state.encryption_key_field = st.session_state.current_key # Initialize with global key if available

    # This is the specific key input for encryption
    encryption_key_input = st.text_input("Encryption Key", value=st.session_state.encryption_key_field, key="encryption_key_input_field")
    st.session_state.encryption_key_field = encryption_key_input # Update session state on user input

if st.button("Encrypt Text", type="primary"):
    if plaintext_input and encryption_key_input:
        try:
            encrypted_output = encrypt_text(plaintext_input, encryption_key_input)
            st.success("Encryption successful!")
            st.text_area("Encrypted Text", value=encrypted_output, height=100, disabled=True, key="encrypted_output_area")
        except Exception as e:
            st.error(f"Encryption error: {e}. Ensure the key and text are correct.")
    else:
        st.warning("Please enter plaintext and encryption key.")

st.markdown("---")

# Decryption Section
st.header("Decrypt Text")
col_decrypt_text, col_decrypt_key = st.columns([2, 1]) # Two columns for side-by-side input

with col_decrypt_text:
    decrypt_ciphertext_input = st.text_area("Ciphertext", height=100, placeholder="Enter ciphertext to decrypt here...", key="decrypt_ciphertext_input_area")

with col_decrypt_key:
    # Initialize session state for this specific key field if not present
    if 'decryption_key_field' not in st.session_state:
        st.session_state.decryption_key_field = st.session_state.current_key # Initialize with global key if available

    # This is the specific key input for decryption
    decryption_key_input = st.text_input("Decryption Key", value=st.session_state.decryption_key_field, key="decryption_key_input_field")
    st.session_state.decryption_key_field = decryption_key_input # Update session state on user input


if st.button("Decrypt Text", type="secondary"):
    if decrypt_ciphertext_input and decryption_key_input:
        try:
            decrypted_output = decrypt_text(decrypt_ciphertext_input, decryption_key_input)
            st.success("Decryption successful!")
            st.text_area("Decrypted Text", value=decrypted_output, height=100, disabled=True, key="decrypted_output_area")
        except InvalidToken:
            st.error("Error: Invalid key or corrupted ciphertext.")
        except Exception as e:
            st.error(f"Decryption error: {e}. Ensure the key and ciphertext are correct.")
    else:
        st.warning("Please enter ciphertext and decryption key.")

st.markdown("---")
st.info("Note: This app uses secure Fernet encryption. The key is essential for decryption.")
