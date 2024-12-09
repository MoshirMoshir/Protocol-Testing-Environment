from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def gcm_encrypt(key, plaintext):
    """
    Encrypts the plaintext using AES-GCM.
    Used in modern secure messaging protocols like RCS for E2EE.
    """
    nonce = get_random_bytes(12)  # Recommended nonce size for AES-GCM
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return nonce, ciphertext, tag

def gcm_decrypt(key, nonce, ciphertext, tag):
    """
    Decrypts the ciphertext using AES-GCM.
    Validates the authenticity of the ciphertext using the tag.
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()
