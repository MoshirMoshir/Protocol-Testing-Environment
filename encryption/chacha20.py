from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes

def chacha20_encrypt(key, plaintext):
    """
    Encrypts the plaintext using ChaCha20-Poly1305.
    Used in modern secure communication protocols like TLS 1.3 and HTTP/3.
    """
    nonce = get_random_bytes(12)  # ChaCha20-Poly1305 recommended nonce size
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return nonce, ciphertext, tag

def chacha20_decrypt(key, nonce, ciphertext, tag):
    """
    Decrypts the ciphertext using ChaCha20-Poly1305.
    Validates the authenticity of the ciphertext using the tag.
    """
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()
