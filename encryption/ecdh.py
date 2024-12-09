from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def ecdh_key_exchange():
    """
    Performs an Elliptic Curve Diffie-Hellman (ECDH) key exchange.
    Commonly used in secure communication protocols like Signal for key derivation.
    """
    # Generate ECC key pairs for two parties
    private_key_1 = ECC.generate(curve='P-256')
    private_key_2 = ECC.generate(curve='P-256')

    # Exchange public keys and compute the shared secret
    shared_secret_1 = private_key_1.pointQ * private_key_2.d  # Party 1's computation
    shared_secret_2 = private_key_2.pointQ * private_key_1.d  # Party 2's computation

    # Ensure both parties derive the same shared secret
    assert shared_secret_1 == shared_secret_2, "ECDH key exchange failed!"

    # Convert the shared secret to bytes
    shared_secret_bytes = int(shared_secret_1.x).to_bytes(32, byteorder='big')

    # Derive a symmetric AES key from the shared secret
    aes_key = SHA256.new(shared_secret_bytes).digest()
    return aes_key

def ecdh_encrypt(aes_key, plaintext):
    """
    Encrypts a message using AES-GCM with the derived key from ECDH.
    """
    nonce = get_random_bytes(12)  # Recommended nonce size for AES-GCM
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return nonce, ciphertext, tag

def ecdh_decrypt(aes_key, nonce, ciphertext, tag):
    """
    Decrypts a message using AES-GCM with the derived key from ECDH.
    """
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()
