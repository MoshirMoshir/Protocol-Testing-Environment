import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encapsulate_metadata(sender, recipient, timestamp, key):
    """
    Encrypts SMS metadata for obfuscation.
    """
    metadata = json.dumps({"sender": sender, "recipient": recipient, "timestamp": timestamp})
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    encrypted_metadata, tag = cipher.encrypt_and_digest(metadata.encode())
    return nonce, encrypted_metadata, tag

def decapsulate_metadata(nonce, encrypted_metadata, tag, key):
    """
    Decrypts SMS metadata.
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    metadata = cipher.decrypt_and_verify(encrypted_metadata, tag)
    return json.loads(metadata.decode())
