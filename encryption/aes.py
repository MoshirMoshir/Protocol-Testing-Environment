from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

def aes_encrypt(key, message):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + ciphertext).decode()

def aes_decrypt(key, encrypted_message):
    raw_data = base64.b64decode(encrypted_message)
    iv = raw_data[:16]
    ciphertext = raw_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
