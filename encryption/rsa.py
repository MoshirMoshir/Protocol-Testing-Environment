from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

def rsa_generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(public_key, message):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return base64.b64encode(cipher.encrypt(message.encode())).decode()

def rsa_decrypt(private_key, encrypted_message):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.decrypt(base64.b64decode(encrypted_message)).decode()
