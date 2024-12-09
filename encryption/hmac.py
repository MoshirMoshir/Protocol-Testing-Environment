import hmac
import hashlib

def hmac_authenticate(key, message):
    hmac_instance = hmac.new(key, message.encode(), hashlib.sha256)
    return hmac_instance.hexdigest()

def hmac_verify(key, message, mac):
    hmac_instance = hmac.new(key, message.encode(), hashlib.sha256)
    return hmac_instance.hexdigest() == mac
