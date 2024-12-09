from encryption.aes import aes_encrypt, aes_decrypt
from encryption.rsa import rsa_generate_keys, rsa_encrypt, rsa_decrypt
from encryption.hmac import hmac_authenticate, hmac_verify
from encryption.gcm import gcm_encrypt, gcm_decrypt
from encryption.ecdh import ecdh_key_exchange, ecdh_encrypt, ecdh_decrypt
from encryption.ecdsa import ecdsa_generate_keys, ecdsa_sign, ecdsa_verify
from encryption.chacha20 import chacha20_encrypt, chacha20_decrypt
from Crypto.Random import get_random_bytes
from test.performance import measure_average_time

def main():
    # Keys
    aes_key = b'16byte_aes_key__'  # AES key must be 16, 24, or 32 bytes
    private_key, public_key = rsa_generate_keys()  # Generate RSA key pair
    hmac_key = b'secret_hmac_key'  # HMAC shared key

    # Message
    message = "This is a test message!"  # Test message

    # Iterations (easily changeable)
    iterations = 100

    """
    # AES (CBC) Test
    aes_total_enc, aes_avg_enc = measure_average_time(aes_encrypt, iterations, aes_key, message, label="AES Encrypt")
    aes_total_dec, aes_avg_dec = measure_average_time(aes_decrypt, iterations, aes_key, aes_encrypt(aes_key, message), label="AES Decrypt")
    print(f"AES: Total Encrypt Time: {aes_total_enc:.6f}s, Average Encrypt Time: {aes_avg_enc:.10f}s")
    print(f"AES: Total Decrypt Time: {aes_total_dec:.6f}s, Average Decrypt Time: {aes_avg_dec:.10f}s")

    # RSA Test
    rsa_total_enc, rsa_avg_enc = measure_average_time(rsa_encrypt, iterations, public_key, message, label="RSA Encrypt")
    rsa_total_dec, rsa_avg_dec = measure_average_time(rsa_decrypt, iterations, private_key, rsa_encrypt(public_key, message), label="RSA Decrypt")
    print(f"RSA: Total Encrypt Time: {rsa_total_enc:.6f}s, Average Encrypt Time: {rsa_avg_enc:.10f}s")
    print(f"RSA: Total Decrypt Time: {rsa_total_dec:.6f}s, Average Decrypt Time: {rsa_avg_dec:.10f}s")

    # HMAC Test
    hmac_total_auth, hmac_avg_auth = measure_average_time(hmac_authenticate, iterations, hmac_key, message, label="HMAC Authenticate")
    hmac_total_verify, hmac_avg_verify = measure_average_time(hmac_verify, iterations, hmac_key, message, hmac_authenticate(hmac_key, message), label="HMAC Verify")
    print(f"HMAC: Total Authenticate Time: {hmac_total_auth:.6f}s, Average Authenticate Time: {hmac_avg_auth:.10f}s")
    print(f"HMAC: Total Verify Time: {hmac_total_verify:.6f}s, Average Verify Time: {hmac_avg_verify:.10f}s")

    # AES-GCM Test
    gcm_total_enc, gcm_avg_enc = measure_average_time(gcm_encrypt, iterations, aes_key, message, label="AES-GCM Encrypt")
    nonce, ciphertext, tag = gcm_encrypt(aes_key, message)  # Encrypt once for decryption test
    gcm_total_dec, gcm_avg_dec = measure_average_time(gcm_decrypt, iterations, aes_key, nonce, ciphertext, tag, label="AES-GCM Decrypt")
    print(f"AES-GCM: Total Encrypt Time: {gcm_total_enc:.6f}s, Average Encrypt Time: {gcm_avg_enc:.10f}s")
    print(f"AES-GCM: Total Decrypt Time: {gcm_total_dec:.6f}s, Average Decrypt Time: {gcm_avg_dec:.10f}s")
    
    # ECDH Test
    aes_key = ecdh_key_exchange()  # Perform key exchange to derive a shared key
    ecdh_total_enc, ecdh_avg_enc = measure_average_time(ecdh_encrypt, iterations, aes_key, message, label="ECDH Encrypt")
    nonce, ciphertext, tag = ecdh_encrypt(aes_key, message)  # Encrypt once for decryption test
    ecdh_total_dec, ecdh_avg_dec = measure_average_time(ecdh_decrypt, iterations, aes_key, nonce, ciphertext, tag, label="ECDH Decrypt")
    print(f"ECDH: Total Encrypt Time: {ecdh_total_enc:.6f}s, Average Encrypt Time: {ecdh_avg_enc:.10f}s")
    print(f"ECDH: Total Decrypt Time: {ecdh_total_dec:.6f}s, Average Decrypt Time: {ecdh_avg_dec:.10f}s")
    
    # ECDSA Test
    private_key, public_key = ecdsa_generate_keys()  # Generate key pair
    ecdsa_total_sign, ecdsa_avg_sign = measure_average_time(ecdsa_sign, iterations, private_key, message, label="ECDSA Sign")
    signature = ecdsa_sign(private_key, message)  # Sign once for verification test
    ecdsa_total_verify, ecdsa_avg_verify = measure_average_time(ecdsa_verify, iterations, public_key, message, signature, label="ECDSA Verify")
    print(f"ECDSA: Total Sign Time: {ecdsa_total_sign:.6f}s, Average Sign Time: {ecdsa_avg_sign:.10f}s")
    print(f"ECDSA: Total Verify Time: {ecdsa_total_verify:.6f}s, Average Verify Time: {ecdsa_avg_verify:.10f}s")
    """
    # ChaCha20-Poly1305 Test
    chacha_key = get_random_bytes(32)  # ChaCha20 requires a 256-bit key
    chacha_total_enc, chacha_avg_enc = measure_average_time(chacha20_encrypt, iterations, chacha_key, message, label="ChaCha20 Encrypt")
    nonce, ciphertext, tag = chacha20_encrypt(chacha_key, message)  # Encrypt once for decryption test
    chacha_total_dec, chacha_avg_dec = measure_average_time(chacha20_decrypt, iterations, chacha_key, nonce, ciphertext, tag, label="ChaCha20 Decrypt")
    print(f"ChaCha20: Total Encrypt Time: {chacha_total_enc:.6f}s, Average Encrypt Time: {chacha_avg_enc:.10f}s")
    print(f"ChaCha20: Total Decrypt Time: {chacha_total_dec:.6f}s, Average Decrypt Time: {chacha_avg_dec:.10f}s")

if __name__ == "__main__":
    main()
