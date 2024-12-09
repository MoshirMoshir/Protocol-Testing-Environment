from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

def ecdsa_generate_keys():
    """
    Generates an ECC key pair for signing and verification.
    Commonly used in secure communication protocols like RCS for message authenticity.
    """
    private_key = ECC.generate(curve='P-256')  # Generate a private key
    public_key = private_key.public_key()  # Extract the corresponding public key
    return private_key, public_key

def ecdsa_sign(private_key, message):
    """
    Signs a message using ECDSA.
    """
    hasher = SHA256.new(message.encode())  # Hash the message
    signer = DSS.new(private_key, 'fips-186-3')  # Create the signer object
    signature = signer.sign(hasher)  # Sign the hash
    return signature

def ecdsa_verify(public_key, message, signature):
    """
    Verifies an ECDSA signature for a given message.
    """
    hasher = SHA256.new(message.encode())  # Hash the message
    verifier = DSS.new(public_key, 'fips-186-3')  # Create the verifier object
    try:
        verifier.verify(hasher, signature)  # Verify the signature
        return True
    except ValueError:
        return False
