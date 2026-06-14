try:
    from .ecc import generate_key_pair, sign, verify
except ImportError:
    from algorithms.asymmetric.ecc.ecc import generate_key_pair, sign, verify

ALGORITHM_NAME = "ECC ECDSA Sign/Verify"
ALGORITHM_DESC = "ECC ECDSA 签名和验签"


def encrypt(plaintext, private_key='', curve='P-256', hash_algorithm='SHA256'):
    return sign(plaintext, private_key=private_key, curve=curve, hash_algorithm=hash_algorithm)


def decrypt(ciphertext, message='', public_key='', hash_algorithm='SHA256'):
    return verify(message, ciphertext, public_key=public_key, hash_algorithm=hash_algorithm)
