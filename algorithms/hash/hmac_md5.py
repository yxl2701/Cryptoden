try:
    from .common import hmac_digest
except ImportError:
    from algorithms.hash.common import hmac_digest

ALGORITHM_NAME = "HMAC-MD5"
ALGORITHM_DESC = "HMAC-MD5 消息认证码"


def encrypt(plaintext, key='key'):
    try:
        return hmac_digest(plaintext, key, 'md5')
    except Exception as error:
        return f"HMAC错误: {error}"
