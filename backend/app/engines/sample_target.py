import hashlib
import ssl
from Crypto.PublicKey import RSA

def legacy_user_hash(password: str):
    # Weak MD5 hashing
    return hashlib.md5(password.encode()).hexdigest()

def legacy_signature(data: bytes):
    # Weak SHA-1 hashing
    return hashlib.sha1(data).digest()

def generate_old_key():
    # Weak 1024-bit RSA key generation
    return RSA.generate(1024)

def get_legacy_ssl_context():
    # Outdated SSL protocol
    return ssl.SSLContext(ssl.PROTOCOL_SSLv23)
