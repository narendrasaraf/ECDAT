"""Authored static fixture; the scanner must never execute this file."""
import hashlib as digest
from cryptography.hazmat.primitives.asymmetric import rsa as rsa_keys

# hashlib.sha1(b"a comment is not a confirmed finding")
digest.md5(b"fixture-only")
rsa_keys.generate_private_key(public_exponent=65537, key_size=unknown_key_size)
