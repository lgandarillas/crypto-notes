"""
src/cryptography_utils.py

Module providing utility functions related to cryptographic operations such as
salt generation and key derivation using PBKDF2.
"""

import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_salt():
	"""Generate a random salt using os.urandom."""
	return os.urandom(16)

def derive_key(password, salt):
	"""Derive a secure key from a password and salt using PBKDF2."""
	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=32,
		salt=salt,
		iterations=480000
	)
	return base64.urlsafe_b64encode(kdf.derive(password.encode()))
