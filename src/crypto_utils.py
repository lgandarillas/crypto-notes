"""
src/crypto_utils.py

Module providing utility functions related to cryptographic operations such as
salt generation and key derivation using PBKDF2.
By: Luis Gandarillas && Carlos Bravo
"""

import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class CryptoUtils:
	def __init__(self, printer):
		self.printer = printer

	def generate_salt(self):
		"""Generate a random salt using os.urandom."""
		self.printer.print_debug("[CRYPTO LOG] Salt generated; os.urandom, 16 bytes")
		return os.urandom(16)

	def derive_key(self, password, salt):
		"""Derive a secure key from a password and salt using PBKDF2."""
		kdf = PBKDF2HMAC(
			algorithm=hashes.SHA256(),
			length=32,
			salt=salt,
			iterations=480000
		)
		self.printer.print_debug("[CRYPTO LOG] Key derived; PBKDF2-HMAC-SHA256, 32 bytes")
		return base64.urlsafe_b64encode(kdf.derive(password.encode()))