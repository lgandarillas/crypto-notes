"""
src/key_manager.py

KeyManager class for generating, encrypting, and storing ChaCha20Poly1305 and RSA keys.
"""

# This module is not being used yet.

import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization, hashes

class KeyManager:
	"""Manages cryptographic keys for encryption and decryption purposes."""

	def __init__(self, user_id):
		self.user_id = user_id
		self.key_folder = f"data/keys/{user_id}"
		os.makedirs(self.key_folder, exist_ok=True)

	def generate_chacha_key(self):
		"""Generates a new ChaCha20Poly1305 key."""
		key = ChaCha20Poly1305.generate_key()
		print(f"\033[90m[DEBUG] ChaCha20Poly1305 key generated (32 bytes).\033[0m")
		return key

	def generate_rsa_keys(self):
		"""Generates a pair of RSA public and private keys."""
		private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
		public_key = private_key.public_key()
		print(f"\033[90m[DEBUG] RSA keys generated with 2048 bits.\033[0m")
		return private_key, public_key

	def save_key(self, key, filename, is_private=False, password=None):
		"""Saves a cryptographic key to a file."""
		path = os.path.join(self.key_folder, filename)
		if is_private:
			encryption = serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
			pem_data = key.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.PKCS8,
				encryption_algorithm=encryption
			)
			print(f"\033[90m[DEBUG] Private key saved to {path}\033[0m")
		else:
			pem_data = key.public_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PublicFormat.SubjectPublicKeyInfo
			)
			print(f"\033[90m[DEBUG] Public key saved to {path}\033[0m")
		with open(path, "wb") as key_file:
			key_file.write(pem_data)