"""
src/handle_notes/crypto_key_utils.py

Contains utility functions for encryption key management.
"""

from print_manager import PrintManager
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def generate_encryption_key():
	"""Generates a encryption key for encryption and decryption."""
	return ChaCha20Poly1305.generate_key()

def encrypt_encryption_key(public_key, encryption_key):
	"""Encrypts the encryption key using the provided public key."""
	encrypted_encryption_key = public_key.encrypt(
		encryption_key,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		)
	)
	PrintManager().print_debug("[CRYPTO LOG] encryption key encrypted using RSA-OAEP with SHA-256.")
	return encrypted_encryption_key

def decrypt_encryption_key(private_key, encrypted_encryption_key):
	"""Decrypts the encryption key using the provided private key."""
	encryption_key = private_key.decrypt(
		encrypted_encryption_key,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		)
	)
	PrintManager().print_debug("[CRYPTO LOG] encryption key decrypted using RSA-OAEP with SHA-256.")
	return encryption_key
