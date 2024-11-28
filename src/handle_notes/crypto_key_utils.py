"""
src/handle_notes/crypto_key_utils.py

Contains utility functions for session key management.
"""

from print_manager import PrintManager
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def generate_session_key():
	"""Generates a session key for encryption and decryption."""
	return ChaCha20Poly1305.generate_key()

def encrypt_session_key(public_key, session_key):
	"""Encrypts the session key using the provided public key."""
	encrypted_session_key = public_key.encrypt(
		session_key,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		)
	)
	PrintManager().print_debug("[CRYPTO LOG] Session key encrypted using RSA-OAEP with SHA-256.")
	return encrypted_session_key

def decrypt_session_key(private_key, encrypted_session_key):
	"""Decrypts the session key using the provided private key."""
	session_key = private_key.decrypt(
		encrypted_session_key,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		)
	)
	PrintManager().print_debug("[CRYPTO LOG] Session key decrypted using RSA-OAEP with SHA-256.")
	return session_key
