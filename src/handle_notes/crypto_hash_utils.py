"""
src/handle_notes/crypto_hash_utils.py

Contains utility functions for generating hashes and signing/verification.
"""

from print_manager import PrintManager
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def	generate_hash(data):
	"""Generates a SHA-256 hash for the given data."""
	digest = hashes.Hash(hashes.SHA256())
	digest.update(data.encode('utf-8'))
	hash_result = digest.finalize()

	PrintManager().print_debug("[CRYPTO LOG] Hash generated using SHA-256.")

	return hash_result

def sign_hash_with_private_key(private_key, data_hash):
	"""Signs the hash using the provided private key."""
	signtaure = private_key.sign(
		data_hash,
		padding.PSS(
			mgf=padding.MGF1(hashes.SHA256()),
			salt_length=padding.PSS.MAX_LENGTH,
		),
		hashes.SHA256(),
	)
	PrintManager().print_debug("[CRYPTO LOG] Hash signed using RSA-PSS with SHA-256.")
	return signtaure

def verify_signature_with_public_key(public_key, signtaure, data_hash):
	"""Verifies the signature of the hash using the public RSA key."""
	try:
		public_key.verify(
			signtaure,
			data_hash,
			padding.PSS(
				mgf=padding.MGF1(hashes.SHA256()),
				salt_length=padding.PSS.MAX_LENGTH,
			),
			hashes.SHA256(),
		)
		PrintManager().print_debug("[CRYPTO LOG] Signature verified using RSA-PSS with SHA-256.")
		return True

	except Exception as e:
		PrintManager().print_debug(f"[CRYPTO LOG] Signature verification failed: {e}")
		return False
