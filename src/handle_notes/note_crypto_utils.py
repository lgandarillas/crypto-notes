"""
src/note_crypto_utils.py

This module contains utility functions for encrypting and decrypting notes data and session keys.
By: Luis Gandarillas && Carlos Bravo
"""

import os
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from print_manager import PrintManager

# New

def	generate_hash(data):
	"""Generates a SHA-256 hash for the given data."""
	digest = hashes.Hash(hashes.SHA256())
	digest.update(data.encode('utf-8'))
	return digest.finalize()

def sign_hash_with_private_key(private_key, data_hash):
	signtaure = private_key.sign(
		data_hash,
		padding.PSS(
			mgf=padding.MGF1(hashes.SHA256()),
			salt_length=padding.PSS.MAX_LENGTH,
		),
		hashes.SHA256(),
	)
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
		return True
	except Exception as e:
		return False

# Modified

def encrypt_notes_data(notes_data, session_key, private_key):
	"""Encrypts notes data using the provided session key."""
	chacha = ChaCha20Poly1305(session_key)
	nonce = os.urandom(12)
	aad = b"authenticated data for integrity"

	# Convert notes to JSON string
	try:
		notes_data_str = json.dumps(notes_data)
	except Exception as e:
		raise ValueError(f"Failed to serialize notes data: {e}")

	# Generate hash and signature
	notes_hash = generate_hash(notes_data_str)
	print(f"[DEBUG] Hash for signing: {notes_hash.hex()}")

	signature = sign_hash_with_private_key(private_key, notes_hash)
	print(f"[DEBUG] Signature: {signature.hex()}")

	# Combine all components into one payload
	payload = {
		"notes": notes_data_str,	# JSON string of the notes
		"hash": notes_hash.hex(),
		"signature": signature.hex(),
	}

	try:
		payload_json = json.dumps(payload)
	except Exception as e:
		raise ValueError(f"Payload serialization failed: {e}")

	# Encrypt combined payload
	try:
		ciphertext = chacha.encrypt(nonce, payload_json.encode('utf-8'), aad)
	except Exception as e:
		raise ValueError(f"Encryption failed: {e}")

	return nonce, ciphertext, aad

def decrypt_notes_data(nonce, session_key, aad, ciphertext, public_key):
	"""Decrypts notes data using the provided session key."""
	chacha = ChaCha20Poly1305(session_key)
	try:
		plaintext = chacha.decrypt(nonce, ciphertext, aad)
	except Exception as e:
		raise ValueError(f"Decryption failed: {e}")

	try:
		payload = json.loads(plaintext.decode('utf-8'))
	except Exception as e:
		raise ValueError(f"Failed to deserialize payload: {e}")

	# Extract components
	try:
		notes_data_str = payload["notes"]
		notes_hash = bytes.fromhex(payload["hash"])
		signature = bytes.fromhex(payload["signature"])
		print(f"[DEBUG] Payload notes hash: {notes_hash.hex()}")
		print(f"[DEBUG] Payload signature: {signature.hex()}")
	except KeyError as e:
		raise ValueError(f"Missing excepted key in payload: {e}")

	# Verify signature
	if not verify_signature_with_public_key(public_key, signature, notes_hash):
		raise ValueError("Signature validation failed.")

	# Recalculate hash to validate integrity
	recalculated_hash = generate_hash(notes_data_str)
	print(f"[DEBUG] Recalculated hash: {recalculated_hash.hex()}")
	if recalculated_hash != notes_hash:
		raise ValueError("Hash mismatch. Possible data tampering.")

	# Convert JSON string back to original data structure
	try:
		return json.loads(notes_data_str)
	except Exception as e:
		raise ValueError(f"Failed to deserialize notes data: {e}")

# Old

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
	return session_key