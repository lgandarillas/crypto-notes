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

def	generate_hash(data):
	"""Generates a SHA-256 hash for the given data."""
	digest = hashes.Hash(hashes.SHA256())
	digest.update(data.encode('utf-8'))
	hash_result = digest.finalize()

	PrintManager().print_debug("[CRYPTO LOG] Hash generated using SHA-256.")

	return hash_result

def sign_hash_with_private_key(private_key, data_hash):
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

def encrypt_notes_data(notes_data, session_key, private_key):
	"""Encrypts notes data using the provided session key."""
	chacha = ChaCha20Poly1305(session_key)
	nonce = os.urandom(12)
	aad = b"authenticated data for integrity"

	try:
		notes_data_str = json.dumps(notes_data)
	except Exception as e:
		raise ValueError(f"Failed to serialize notes data: {e}")

	notes_hash = generate_hash(notes_data_str)
	signature = sign_hash_with_private_key(private_key, notes_hash)

	payload = {
		"notes": notes_data_str,
		"hash": notes_hash.hex(),
		"signature": signature.hex(),
	}

	try:
		payload_json = json.dumps(payload)
	except Exception as e:
		raise ValueError(f"Payload serialization failed: {e}")

	try:
		ciphertext = chacha.encrypt(nonce, payload_json.encode('utf-8'), aad)
	except Exception as e:
		raise ValueError(f"Encryption failed: {e}")

	PrintManager().print_debug("[CRYPTO LOG] Notes encrypted using ChaCha20Poly1305.")
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

	try:
		notes_data_str = payload["notes"]
		notes_hash = bytes.fromhex(payload["hash"])
		signature = bytes.fromhex(payload["signature"])
	except KeyError as e:
		raise ValueError(f"Missing excepted key in payload: {e}")

	if not verify_signature_with_public_key(public_key, signature, notes_hash):
		raise ValueError("Signature validation failed.")

	recalculated_hash = generate_hash(notes_data_str)
	if recalculated_hash != notes_hash:
		raise ValueError("Hash mismatch. Possible data tampering.")

	PrintManager().print_debug("[CRYPTO LOG] Notes decrypted and signature verified successfully.")
	return json.loads(notes_data_str)

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