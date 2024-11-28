"""
src/handle_notes/note_encryption.py

Contains functions for encrypting and decrypting notes data.
"""

import os
import json
from print_manager import PrintManager
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from .crypto_hash_utils import generate_hash, sign_hash_with_private_key, verify_signature_with_public_key

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
