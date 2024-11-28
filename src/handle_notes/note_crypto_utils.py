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
		hashes.SHA256,
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
			hashes.SHA256,
		)
		return True
	except Exception as e:
		return False

# Old

def generate_session_key():
	"""Generates a session key for encryption and decryption."""
	return ChaCha20Poly1305.generate_key()

def encrypt_notes_data(notes_data, session_key):
	"""Encrypts notes data using the provided session key."""
	chacha = ChaCha20Poly1305(session_key)
	nonce = os.urandom(12)
	aad = b"authenticated data for integrity"
	ciphertext = chacha.encrypt(nonce, json.dumps(notes_data).encode('utf-8'), aad)
	print_manager = PrintManager()
	print_manager.print_debug("[CRYPTO LOG] Notes data encrypted using ChaCha20Poly1305, key length: 256 bits.")
	return nonce, ciphertext, aad

def decrypt_notes_data(nonce, session_key, aad, ciphertext):
	"""Decrypts notes data using the provided session key."""
	chacha = ChaCha20Poly1305(session_key)
	plaintext = chacha.decrypt(nonce, ciphertext, aad)
	print_manager = PrintManager()
	print_manager.print_debug("[CRYPTO LOG] Notes data decrypted using ChaCha20Poly1305, key length: 256 bits.")
	return json.loads(plaintext.decode('utf-8'))

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