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