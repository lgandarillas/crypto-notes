"""
src/note_crypto_manager.py

This module contains functions for encrypting and decrypting note content.
"""

import os
import base64
from note_operations import NoteHandler
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from rsa_utils import encrypt_with_public_key, decrypt_with_private_key

def generate_session_key(printer):
	"""Generate a 32-byte session key for ChaCha20Poly1305."""
	key = ChaCha20Poly1305.generate_key()
	printer.print_debug("[CRYPTO LOG] Session key generated; ChaCha20Poly1305, 256 bits")
	return key

def encrypt_note_content(printer, session_key, plaintext):
	"""Encrypt the note content using ChaCha20Poly1305."""
	chacha = ChaCha20Poly1305(session_key)
	nonce = os.urandom(12)
	encrypted_content = chacha.encrypt(nonce, plaintext.encode(), None)
	printer.print_debug("[CRYPTO LOG] Note content encrypted; ChaCha20Poly1305, 256 bits")
	return nonce, encrypted_content

def decrypt_note_content(printer, session_key, nonce, encrypted_content):
	"""Decrypt the note content using ChaCha20Poly1305."""
	chacha = ChaCha20Poly1305(session_key)
	plaintext = chacha.decrypt(nonce, encrypted_content, None)
	printer.print_debug("[CRYPTO LOG] Note content decrypted; ChaCha20Poly1305, 256 bits")
	return plaintext.decode()

def encrypt_and_save_note(printer, username, note_content):
	note_handler = NoteHandler(printer, username)
	session_key = generate_session_key()
	nonce, encrypted_content = encrypt_note_content(session_key, note_content)
	encrypted_session_key = encrypt_with_public_key(username, session_key)

	note_data = {
		"nonce": base64.urlsafe_b64encode(nonce).decode(),
		"content": base64.urlsafe_b64encode(encrypted_content).decode(),
		"session_key": base64.urlsafe_b64encode(encrypted_session_key).decode()
	}

	note_handler.save_notes([note_data])
	printer.print_debug("[CRYPTO LOG] Note data encrypted and saved; JSON, n/a")

def load_and_decrypt_note(printer, username, password):
	note_handler = NoteHandler(printer, username)
	note_data_list = note_handler.load_notes()
	note_data = note_data_list[0] if note_data_list else None

	encrypted_session_key = base64.urlsafe_b64decode(note_data["session_key"])
	session_key = decrypt_with_private_key(username, encrypted_session_key, password)
	nonce = base64.urlsafe_b64decode(note_data["nonce"])
	encrypted_content = base64.urlsafe_b64decode(note_data["content"])
	note_content = decrypt_note_content(session_key, nonce, encrypted_content)
	printer.print_debug("[CRYPTO LOG] Note data decrypted and loaded; JSON, n/a")
	return note_content