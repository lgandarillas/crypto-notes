"""
src/handle_notes/note_file_manager.py

Handles loading, saving, encrypting, and decrypting notes.
"""

import os
import json
from handle_notes.crypto_key_utils import generate_encryption_key, encrypt_encryption_key, decrypt_encryption_key
from handle_notes.note_encryption import encrypt_notes_data, decrypt_notes_data
from handle_notes.note_utils import ensure_directory_exists

class NoteFileManager:
	"""Manages file operations related to notes."""

	def __init__(self, username, rsa_private_key, rsa_public_key):
		self.notes_dir = "data/notes"
		self.notes_file = f"{self.notes_dir}/notes_{username}.json"
		self.rsa_private_key = rsa_private_key
		self.rsa_public_key = rsa_public_key

	def load_notes(self):
		"""Loads notes from the user's file."""
		ensure_directory_exists(self.notes_dir)

		if not os.path.exists(self.notes_file):
			return []

		try:
			notes_data_str = self._decrypt_notes_file()
			return json.loads(notes_data_str)
		except Exception as e:
			raise RuntimeError(f"[SECURITY ALERT] Failed to load notes: {e}")

	def save_notes(self, notes):
		"""Saves the current list of notes to the user's file."""
		if notes:
			encrypted_data = self._encrypt_notes_file(notes)
			with open(self.notes_file, 'w') as file:
				json.dump(encrypted_data, file, indent=4)
		elif os.path.exists(self.notes_file):
			os.remove(self.notes_file)

	def _decrypt_notes_file(self):
		"""Decrypts the notes file and returns the decrypted notes as a string."""
		with open(self.notes_file, 'rb') as file:
			encrypted_data = json.load(file)

		encrypted_encryption_key = bytes.fromhex(encrypted_data["encrypted_encryption_key"])
		nonce = bytes.fromhex(encrypted_data["nonce"])
		ciphertext = bytes.fromhex(encrypted_data["ciphertext"])
		aad = bytes.fromhex(encrypted_data["aad"])

		encryption_key = decrypt_encryption_key(self.rsa_private_key, encrypted_encryption_key)
		return decrypt_notes_data(nonce, encryption_key, aad, ciphertext, self.rsa_public_key)

	def _encrypt_notes_file(self, notes):
		"""Encrypts and prepares notes data for saving."""
		encryption_key = generate_encryption_key()
		notes_data = json.dumps(notes)

		nonce, ciphertext, aad = encrypt_notes_data(notes_data, encryption_key, self.rsa_private_key)
		encrypted_encryption_key = encrypt_encryption_key(self.rsa_public_key, encryption_key)

		return {
			"nonce": nonce.hex(),
			"encrypted_encryption_key": encrypted_encryption_key.hex(),
			"aad": aad.hex(),
			"ciphertext": ciphertext.hex()
		}
