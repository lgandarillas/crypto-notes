"""
src/note_handler.py

This file contains the note manager for the program.
By: Luis Gandarillas && Carlos Bravo
"""

import os
import re
import json
from print_manager import PrintManager
from handle_notes.note_actions import NoteActions
from handle_notes.note_encryption import encrypt_notes_data, decrypt_notes_data
from handle_notes.crypto_key_utils import generate_session_key, encrypt_session_key, decrypt_session_key

class NoteHandler:
	"""Manages note-taking functionalities, including creating, reading, listing, and deleting notes."""

	def __init__(self, username, rsa_private_key, rsa_public_key):
		self.printer = PrintManager()
		self.rsa_private_key = rsa_private_key
		self.rsa_public_key = rsa_public_key
		self.username = username
		self.notes_dir = "data/notes"
		self.notes_file = f"{self.notes_dir}/notes_{username}.json"

	def run_notes_app(self, is_first_time_login=False):
		"""Runs the note management session, allowing the user to choose different note operations."""
		if is_first_time_login:
			self._new_note()
			return
		while True:
			try:
				mode = input(f"\nSelect a mode ({self.printer.COLOR_BLUE}new{self.printer.COLOR_RESET}, {self.printer.COLOR_BLUE}read{self.printer.COLOR_RESET}, {self.printer.COLOR_BLUE}list{self.printer.COLOR_RESET}, {self.printer.COLOR_BLUE}delete{self.printer.COLOR_RESET}, {self.printer.COLOR_BLUE}exit{self.printer.COLOR_RESET}) for user {self.username}: ").strip().lower()

				if not mode or mode == "exit":
					self.printer.print_action(f"Exiting notes app for user {self.username}")
					break
				else:
					self._execute_mode(mode)

			except KeyboardInterrupt:
				print("^C")
				self.printer.print_action(f"Exiting notes app for user {self.username}")
				break

	def _execute_mode(self, mode):
		"""Dispatches the action based on the mode chosen by the user or informs of an invalid selection."""
		notes = self._load_notes()
		note_actions = NoteActions(notes)

		if mode == "new":
			self._new_note()
		elif mode == "read":
			note_name = input("Enter the name of the note you want to read: ").strip()
			note_actions.read(note_name)
		elif mode == "list":
			note_actions.list()
		elif mode == "delete":
			note_name = input("Enter the name of the note to delete: ").strip()
			if note_actions.delete(note_name):
				self._save_notes(notes)
		else:
			self.printer.print_error("Invalid mode selected")

	def _new_note(self):
		"""Handles the creation of a new note, including input validation and storage."""
		self.printer.print_action("You selected new note mode")
		note_name = input("Enter a name for the new note (letters, numbers, underscores only): ").strip()
		notes = self._load_notes()
		note_actions = NoteActions(notes)

		if not self._validate_note_name(note_name, notes, self.printer):
			return

		self.printer.print_action("Enter the note content (press Ctrl+D to finish):")
		note_content = []
		while True:
			try:
				line = input()
			except EOFError:
				break
			note_content.append(line)
		note_content = "\n".join(note_content)
		note_actions.create(note_name, note_content)
		self._save_notes(notes)

	@staticmethod
	def _ensure_directory_exists(directory_path):
		"""Ensures that the specified directory exists, creating it if necessary."""
		if not os.path.exists(directory_path):
			os.makedirs(directory_path)

	def _decrypt_notes_file(self):
		"""Decrypts and loads the notes file, returning the decrypted notes as a string."""
		with open(self.notes_file, 'rb') as file:
				encrypted_data = json.load(file)

		encrypted_session_key = bytes.fromhex(encrypted_data["encrypted_session_key"])
		nonce = bytes.fromhex(encrypted_data["nonce"])
		ciphertext = bytes.fromhex(encrypted_data["ciphertext"])
		aad = bytes.fromhex(encrypted_data["aad"])

		session_key = decrypt_session_key(self.rsa_private_key, encrypted_session_key)
		notes_data_str = decrypt_notes_data(nonce, session_key, aad, ciphertext, self.rsa_public_key)

		return notes_data_str

	def _load_notes(self):
		"""Loads notes from a file associated with the user."""
		self._ensure_directory_exists(self.notes_dir)

		if not os.path.exists(self.notes_file):
			return []

		try:
			notes_data_str = self._decrypt_notes_file()
			self.printer.print_debug("[CRYPTO LOG] Notes successfully decrypted and loaded.")
			return json.loads(notes_data_str)
		except ValueError as e:
			self.printer.print_error(f"[SECURITY ALERT] {e}")
			exit(1)
		except Exception as e:
			self.printer.print_error(f"[SECURITY ALERT] Failed to load notes: {e}")
			exit(1)

	def _encrypt_notes_file(self, notes):
		"""Encrypts and prepares notes data for saving."""
		session_key = generate_session_key()
		notes_data = json.dumps(notes)

		nonce, ciphertext, aad = encrypt_notes_data(notes_data, session_key, self.rsa_private_key)
		encrypted_session_key = encrypt_session_key(self.rsa_public_key, session_key)

		encrypted_data = {
			"nonce": nonce.hex(),
			"encrypted_session_key": encrypted_session_key.hex(),
			"aad": aad.hex(),
			"ciphertext": ciphertext.hex()
		}

		return encrypted_data

	def _save_notes(self, notes):
		"""Saves the current list of notes to the user's file."""
		if notes:
			encrypted_data = self._encrypt_notes_file(notes)

			with open(self.notes_file, 'w') as file:
				json.dump(encrypted_data, file, indent=4)

			self.printer.print_debug("[CRYPTO LOG] Notes saved and encrypted with ChaCha20Poly1305, key length: 256 bits.")
		else:
			if os.path.exists(self.notes_file):
				os.remove(self.notes_file)

	@staticmethod
	def _validate_note_name(note_name, notes, printer):
		"""Validates the note name and checks if it already exists."""
		if not re.match(r'^\w+$', note_name):
			printer.print_error("Invalid note name. Only letters, numbers, and underscores are allowed.")
			return False

		for note in notes:
			if note["name"] == note_name:
				printer.print_error(f"Note '{note_name}' already exists. Please choose a different name.")
				return False

		return True