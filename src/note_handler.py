"""
src/note_handler.py

This file contains the note manager for the program.
By: Luis Gandarillas && Carlos Bravo
"""

import os
import re
import json
from print_manager import PrintManager
from note_crypto_utils import encrypt_notes_data, encrypt_session_key, generate_session_key, decrypt_session_key, decrypt_notes_data


class NoteHandler:
	"""Manages note-taking functionalities, including creating, reading, listing, and deleting notes."""

	MODES = {
		"new": "new",
		"read": "read",
		"list": "list",
		"delete": "delete",
		"exit": "exit"
	}

	def __init__(self, username, rsa_private_key, rsa_public_key):
		self.printer = PrintManager()
		self.username = username
		self.rsa_private_key = rsa_private_key
		self.rsa_public_key = rsa_public_key
		self.notes_dir = "data/notes"
		self.notes_file = f"{self.notes_dir}/notes_{username}.json"
		self.session_key = None
		self.encrypted_session_key = None
		self.notes = self.load_notes()
		self.note_handlers = {
			self.MODES["new"]: self.handle_new_note,
			self.MODES["read"]: self.handle_read_note,
			self.MODES["list"]: self.handle_list_notes,
			self.MODES["delete"]: self.handle_delete_note,
			self.MODES["exit"]: self.handle_exit
		}

	def load_notes(self):
		"""Loads notes from a file associated with the user."""
		printer = PrintManager()
		if not os.path.exists(self.notes_dir):
				os.makedirs(self.notes_dir)

		if not os.path.exists(self.notes_file):
				return []

		try:
				with open(self.notes_file, 'rb') as file:
						encrypted_data = json.load(file)
						self.encrypted_session_key = bytes.fromhex(encrypted_data["encrypted_session_key"])
						nonce = bytes.fromhex(encrypted_data["nonce"])
						ciphertext = bytes.fromhex(encrypted_data["ciphertext"])
						aad = bytes.fromhex(encrypted_data["aad"])
						self.session_key = decrypt_session_key(self.rsa_private_key, self.encrypted_session_key)
						return decrypt_notes_data(nonce, self.session_key, aad, ciphertext)
		except ValueError as e:
				printer.print_error("[SECURITY ALERT] Possible data tampering detected. Exiting program.")
				exit(1)
		except Exception as e:
				printer.print_error(f"[SECURITY ALERT] Failed to load notes {e}")
				exit(1)

	def save_notes(self, notes):
		"""Saves the current list of notes to the user's file."""
		printer = PrintManager()

		if self.notes:
			if not self.session_key:
				self.session_key = generate_session_key()
				self.printer.print_debug("[CRYPTO LOG] Session key generated; ChaCha20Poly1305, 256 bits")

			nonce, ciphertext, aad = encrypt_notes_data(self.notes, self.session_key)
			self.printer.print_debug("[CRYPTO LOG] Notes data encrypted; ChaCha20Poly1305 with nonce, AAD for integrity")

			self.encrypted_session_key = encrypt_session_key(self.rsa_public_key, self.session_key)
			self.printer.print_debug("[CRYPTO LOG] Session key encrypted with RSA public key; RSA, 2048 bits")

			encrypted_data = {
				"nonce": nonce.hex(),
				"encrypted_session_key": self.encrypted_session_key.hex(),
				"aad": aad.hex(),
				"ciphertext": ciphertext.hex()
			}
			with open(self.notes_file, 'w') as file:
				json.dump(encrypted_data, file, indent=4)
				self.printer.print_debug("[CRYPTO LOG] Encrypted notes data saved to file; JSON format")

	def handle_exit(self):
		"""Handles the exit process from the note manager."""
		self.save_notes()
		self.printer.print_action("Exiting notes manager")
		return False

	@staticmethod
	def validate_note_name(note_name, notes, printer):
		"""Validates the note name and checks if it already exists."""
		if not re.match(r'^\w+$', note_name):
			printer.print_error("Invalid note name. Only letters, numbers, and underscores are allowed.")
			return False

		if any(note["name"] == note_name for note in notes):
			printer.print_error(f"Note '{note_name}' already exists. Please choose a different name.")
			return False

		return True

	def handle_new_note(self):
		"""Handles the creation of a new note, including input validation and storage."""

		self.printer.print_action("You selected new note mode")

		note_name = input("Enter a name for the new note (letters, numbers, underscores only): ").strip()
		if not self.validate_note_name(note_name, self.notes, self.printer):
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
		new_note = {
			"name": note_name,
			"content": note_content
		}

		self.notes.append(new_note)
		self.save_notes(self.notes)

		self.printer.print_success(f"Note '{note_name}' has been created.")

	def handle_read_note(self):
		"""Handles reading a note by name, displaying its content if found."""

		self.printer.print_action("You selected read note mode")

		note_name = input("Enter the name of the note you want to read: ").strip()

		note = next((note for note in self.notes if note['name'] == note_name), None)
		if note:
			print(f"Content of '{note_name}':\n{note['content']}")
		else:
			self.printer.print_error(f"Note '{note_name}' not found.")

	def handle_list_notes(self):
		"""Lists all notes currently stored for the user."""

		self.printer.print_action("Your notes available are:")

		if self.notes:
			for note in self.notes:
				if isinstance(note, dict) and 'name' in note:
					self.printer.print_action(f"- {note['name']}")
				else:
					self.printer.print_error("Invalid note format detected.")
		else:
			self.printer.print_error("No notes found.")

	def handle_delete_note(self):
		"""Deletes a note by name if it exists."""

		self.printer.print_action("You selected delete note mode")

		note_name = input("Enter the name of the note to delete: ").strip()
		note = next((note for note in self.notes if note['name'] == note_name), None)
		if note:
			self.notes.remove(note)
			self.save_notes(self.notes)
			self.printer.print_success(f"Note '{note_name}' has been deleted.")
		else:
			self.printer.print_error(f"Note '{note_name}' not found.")

	def handle_exit(self):
		"""Handles the exit process from the note manager."""
		self.printer.print_action("Exiting notes manager")
		return False

	def run(self, is_first_time_login=False):
		"""Runs the note management session, allowing the user to choose different note operations."""
		if is_first_time_login:
			self.handle_new_note()
		else:
			while True:
				try:
					mode = input(f"\nSelect a mode ({self.printer.COLOR_BLUE}new{self.printer.COLOR_RESET}, {self.printer.COLOR_BLUE}read{self.printer.COLOR_RESET}, {self.printer.COLOR_BLUE}list{self.printer.COLOR_RESET}, {self.printer.COLOR_BLUE}delete{self.printer.COLOR_RESET}, {self.printer.COLOR_BLUE}exit{self.printer.COLOR_RESET}) for user {self.username}: ").strip().lower()
					if mode == "exit":
						self.printer.print_action("Exiting notes manager")
						break
					else:
						self.handle_mode(mode)
				except KeyboardInterrupt:
					print("^C")
					break

	def handle_mode(self, mode):
		"""Dispatches the action based on the mode chosen by the user."""
		handler = self.note_handlers.get(mode, self.handle_invalid_mode)
		return handler()

	def handle_invalid_mode(self):
		"""Informs the user that an invalid mode has been selected."""
		self.printer.print_error("Invalid mode selected")
		return True