"""
src/handle_notes/note_handler.py

This file contains the main class for handling notes.
"""

import json
from print_manager import PrintManager
from handle_notes.note_actions import NoteActions
from handle_notes.note_file_manager import NoteFileManager
from handle_notes.note_utils import validate_note_name


class NoteHandler:
	"""Manages note-taking functionalities, including creating, reading, listing, and deleting notes."""

	def __init__(self, username, rsa_private_key, rsa_public_key):
		self.printer = PrintManager()
		self.username = username
		self.file_manager = NoteFileManager(username, rsa_private_key, rsa_public_key)

	def run_notes_app(self, is_first_time_login=False):
		"""Runs the note management encryption, allowing the user to choose different note operations."""
		if is_first_time_login:
			self._new_note()
			return

		while True:
			try:
				mode = input(f"\nSelect a mode ({self.printer.COLOR_BLUE}new{self.printer.COLOR_RESET}, "
							 f"{self.printer.COLOR_BLUE}read{self.printer.COLOR_RESET}, "
							 f"{self.printer.COLOR_BLUE}list{self.printer.COLOR_RESET}, "
							 f"{self.printer.COLOR_BLUE}delete{self.printer.COLOR_RESET}, "
							 f"{self.printer.COLOR_BLUE}exit{self.printer.COLOR_RESET}) for user {self.username}: ").strip().lower()

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
		"""Dispatches the action based on the mode chosen by the user."""
		notes = self.file_manager.load_notes()
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
				self.file_manager.save_notes(notes)
		else:
			self.printer.print_error("Invalid mode selected")

	def _new_note(self):
		"""Handles the creation of a new note."""
		self.printer.print_action("You selected new note mode")
		note_name = input("Enter a name for the new note (letters, numbers, underscores only): ").strip()
		notes = self.file_manager.load_notes()

		if not validate_note_name(note_name, notes, self.printer):
			return

		self.printer.print_action("Enter the note content (press Ctrl+D to finish):")
		note_content = []
		while True:
			try:
				line = input()
			except EOFError:
				break
			note_content.append(line)
		notes.append({"name": note_name, "content": "\n".join(note_content)})
		self.file_manager.save_notes(notes)
