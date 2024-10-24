"""
src/note_manager.py
This file contains the note manager for the program.
"""

import json
import os
import re

class NoteManager:
	MODES = {
		"new": "new",
		"read": "read",
		"list": "list",
		"delete": "delete",
		"exit": "exit"
	}

	def __init__(self, printer, username):
		self.printer = printer
		self.username = username
		self.notes_file = f"data/notes_{username}.json"
		self.notes = self.load_notes()
		self.note_handlers = {
			self.MODES["new"]: self.handle_new_note,
			self.MODES["read"]: self.handle_read_note,
			self.MODES["list"]: self.handle_list_notes,
			self.MODES["delete"]: self.handle_delete_note,
			self.MODES["exit"]: self.handle_exit
		}

	def load_notes(self):
		if os.path.exists(self.notes_file):
			with open(self.notes_file, 'rb') as file:
				try:
					return json.load(file)
				except json.JSONDecodeError:
					return []
		else:
			self.save_notes([])
			return []

	def save_notes(self, notes):
		with open(self.notes_file, 'w') as file:
			json.dump(notes, file, indent=4)

	def handle_new_note(self):
		print(self.printer.apply_color("You selected new note mode", self.printer.COLOR_BLUE))

		# Ask for the note name and validate it
		note_name = input("Enter a name for the new note (letters, numbers, underscores only): ").strip()
		if not re.match(r'^\w+$', note_name):
			print(self.printer.apply_color("Invalid note name. Only letters, numbers, and underscores are allowed.", self.printer.COLOR_RED))
			return

		# Verify if the note name already exists
		if note_name in self.notes:
			print(self.printer.apply_color(f"Note '{note_name}' already exists. Please choose a different name.", self.printer.COLOR_RED))
			return

		# Add the new note to the notes list
		self.notes.append(note_name)
		self.save_notes(self.notes)

		print(self.printer.apply_color(f"Note '{note_name}' has been created.", self.printer.COLOR_GREEN))

	def handle_read_note(self):
		print(self.printer.apply_color("You selected read note mode", self.printer.COLOR_BLUE))
		return True

	def handle_list_notes(self):
		print(self.printer.apply_color("Your notes available are:", self.printer.COLOR_BLUE))

		# List the note names
		if self.notes:
			for note in self.notes:
				print(self.printer.apply_color(f"- {note}", self.printer.COLOR_BLUE))
		else:
			print(self.printer.apply_color("No notes found.", self.printer.COLOR_RED))

	def handle_delete_note(self):
		print(self.printer.apply_color("You selected delete note mode", self.printer.COLOR_BLUE))
		return True

	def handle_exit(self):
		print(self.printer.apply_color("Exiting notes manager", self.printer.COLOR_RED))
		return False

	def run(self):
		while True:
			try:
				mode = input(f"Select a mode ({self.printer.COLOR_BLUE}new{self.printer.COLOR_RESET}, "f"{self.printer.COLOR_BLUE}read{self.printer.COLOR_RESET}, "f"{self.printer.COLOR_BLUE}list{self.printer.COLOR_RESET}, "f"{self.printer.COLOR_BLUE}delete{self.printer.COLOR_RESET}, "f"{self.printer.COLOR_BLUE}exit{self.printer.COLOR_RESET}) for user {self.username}: ").strip().lower()
				if mode == "exit":
					print(self.printer.apply_color("Exiting notes manager", self.printer.COLOR_RED))
					break
				else:
					self.handle_mode(mode)
			except KeyboardInterrupt:
				print("^C")
				break

	def handle_mode(self, mode):
		handler = self.note_handlers.get(mode, self.handle_invalid_mode)
		return handler()

	def handle_invalid_mode(self):
		print(self.printer.apply_color("Invalid mode selected", self.printer.COLOR_RED))
		return True