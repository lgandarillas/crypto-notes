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

		# Capture the note content
		print(self.printer.apply_color("Enter the note content (press Ctrl+D to finish):", self.printer.COLOR_BLUE))
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

		# Add the new note to the notes list
		self.notes.append(new_note)
		self.save_notes(self.notes)

		print(self.printer.apply_color(f"Note '{note_name}' has been created.", self.printer.COLOR_GREEN))

	def handle_read_note(self):
		print(self.printer.apply_color("You selected read note mode", self.printer.COLOR_BLUE))

		# Ask for the note name and validate it
		note_name = input("Enter the name of the note you want to read: ").strip()

		# Find the note by name
		note = next((note for note in self.notes if note['name'] == note_name), None)
		if note:
			print(f"Content of '{note_name}':\n{note['content']}")
		else:
			print(self.printer.apply_color(f"Note '{note_name}' not found.", self.printer.COLOR_RED))

	def handle_list_notes(self):
		print(self.printer.apply_color("Your notes available are:", self.printer.COLOR_BLUE))

		# List the note names
		if self.notes:
			for note in self.notes:
				if isinstance(note, dict) and 'name' in note:
					print(self.printer.apply_color(f"- {note['name']}", self.printer.COLOR_BLUE))
				else:
					print(self.printer.apply_color("Invalid note format detected.", self.printer.COLOR_RED))
		else:
			print(self.printer.apply_color("No notes found.", self.printer.COLOR_RED))

	def handle_delete_note(self):
		print(self.printer.apply_color("You selected delete note mode", self.printer.COLOR_BLUE))

		# Ask for the note name
		note_name = input("Enter the name of the note to delete: ").strip()

		# Find the note by name
		note = next((note for note in self.notes if note['name'] == note_name), None)
		if note:
			self.notes.remove(note)
			self.save_notes(self.notes)
			print(self.printer.apply_color(f"Note '{note_name}' has been deleted.", self.printer.COLOR_GREEN))
		else:
			print(self.printer.apply_color(f"Note '{note_name}' not found.", self.printer.COLOR_RED))

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