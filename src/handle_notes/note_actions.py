"""
src/handle_notes/note_actions.py

This file contains the note actions for the program.
By: Luis Gandarillas && Carlos Bravo
"""

from print_manager import PrintManager

class NoteActions:
	"""Class to manage all note-taking functionalities like creating, reading, listing, and deleting notes."""

	def __init__(self, notes, printer):
		self.notes = notes
		self.printer = printer

	def read(self, note_name):
		"""Handles reading a note by name, displaying its content if found."""
		self.printer.print_action("You selected read note mode")
		found_note = next((note for note in self.notes if note['name'] == note_name), None)
		if found_note:
			print(f"Content of '{note_name}':\n{found_note['content']}")
		else:
			self.printer.print_error(f"Note '{note_name}' not found.")

	def create(self, note_name, note_content):
		"""Handles the creation of a new note."""
		new_note = {"name": note_name, "content": note_content}
		self.notes.append(new_note)
		self.printer.print_success(f"Note '{note_name}' has been created.")
		return new_note

	def list(self):
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

	def delete(self, note_name):
		"""Deletes a note by name if it exists."""
		note = next((note for note in self.notes if note['name'] == note_name), None)
		if note:
			self.notes.remove(note)
			self.printer.print_success(f"Note '{note_name}' has been deleted.")
			return True
		else:
			self.printer.print_error(f"Note '{note_name}' not found.")
			return False