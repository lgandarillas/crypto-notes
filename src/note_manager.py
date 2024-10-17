"""
src/note_manager.py
This file contains the note manager for the program.
"""

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
		self.note_handlers = {
			self.MODES["new"]: self.handle_new_note,
			self.MODES["read"]: self.handle_read_note,
			self.MODES["list"]: self.handle_list_notes,
			self.MODES["delete"]: self.handle_delete_note,
			self.MODES["exit"]: self.handle_exit
		}

	def run(self):
		while True:
			try:
				mode = input(f"Select a mode ({self.printer.COLOR_BLUE}new{self.printer.COLOR_RESET}, "f"{self.printer.COLOR_BLUE}read{self.printer.COLOR_RESET}, "f"{self.printer.COLOR_BLUE}list{self.printer.COLOR_RESET}, "f"{self.printer.COLOR_BLUE}delete{self.printer.COLOR_RESET}, "f"{self.printer.COLOR_BLUE}exit{self.printer.COLOR_RESET}) for user {self.username}: ").strip().lower()
				if not self.handle_mode(mode):
					break
			except KeyboardInterrupt:
				print("^C")
				break

	def handle_mode(self, mode: str) -> bool:
		handler = self.note_handlers.get(mode, self.handle_invalid_mode)
		return handler()

	def handle_new_note(self):
		print(self.printer.apply_color("You selected new note mode", self.printer.COLOR_BLUE))
		return True

	def handle_read_note(self):
		print(self.printer.apply_color("You selected read note mode", self.printer.COLOR_BLUE))
		return True

	def handle_list_notes(self):
		print(self.printer.apply_color("You selected list notes mode", self.printer.COLOR_BLUE))
		return True

	def handle_delete_note(self):
		print(self.printer.apply_color("You selected delete note mode", self.printer.COLOR_BLUE))
		return True

	def handle_exit(self):
		print(self.printer.apply_color("Exiting notes manager", self.printer.COLOR_RED))
		return False

	def handle_invalid_mode(self):
		print(self.printer.apply_color("Invalid mode selected", self.printer.COLOR_RED))
		return True