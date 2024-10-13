"""
This file contains the note manager for the program.
"""

class NoteManager:
	MODES = {
		"new": "new",
		"existent": "existent",
		"list": "list",
		"exit": "exit"
	}

	def __init__(self, printer, username):
		self.printer = printer
		self.username = username
		self.note_handlers = {
			self.MODES["new"]: self.handle_new_note,
			self.MODES["existent"]: self.handle_existent_note,
			self.MODES["list"]: self.handle_list_notes,
			self.MODES["exit"]: self.handle_exit
		}

	def run(self):
		while True:
			try:
				mode = input(f"Select a mode ({self.printer.COLOR_BLUE}new{self.printer.COLOR_RESET}, {self.printer.COLOR_BLUE}existent{self.printer.COLOR_RESET}, {self.printer.COLOR_BLUE}list{self.printer.COLOR_RESET}, {self.printer.COLOR_BLUE}exit{self.printer.COLOR_RESET}): ").strip().lower()
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

	def handle_existent_note(self):
		print(self.printer.apply_color("You selected existent note mode", self.printer.COLOR_BLUE))
		return True

	def handle_list_notes(self):
		print(self.printer.apply_color("You selected list notes mode", self.printer.COLOR_BLUE))
		return True

	def handle_exit(self):
		print(self.printer.apply_color("Exiting notes manager", self.printer.COLOR_RED))
		return False

	def handle_invalid_mode(self):
		print(self.printer.apply_color("Invalid mode selected", self.printer.COLOR_RED))
		return True