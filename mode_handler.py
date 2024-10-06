"""
This file contains the mode handler for the program.
"""

import readline
from authenticator import Authenticator

class ModeHandler:
	MODES = {
		"register": "register",
		"login": "login",
		"exit": "exit"
	}

	def __init__(self, printer):
		self.printer = printer
		self.authenticator = Authenticator(printer)
		self.mode_handlers = {
			self.MODES["register"]: self.handle_register,
			self.MODES["login"]: self.handle_login,
			self.MODES["exit"]: self.handle_exit
		}

	def setup_readline_history(self):
		"""Add basic commands to the readline history."""
		for cmd in self.MODES.values():
			readline.add_history(cmd)

	def handle_mode(self, mode: str) -> bool:
		handler = self.mode_handlers.get(mode, lambda: self.handle_invalid_mode(mode))
		return handler()

	def handle_register(self):
		username = input("Enter your username: ").strip()
		password = input("Enter your password: ").strip()
		if self.authenticator.register(username, password):
			print(f"You selected {self.printer.COLOR_BLUE}register{self.printer.COLOR_RESET}\n")
		return True

	def handle_login(self):
		username = input("Enter your username: ").strip()
		password = input("Enter your password: ").strip()
		if self.authenticator.login(username, password):
			print(f"You selected {self.printer.COLOR_BLUE}login{self.printer.COLOR_RESET}\n")
		return True

	def handle_exit(self):
		self.printer.print_exit_msg()
		return False

	def handle_invalid_mode(self, mode: str):
		print(f"Invalid mode: {self.printer.COLOR_RED}{mode}{self.printer.COLOR_RESET}\n")
		return True