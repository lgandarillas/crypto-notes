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
		print(self.printer.apply_color("You selected register mode", self.printer.COLOR_BLUE))
		username = input("Enter your username: ").strip()
		password = input("Enter your password: ").strip()
		if self.authenticator.register(username, password):
			print(self.printer.apply_color(f"You successfully registered user: {username}", self.printer.COLOR_GREEN))
		else:
			print(self.printer.apply_color(f"Registration failed for user: {username}", self.printer.COLOR_RED))
		return True

	def handle_login(self):
		print(self.printer.apply_color("You selected login mode", self.printer.COLOR_BLUE))
		username = input("Enter your username: ").strip()
		password = input("Enter your password: ").strip()
		if self.authenticator.login(username, password):
			print(self.printer.apply_color(f"User {username} logged in successfully", self.printer.COLOR_GREEN))
		else:
			print(self.printer.apply_color(f"Failed to login user: {username}", self.printer.COLOR_RED))
		return True

	def handle_exit(self):
		self.printer.print_exit_msg()
		return False

	def handle_invalid_mode(self, mode: str):
		print(f"Invalid mode: {self.printer.COLOR_RED}{mode}{self.printer.COLOR_RESET}\n")
		return True