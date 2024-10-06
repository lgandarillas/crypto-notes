"""
This file contains the mode handler for the program.
"""

import readline
import os
from authenticator import Authenticator

class ModeHandler:
	MODES = {
		"register": "register",
		"login": "login",
		"exit": "exit"
	}

	def __init__(self, printer):
		"""Initialize the ModeHandler with a printer and the available modes."""
		self.printer = printer
		self.authenticator = Authenticator(printer)
		self.mode_handlers = {
			self.MODES["register"]: self.handle_register,
			self.MODES["login"]: self.handle_login,
			self.MODES["exit"]: self.handle_exit
		}

	def setup_readline_history(self):
		"""Set up basic readline history for the modes available."""
		for cmd in self.MODES.values():
			readline.add_history(cmd)

	def handle_mode(self, mode: str) -> bool:
		"""Handle the selected mode by the user (register, login, or exit)."""
		handler = self.mode_handlers.get(mode, lambda: self.handle_invalid_mode(mode))
		return handler()

	def handle_register(self):
		"""Handle the registration process for a new user."""
		print(self.printer.apply_color("You selected register mode", self.printer.COLOR_BLUE))
		username = input("    Enter your username: ").strip()
		password = input("    Enter your password: ").strip()
		email = input("    Enter your email: ").strip()
		if self.authenticator.register(username, password):
			print(self.printer.apply_color(f"You successfully registered user: {username}", self.printer.COLOR_GREEN))
		else:
			print(self.printer.apply_color(f"Registration failed for user: {username}", self.printer.COLOR_RED))
		return True

	def handle_login(self):
		"""Handle the login process for an existing user."""
		print(self.printer.apply_color("You selected login mode", self.printer.COLOR_BLUE))
		username = input("    Enter your username: ").strip()
		password = input("    Enter your password: ").strip()
		otp_input = input("    Ener your 2FA code from Google Authenticator: ").strip()
		if self.authenticator.login(username, password, otp_input):
			print(self.printer.apply_color(f"User {username} logged in successfully", self.printer.COLOR_GREEN))
		else:
			print(self.printer.apply_color(f"Failed to login user: {username}", self.printer.COLOR_RED))
		return True

	def handle_exit(self):
		"""Handle the exit mode, printing the exit message."""
		for user in self.authenticator.users:
			qr_image_file = f"{user}_qrcode.png"
			if os.path.exists(qr_image_file):
				os.remove(qr_image_file)

		self.printer.print_exit_msg()
		return False

	def handle_invalid_mode(self, mode: str):
		"""Handle invalid modes, informing the user of the error."""
		print(f"Invalid mode: {self.printer.COLOR_RED}{mode}{self.printer.COLOR_RESET}\n")
		return True