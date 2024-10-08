"""
This file contains the mode handler for the program.
"""

import readline
import os
import re
import base64
import pyotp
import getpass
import pwinput
from cryptography.fernet import Fernet
from src.authenticator import Authenticator
from src.utils import derive_key

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
		username = input("    Enter a new username: ").strip()
		password = pwinput.pwinput("    Enter your password: ", mask='*').strip()
		email = input("    Enter your email: ").strip()
		if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
			print(self.printer.apply_color("Invalid email format. Please enter a valid email.", self.printer.COLOR_RED))
			return True
		if self.authenticator.register(username, password):
			print(self.printer.apply_color(f"You successfully registered user: {username}", self.printer.COLOR_GREEN))
		else:
			print(self.printer.apply_color(f"Registration failed for user: {username}", self.printer.COLOR_RED))
		return True

	def handle_login(self):
		"""Handle the login process for an existing user."""

		print(self.printer.apply_color("You selected login mode", self.printer.COLOR_BLUE))

		username = input("    Enter your username: ").strip()
		user = self.authenticator.users.get(username)
		if not user:
			print(self.printer.apply_color(f"Login failed: Username '{username}' not found.", self.printer.COLOR_RED))
			return True

		password = pwinput.pwinput("    Enter your password: ", mask='*').strip()
		salt = base64.urlsafe_b64decode(user['salt'])
		key = derive_key(password, salt)
		f = Fernet(key)
		try:
			f.decrypt(user['token'].encode())
		except Exception:
			print(self.printer.apply_color("Login failed: Incorrect password.", self.printer.COLOR_RED))
			return True

		otp_input = input("    Ener your 2FA code from Google Authenticator: ").strip()
		totp = pyotp.TOTP(user['2fa_secret'])
		if not totp.verify(otp_input):
			print(self.printer.apply_color("Login failed: Invalid 2FA code.", self.printer.COLOR_RED))
			return True

		print(self.printer.apply_color(f"User {username} logged in successfully", self.printer.COLOR_GREEN))
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