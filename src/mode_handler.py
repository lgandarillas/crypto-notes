"""
src/mode_handler.py

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
from account_manager import AccountManager
from cryptography_utils import derive_key
from ui_utils import show_progress_bar
from note_manager import NoteManager

class ModeHandler:
	"""Handles different operating modes of the application such as register, login, and exit."""

	MODES = {
		"register": "register",
		"login": "login",
		"exit": "exit"
	}

	def __init__(self, printer, encryption_key):
		self.printer = printer
		self.encryption_key = encryption_key
		self.account_manager = AccountManager(printer, encryption_key)
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
		"""Handles user registration process."""
		self.printer.print_action("You selected register mode")
		username = input("    Enter a new username: ").strip()
		password = pwinput.pwinput("    Enter your password: ", mask='*').strip()
		if self.account_manager.register(username, password):
			self.printer.print_success(f"You successfully registered user: {username}")
		else:
			self.printer.print_error(f"Registration failed for user: {username}")
		return True

	def handle_login(self):
		"""Handle the login process for an existing user."""

		self.printer.print_action("You selected login mode")

		username = input("    Enter your username: ").strip()
		user = self.account_manager.users.get(username)
		if not user:
			self.printer.print_error(f"Login failed: Username '{username}' not found.")
			return True

		password = pwinput.pwinput("    Enter your password: ", mask='*').strip()
		salt = base64.urlsafe_b64decode(user['salt'])
		key = derive_key(password, salt)
		f = Fernet(key)

		try:
			f.decrypt(user['token'].encode())
		except Exception:
			self.printer.print_error(f"Login failed: Incorrect password for user: '{username}'.")
			return True

		otp_input = input("    Ener your 2FA code from Google account_manager: ").strip()
		totp = pyotp.TOTP(user['2fa_secret'])
		if not totp.verify(otp_input):
			self.printer.print_error("Login failed: Invalid 2FA code.")
			return True

		show_progress_bar("Processing login...")
		self.printer.print_success(f"User {username} logged in successfully!")

		note_manager = NoteManager(self.printer, username)
		note_manager.run()

		return True

	def handle_exit(self):
		"""Handle the exit mode, printing the exit message."""
		for user in self.account_manager.users:
			qr_image_file = f"{user}_qrcode.png"
			if os.path.exists(qr_image_file):
				os.remove(qr_image_file)

		self.printer.print_exit_msg()
		return False

	def handle_invalid_mode(self, mode: str):
		"""Handle invalid modes, informing the user of the error."""
		print(f"Invalid mode: {self.printer.COLOR_RED}{mode}{self.printer.COLOR_RESET}\n")
		return True