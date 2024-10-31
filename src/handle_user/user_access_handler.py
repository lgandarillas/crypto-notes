"""
src/handle_user/user_access_handler.py

Handles user access modes such as register, login, and exit.
By: Luis Gandarillas && Carlos Bravo
"""

import os
import pyotp
import base64
import pwinput
import readline
from handle_user.register_handler import UserHandler
from handle_user.login_handler import LoginHandler
from crypto_utils import CryptoUtils
from print_manager import PrintManager
from note_handler import NoteHandler
from cryptography.fernet import Fernet
from account_manager import AccountManager
from rsa_utils import generate_rsa_keys, save_rsa_keys

class UserAccessHandler:
	"""Handles user access modes such as register, login, and exit."""

	def __init__(self):
		self._setup_readline_history()
		self.printer = PrintManager()
		self.printer.print_welcome_msg()

		# SIN REVISAR
		self.account_manager = AccountManager()
		self.crypto_utils = CryptoUtils()

	def _setup_readline_history(self):
		"""Set up basic readline history for the modes available."""
		MODES = ["register", "login", "exit"]
		for mode in MODES:
			readline.add_history(mode)

	def handle_mode(self) -> bool:
		"""Handle the selected mode by the user (register, login, or exit)."""
		mode = input(f"\nSelect a mode ({self.printer.COLOR_BLUE}register{self.printer.COLOR_RESET}, {self.printer.COLOR_BLUE}login{self.printer.COLOR_RESET}, {self.printer.COLOR_BLUE}exit{self.printer.COLOR_RESET}): ").strip().lower()
		if mode == "register":
			return self._handle_register()
		elif mode == "login":
			return self._handle_login()
		elif mode == "exit":
			return self._handle_exit()
		else:
			return self._handle_invalid_mode(mode)

	def _handle_register(self):
		"""Handles user registration process."""
		self.printer.print_action("You selected register mode")
		register_handler = UserHandler(self.account_manager)
		register_handler.handle_register()

	def _handle_exit(self):
		"""Handle the exit mode, printing the exit message."""
		for user in self.account_manager.users:
			qr_image_file = f"{user}_qrcode.png"
			if os.path.exists(qr_image_file):
				os.remove(qr_image_file)

		self.printer.print_exit_msg()
		exit(0)

	def _handle_invalid_mode(self, mode: str):
		"""Handle invalid modes, informing the user of the error."""
		print(f"Invalid mode: {self.printer.COLOR_RED}{mode}{self.printer.COLOR_RESET}\n")
		return True

	def _handle_login(self):
		"""Initiates login process using LoginHandler."""
		login_handler = LoginHandler(self.account_manager, self.crypto_utils, self.printer, NoteHandler)
		login_handler.handle_login()