"""
src/handle_user/user_access_handler.py

Handles user access modes such as register, login, and exit.
By: Luis Gandarillas && Carlos Bravo
"""

import os
import pwinput
import readline
from note_handler import NoteHandler
from print_manager import PrintManager
from account_manager import AccountManager
from handle_user.login_handler import LoginHandler
from handle_user.register_handler import RegisterHandler

class UserAccessHandler:
	"""Handles user access modes such as register, login, and exit."""

	def __init__(self):
		self._setup_readline_history()
		self.printer = PrintManager()
		self.printer.print_welcome_msg()
		# REVISAR
		self.account_manager = AccountManager()

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
		self.account_manager.register_handler.handle_register()

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
		login_handler = LoginHandler(self.account_manager, self.crypto_utils, NoteHandler)
		login_handler.handle_login()