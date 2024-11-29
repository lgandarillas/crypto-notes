"""
src/handle_user/access_handler.py

Handles user access modes such as register, login, and exit.
By: Luis Gandarillas && Carlos Bravo
"""

import os
import readline
from print_manager import PrintManager
from handle_user.login_handler import LoginHandler
from handle_user.access_crypto_utils import UserCrypto
from handle_user.register_handler import RegisterHandler

class AccessHandler:
	"""Handles user access modes such as register, login, and exit."""

	def __init__(self):
		self._setup_readline_history()
		self.printer = PrintManager()
		self.printer.print_welcome_msg()
		self.user_crypto = UserCrypto()
		self.users = self.user_crypto.load_users()
		self.register_handler = RegisterHandler()
		self.login_handler = LoginHandler(self.users)

	def handle_access(self) -> bool:
		"""Handle the selected mode by the user (register, login, or exit)."""

		mode = input(f"\nSelect a mode ({self.printer.COLOR_BLUE}register{self.printer.COLOR_RESET}, "
					 f"{self.printer.COLOR_BLUE}login{self.printer.COLOR_RESET}, "
					 f"{self.printer.COLOR_BLUE}exit{self.printer.COLOR_RESET}): ").strip().lower()

		if mode == "register":
			if self.register_handler.handle_register():
				self.users = self.user_crypto.load_users()
				self.login_handler.users = self.users
		elif mode == "login":
			return self.login_handler.handle_login()
		elif mode == "exit":
			return self._handle_exit()
		else:
			return self._handle_invalid_mode(mode)

	def _setup_readline_history(self):
		"""Set up basic readline history for the modes available."""
		MODES = ["register", "login", "exit"]
		for mode in MODES:
			readline.add_history(mode)

	def _handle_exit(self):
		"""Handle the exit mode, printing the exit message."""
		for user in self.users:
			qr_image_file = f"data/{user}_qrcode.png"
			if os.path.exists(qr_image_file):
				os.remove(qr_image_file)
		self.printer.print_exit_msg()
		exit(0)

	def _handle_invalid_mode(self, mode: str):
		"""Handle invalid modes, informing the user of the error."""
		print(f"Invalid mode: {self.printer.COLOR_RED}{mode}{self.printer.COLOR_RESET}\n")
		return True