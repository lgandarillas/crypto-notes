"""
src/handle_user/handle_register.py

Handles the registration process for new users, including the generation of RSA keys,
"""

import re
import pwinput
from print_manager import PrintManager
from account_manager import AccountManager

class UserHandler:

	def __init__(self, account_manager: AccountManager):
		self.printer = PrintManager()
		self.account_manager = account_manager

	def handle_register(self):
		username = self._get_username()
		if username is None:
			return True
		password = self._get_password()
		if password is None:
			return True
		if self.account_manager.register(username, password):
			self.printer.print_success(f"User {username} registered successfully!")
		else:
			self.printer.print_error(f"Registration failed for user {username}.")

		return True

	def _get_username(self):
		"""Prompts the user to enter a username, handling interruption."""
		try:
			return input("    Enter your username: ").strip()
		except KeyboardInterrupt:
			self.printer.print_error("\nRegistration cancelled.")
			return None

	def _get_password(self):
		"""Prompts the user to enter a password with validation, handling interruption."""
		while True:
			try:
				password = pwinput.pwinput("    Enter your password: ", mask='*').strip()
			except KeyboardInterrupt:
				self.printer.print_error("\nRegistration cancelled.")
				return None

			failed_requirements = self._validate_register_password(password)
			if not failed_requirements:
				return password
			else:
				self.printer.print_error("Password must have: " + ", ".join(failed_requirements))

	def _validate_register_password(self, password):
		"""Validate the password requirements."""
		password_requirements = {
			r".{8,}": "at least 8 characters",
			r"[A-Z]": "at least one uppercase letter",
			r"[a-z]": "at least one lowercase letter",
			r"\d": "at least one digit",
			r"[!@#$%^&*()\-_=+\[\]{}|;:'\",.<>/?`~]": "at least one special character"
		}

		failed_requirements = []
		for regex, message in password_requirements.items():
			if not re.search(regex, password):
				failed_requirements.append(message)

		return failed_requirements