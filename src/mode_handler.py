"""
src/mode_handler.py

This file contains the mode handler for the program.
By: Luis Gandarillas && Carlos Bravo
"""

import os
import re
import pyotp
import base64
import getpass
import pwinput
import readline
from crypto_utils import CryptoUtils
from print_manager import PrintManager
from note_handler import NoteHandler
from cryptography.fernet import Fernet
from account_manager import AccountManager
from rsa_utils import generate_rsa_keys, save_rsa_keys
from cryptography.hazmat.primitives import serialization

class ModeHandler:
	"""Handles different operating modes of the application such as register, login, and exit."""

	MODES = {
		"register": "register",
		"login": "login",
		"exit": "exit"
	}

	def __init__(self, encryption_key):
		self.setup_readline_history()
		self.printer = PrintManager()
		self.printer.print_welcome_msg()
		self.mode_handlers = {
			self.MODES["register"]: self.handle_register,
			self.MODES["login"]: self.handle_login,
			self.MODES["exit"]: self.handle_exit
		}

		# SIN REVISAR
		self.encryption_key = encryption_key
		self.account_manager = AccountManager(self.printer, encryption_key)
		self.crypto_utils = CryptoUtils(self.printer)

	# OK
	def setup_readline_history(self):
		"""Set up basic readline history for the modes available."""
		for cmd in self.MODES.values():
			readline.add_history(cmd)

	# OK
	def handle_exit(self):
		"""Handle the exit mode, printing the exit message."""
		for user in self.account_manager.users:
			qr_image_file = f"{user}_qrcode.png"
			if os.path.exists(qr_image_file):
				os.remove(qr_image_file)

		self.printer.print_exit_msg()
		exit(0)

	def handle_mode(self) -> bool:
		"""Handle the selected mode by the user (register, login, or exit)."""
		mode = input(f"\nSelect a mode ({self.printer.COLOR_BLUE}register{self.printer.COLOR_RESET}, {self.printer.COLOR_BLUE}login{self.printer.COLOR_RESET}, {self.printer.COLOR_BLUE}exit{self.printer.COLOR_RESET}): ").strip().lower()
		handler = self.mode_handlers.get(mode, lambda: self.handle_invalid_mode(mode))
		return handler()

	def handle_register(self):
		"""Handles user registration process."""
		self.printer.print_action("You selected register mode")
		username = input("	Enter your username: ").strip()

		while True:
			password = pwinput.pwinput("	Enter your password: ", mask='*').strip()
			failed_requirements = self._validate_register_password(password)
			if not failed_requirements:
				break
			else:
				self.printer.print_error("Password must have: " + ", ".join(failed_requirements))

		if self.account_manager.register(username, password):
			self.printer.print_success(f"User {username} registered successfully!")
		else:
			self.printer.print_error(f"Registration failed for user {username}.")

		return True

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

	@staticmethod
	def verify_user(username, account_manager, printer):
		"""Verify the user exists."""
		if username not in account_manager.users:
			printer.print_error(f"Login failed: Username '{username}' not found.")
			return False
		return True

	@staticmethod
	def verify_password(user, password, printer, username, crypto_utils):
		"""Verify if the provided password matches the stored token."""
		salt = base64.urlsafe_b64decode(user['salt'])
		key = crypto_utils.derive_key(password, salt)
		f = Fernet(key)
		try:
			f.decrypt(user['token'].encode())
			return True
		except Exception:
			printer.print_error(f"Login failed: Incorrect password for user '{username}'.")
			return False

	@staticmethod
	def verify_2fa(user, otp_input, printer):
		"""Verify the 2FA code using the user's secret."""
		totp = pyotp.TOTP(user['2fa_secret'])
		if not totp.verify(otp_input):
			printer.print_error("Login failed: Invalid 2FA code.")
			return False
		return True

	def handle_login(self):
		"""Handle the login process for an existing user."""
		self.printer.print_action("You selected login mode")

		username = input("	Enter your username: ").strip()
		if not self._validate_user(username):
			return True

		password = pwinput.pwinput("	Enter your password: ", mask='*').strip()
		if not self._validate_password(username, password):
			return True

		otp_input = pwinput.pwinput("	Enter your 2FA code from Google Authenticator: ", mask='*').strip()
		if not self._validate_2fa(username, otp_input):
			return True

		self.printer.show_progress_bar("Processing login...")
		self.printer.print_success(f"User {username} logged in successfully!")

		private_key, public_key = self._get_rsa_keys(username, password)
		self._launch_note_handler(username, private_key, public_key)

		return True

	def _validate_user(self, username):
		"""Validates if the user exists in the account manager."""
		return self.verify_user(username, self.account_manager, self.printer)

	def _validate_password(self, username, password):
		"""Validates the user's password."""
		user = self.account_manager.users.get(username)
		return self.verify_password(user, password, self.printer, username, self.crypto_utils)

	def _validate_2fa(self, username, otp_input):
		"""Validates the 2FA code provided by the user."""
		user = self.account_manager.users.get(username)
		return self.verify_2fa(user, otp_input, self.printer)

	def _get_rsa_keys(self, username, password):
		"""Retrieves or generates RSA keys for the user."""
		user = self.account_manager.users.get(username)

		if "rsa_private_key" in user and "rsa_public_key" in user:
			return self._load_rsa_keys(user, password)
		else:
			return self._generate_and_store_rsa_keys(username, password, user)

	def _load_rsa_keys(self, user, password):
		"""Loads existing RSA private and public keys for the user."""
		private_key = serialization.load_pem_private_key(
			base64.b64decode(user["rsa_private_key"]),
			password=password.encode()
		)
		public_key = serialization.load_pem_public_key(
			base64.b64decode(user["rsa_public_key"])
		)
		return private_key, public_key

	def _generate_and_store_rsa_keys(self, username, password, user):
		"""Generates and stores RSA private and public keys for the user."""
		private_key, public_key = generate_rsa_keys(self.printer, password)
		save_rsa_keys(self.printer, None, public_key, username)

		user["rsa_private_key"] = base64.b64encode(
			private_key.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.PKCS8,
				encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
			)
		).decode('utf-8')
		user["rsa_public_key"] = base64.b64encode(
			public_key.public_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PublicFormat.SubjectPublicKeyInfo
			)
		).decode('utf-8')
		self.account_manager.save_users()

		return private_key, public_key

	def _launch_note_handler(self, username, private_key, public_key):
		"""Initializes the NoteHandler for managing user notes."""
		note_handler = NoteHandler(self.printer, username, private_key, public_key)
		note_handler.run()

	def handle_invalid_mode(self, mode: str):
		"""Handle invalid modes, informing the user of the error."""
		print(f"Invalid mode: {self.printer.COLOR_RED}{mode}{self.printer.COLOR_RESET}\n")
		return True