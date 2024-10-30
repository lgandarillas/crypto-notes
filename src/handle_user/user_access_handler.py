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
from crypto_utils import CryptoUtils
from print_manager import PrintManager
from note_handler import NoteHandler
from cryptography.fernet import Fernet
from account_manager import AccountManager
from rsa_utils import generate_rsa_keys, save_rsa_keys
from cryptography.hazmat.primitives import serialization

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
			return self.handle_login()
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

######################################################

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

######################################################

	def _validate_user(self, username):
		"""Validates if the user exists in the account manager."""
		if username not in self.account_manager.users:
			printer.print_error(f"Login failed: Username '{username}' not found.")
			return False
		return True

	def _validate_password(self, username, password):
		"""Validates the user's password."""
		user = self.account_manager.users.get(username)
		if user is None:
			self.printer.print_error(f"Login failed: Username '{username}' not found.")
			return False

		salt = base64.urlsafe_b64decode(user['salt'])
		key = self.crypto_utils.derive_key(password, salt)
		f = Fernet(key)
		try:
			f.decrypt(user['token'].encode())
			return True
		except Exception:
			self.printer.print_error(f"Login failed: Incorrect password for user '{username}'.")
			return False

	def _validate_2fa(self, username, otp_input):
		"""Validates the 2FA code provided by the user."""
		user = self.account_manager.users.get(username)
		if user is None:
			self.printer.print_error(f"Login failed: Username '{username}' not found.")
			return False

		totp = pyotp.TOTP(user['2fa_secret'])
		if not totp.verify(otp_input):
			self.printer.print_error("Login failed: Invalid 2FA code.")
			return False
		return True

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