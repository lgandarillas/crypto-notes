"""
src/handle_user/login_handler.py

Handles the login process for existing users, including the generation of RSA keys,
"""

import pwinput
import pyotp
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization

class LoginHandler:
	"""Handles the login process for existing users."""

	def __init__(self, account_manager, crypto_utils, printer, note_handler):
		self.account_manager = account_manager
		self.crypto_utils = crypto_utils
		self.printer = printer
		self.note_handler = note_handler

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
		if username not in self.account_manager.users:
			self.printer.print_error(f"Login failed: Username '{username}' not found.")
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
		note_handler = self.note_handler(self.printer, username, private_key, public_key)
		note_handler.run()