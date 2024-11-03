"""
src/handle_user/login_handler.py

Handles the login process for existing users.
By: Luis Gandarillas && Carlos Bravo
"""

import pyotp
import base64
import pwinput
from print_manager import PrintManager
from handle_notes.note_handler import NoteHandler
from handle_user.rsa_utils import generate_rsa_keys, save_rsa_keys
from cryptography.hazmat.primitives import serialization
from handle_user.access_crypto_utils import UserCrypto

class LoginHandler:
	def __init__(self, users):
		self.users = users
		self.printer = PrintManager()
		self.user_crypto = UserCrypto()

	def handle_login(self):
		"""Handle the login process for an existing user."""

		username = self._get_username()
		if username is None:
			return False

		password = self._get_password(username)
		if password is None:
			return False

		if not self._validate_2fa(username):
			return False

		private_key, public_key = self._get_rsa_keys(username, password)
		if private_key is None or public_key is None:
			self.printer.print_error("Failed to retrieve RSA keys.")
			return False

		NoteHandler(username, private_key, public_key).run_notes_app()

		return True

	def _get_username(self):
		"""Prompt the user for a username and validate its existence with Ctrl+C handling."""
		while True:
			try:
				username = input("Enter your username: ").strip()
				if username not in self.users:
					self.printer.print_error(f"Login failed: Username '{username}' not found.")
					cancel = input("Do you want to cancel login? (y/n): ").strip().lower()
					if cancel == 'y':
						self.printer.print_error("Login cancelled.")
						return None
				else:
					return username
			except KeyboardInterrupt:
				self.printer.print_error("\nLogin cancelled.")
				return None

	def _get_password(self, username):
		"""Prompt for and validate the user's password with an option to cancel."""
		while True:
			password = pwinput.pwinput("Enter your password: ", mask='*').strip()
			salt = bytes.fromhex(self.users[username]['salt'])
			expected_token = self.users[username]['token']

			token = self.user_crypto.generate_token(salt, password).decode()

			if token == expected_token:
				return password
			else:
				self.printer.print_error("Incorrect password.")
				retry = input("Do you want to try again? (y/n): ").strip().lower()
				if retry == 'n':
					self.printer.print_error("Login cancelled.")
					return None

	def _validate_2fa(self, username):
		"""Validate the user's 2FA code with retry/cancel option only."""
		while True:
			otp_input = pwinput.pwinput("Enter your 2FA code: ", mask='*').strip()
			if otp_input == "":
				cancel = input("Do you want to cancel login? (y/n): ").strip().lower()
				if cancel == 'y':
					self.printer.print_error("Login cancelled.")
					return False

			totp = pyotp.TOTP(self.users[username]['2fa_secret'])
			if totp.verify(otp_input):
				return True
			else:
				self.printer.print_error("Invalid 2FA code.")
				retry = input("Do you want to try again? (y/n): ").strip().lower()
				if retry == 'n':
					self.printer.print_error("Login cancelled.")
					return False

	def _get_rsa_keys(self, username, password):
		"""Retrieve or generate the user's RSA keys."""
		try:
			with open(f"data/keys/{username}/{username}_private_key.pem", 'rb') as priv_file:
				private_key = serialization.load_pem_private_key(
					priv_file.read(),
					password=password.encode()
				)

			with open(f"data/keys/public/{username}_public_key.pem", 'rb') as pub_file:
				public_key = serialization.load_pem_public_key(
					pub_file.read()
				)
			return private_key, public_key
		except Exception as e:
			self.printer.print_error(f"Failed to load RSA keys for {username}: {e}")
			return None, None

	def _load_rsa_keys(self, user, password):
		"""Load existing RSA keys for the user."""
		try:
			private_key = serialization.load_pem_private_key(
				base64.b64decode(user["rsa_private_key"]),
				password=password.encode()
			)
			public_key = serialization.load_pem_public_key(
				base64.b64decode(user["rsa_public_key"])
			)
			return private_key, public_key
		except Exception as e:
			self.printer.print_error(f"Failed to load RSA keys: {e}")
			return None, None

	def _generate_and_save_rsa_keys(self, user, username, password):
		"""Generate new RSA keys, encode, and save them for the user."""
		private_key, public_key = generate_rsa_keys(self.printer, password)
		user["rsa_private_key"] = self._encode_private_key(private_key, password)
		user["rsa_public_key"] = self._encode_public_key(public_key)
		save_rsa_keys(self.printer, None, public_key, username)
		save_users(self.users)
		return private_key, public_key

	def _encode_private_key(self, private_key, password):
		"""Encode the private key to base64 PEM format."""
		return base64.b64encode(
			private_key.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.PKCS8,
				encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
			)
		).decode('utf-8')

	def _encode_public_key(self, public_key):
		"""Encode the public key to base64 PEM format."""
		return base64.b64encode(
			public_key.public_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PublicFormat.SubjectPublicKeyInfo
			)
		).decode('utf-8')