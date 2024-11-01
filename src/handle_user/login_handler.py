"""
src/handle_user/login_handler.py
Handles the login process for existing users.
By: Luis Gandarillas && Carlos Bravo
"""

import pyotp
import base64
import pwinput
from note_handler import NoteHandler
from print_manager import PrintManager
from rsa_utils import generate_rsa_keys, save_rsa_keys
from cryptography.hazmat.primitives import serialization

class LoginHandler:
	def __init__(self, users):
		self.users = users
		self.printer = PrintManager()

	def handle_login(self):
		"""Handle the login process for an existing user."""

		username = input("Enter your username: ").strip()
		if not self._validate_user(username):
			return False

		password = pwinput.pwinput("Enter your password: ", mask='*').strip()
		if not self._validate_password(username, password):
			return False

		otp_input = pwinput.pwinput("Enter your 2FA code: ", mask='*').strip()
		if not self._validate_2fa(username, otp_input):
			return False

		private_key, public_key = self._get_rsa_keys(username, password)
		if private_key is None or public_key is None:
			self.printer.print_error("Failed to retrieve RSA keys.")
			return False

		NoteHandler(username, private_key, public_key).run()

		return True

	def _validate_user(self, username):
		"""Validate that the user exists."""
		if username not in self.users:
			self.printer.print_error(f"Login failed: Username '{username}' not found.")
			return False
		return True

	def _validate_password(self, username, password):
		"""Validate the user's password."""
		if password != self.users.get(username, {}).get('password'):
			self.printer.print_error("Incorrect password.")
			return False
		return True

	def _validate_2fa(self, username, otp_input):
		"""Validate the user's 2FA code."""
		totp = pyotp.TOTP(self.users[username]['2fa_secret'])
		if not totp.verify(otp_input):
			self.printer.print_error("Invalid 2FA code.")
			return False
		return True

	def _get_rsa_keys(self, username, password):
		"""Retrieve or generate the user's RSA keys."""
		user = self.users.get(username)

		if "rsa_private_key" in user and "rsa_public_key" in user:
			return self._load_rsa_keys(user, password)
		else:
			return self._generate_and_save_rsa_keys(user, username, password)

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