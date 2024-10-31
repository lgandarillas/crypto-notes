"""
src/handle_user/login_handler.py
Handles the login process for existing users.
By: Luis Gandarillas && Carlos Bravo
"""

import pwinput
import pyotp
import base64
from print_manager import PrintManager
from cryptography.hazmat.primitives import serialization
from rsa_utils import generate_rsa_keys, save_rsa_keys
from note_handler import NoteHandler

class LoginHandler:
	def __init__(self, user_manager):
		self.user_manager = user_manager
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
		NoteHandler(self.printer, username, private_key, public_key).run()
		return True

	def _validate_user(self, username):
		if username not in self.user_manager.users:
			self.printer.print_error(f"Login failed: Username '{username}' not found.")
			return False
		return True

	def _validate_password(self, username, password):
		if password != self.user_manager.users.get(username, {}).get('password'):
			self.printer.print_error("Incorrect password.")
			return False
		return True

	def _validate_2fa(self, username, otp_input):
		totp = pyotp.TOTP(self.user_manager.users[username]['2fa_secret'])
		if not totp.verify(otp_input):
			self.printer.print_error("Invalid 2FA code.")
			return False
		return True

	def _get_rsa_keys(self, username, password):
		"""Retrieve the user's RSA keys, generating them if they do not exist."""
		user = self.user_manager.users.get(username)

		if "rsa_private_key" in user and "rsa_public_key" in user:
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
		else:
			# Generate and store new RSA keys if they don't exist
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
			self.user_manager.save_users()

			return private_key, public_key