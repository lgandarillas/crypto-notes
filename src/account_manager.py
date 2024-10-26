"""
src/account_manager.py

Handles the management of user accounts, including registration and login processes,
leveraging cryptographic utilities for secure password handling and user data encryption.
"""

import os
import json
import base64
from crypto_utils import CryptoUtils
from cryptography.fernet import Fernet
from two_factor_auth import generate_2fa_secret, get_qr_code, open_qr_in_default_viewer

class AccountManager:
	"""Manages user accounts, including registration, login, and data encryption."""

	def __init__(self, printer, encryption_key, database='data/users.json'):
		self.printer = printer
		self.encryption_key = encryption_key
		self.database = database
		self.crypto_utils = CryptoUtils(printer)
		self.users = self.load_users()

	def get_encryption_key(self):
		salt = os.urandom(16)
		return self.crypto_utils.derive_key(self.encryption_key, salt), salt

	def load_users(self):
		if not os.path.exists(self.database):
			with open(self.database, 'wb') as file:
				file.write(b"")
			return {}
		try:
			with open(self.database, 'rb') as file:
				salt = file.read(16)
				if not salt:
					return {}
				encrypted_data = file.read()
				if not encrypted_data:
					return {}
				key = self.crypto_utils.derive_key(self.encryption_key, salt)
				decryptor = Fernet(key)
				decrypted_data = decryptor.decrypt(encrypted_data)
				self.printer.print_debug("[DEBUG] User data decrypted.")
				return json.loads(decrypted_data.decode())
		except Exception as e:
			self.printer.print_error(f"Failed to load users {e}")
			return {}

	def save_users(self):
		key, salt = self.get_encryption_key()
		f = Fernet(key)
		self.printer.print_debug("[DEBUG] Encrypting and saving user data.")
		encrypted_data = f.encrypt(json.dumps(self.users).encode())
		with open(self.database, 'wb') as file:
			file.write(salt)
			file.write(encrypted_data)

	def register(self, username, password):
		"""Registers a new user with a username and password, encrypts their data, and handles 2FA setup."""
		if username in self.users:
			self.printer.print_error(f"Registration failed: Username '{username}' already exists.")
			return False

		salt = self.crypto_utils.generate_salt()
		key = self.crypto_utils.derive_key(password, salt)
		f = Fernet(key)
		token = f.encrypt(password.encode())
		self.printer.print_debug("[DEBUG] User data encrypted for registration.")
		secret = generate_2fa_secret()

		self.users[username] = {
			'salt': base64.urlsafe_b64encode(salt).decode(),
			'token': token.decode(),
			'2fa_secret': secret
		}
		self.save_users()

		qr_code_image = get_qr_code(username, secret, self.printer)
		qr_image_file = f"{username}_qrcode.png"
		with open(qr_image_file, 'wb') as qr_file:
			qr_file.write(qr_code_image)

		open_qr_in_default_viewer(qr_image_file, self.printer)
		return True

	def login(self, username, password, otp_input):
		"""Attempts to log in a user with the given username, password, and 2FA code."""
		user = self.users.get(username)
		if not user:
			self.printer.print_error(f"Login failed: Username '{username}' not found.")
			return False

		salt = base64.urlsafe_b64decode(user['salt'])
		stored_token = user['token']
		key = derive_key(password, salt)
		f = Fernet(key)

		try:
			self.printer.print_debug("[DEBUG] Decrypting token to verify login credentials.")
			f.decrypt(stored_token.encode())
			totp = pyotp.TOTP(user['2fa_secret'])
			if not totp.verify(otp_input):
				self.printer.print_error("Login failed: Invalid 2FA code.")
				return False
			self.printer.print_success(f"Login successful for user: {username}!")
			return True
		except Exception:
			self.printer.print_error(f"Login failed: Incorrect password for user '{username}'.")
			return False