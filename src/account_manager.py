"""
src/account_manager.py

Handles the management of user accounts, including registration and login processes,
leveraging cryptographic utilities for secure password handling and user data encryption.
"""

import os
import json
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography_utils import generate_salt, derive_key
from two_factor_auth import generate_2fa_secret, get_qr_code, open_qr_in_default_viewer

DATABASE_FILE = 'data/users.json'

class AccountManager:
	"""Manages user accounts, including registration, login, and data encryption."""

	def __init__(self, printer, encryption_key):
		self.printer = printer
		self.encryption_key = encryption_key
		self.users = self.load_users()

	def get_encryption_key(self):
		salt = b'salt_for_file_encryption'
		return derive_key(self.encryption_key, salt)

	def load_users(self):
		"""Loads user data from a file, decrypts it, and returns it as a dictionary."""
		if not os.path.exists(DATABASE_FILE):
			return {}

		with open(DATABASE_FILE, 'rb') as file:
			encrypted_data = file.read()
			try:
				decryptor = Fernet(self.get_encryption_key())
				decrypted_data = decryptor.decrypt(encrypted_data)
				return json.loads(decrypted_data.decode())
			except Exception as e:
				self.printer.print_error(f"Failed to load users: {e}")
				return {}

	def save_users(self):
		"""Encrypts and saves the current user data to a file."""
		f = Fernet(self.get_encryption_key())
		encrypted_data = f.encrypt(json.dumps(self.users).encode())
		with open(DATABASE_FILE, 'wb') as file:
			file.write(encrypted_data)

	def register(self, username, password):
		"""Registers a new user with a username and password, encrypts their data, and handles 2FA setup."""
		if username in self.users:
			self.printer.apply_color(f"Registration failed: Username '{username}' already exists.", self.printer.COLOR_RED)
			return False

		salt = generate_salt()
		key = derive_key(password, salt)
		f = Fernet(key)
		token = f.encrypt(password.encode())
		secret = generate_2fa_secret()

		self.users[username] = {
			'salt': base64.urlsafe_b64encode(salt).decode(),
			'token': token.decode(),
			'2fa_secret': secret
		}
		self.save_users()

		qr_code_image = get_qr_code(username, secret)
		qr_image_file = f"{username}_qrcode.png"
		with open(qr_image_file, 'wb') as qr_file:
			qr_file.write(qr_code_image)

		open_qr_in_default_viewer(qr_image_file, self.printer)
		self.printer.apply_color(f"Registration successful for user: {username}", self.printer.COLOR_GREEN)
		return True

	def login(self, username, password, otp_input):
		"""Attempts to log in a user with the given username, password, and 2FA code."""
		user = self.users.get(username)
		if not user:
			self.printer.apply_color(f"Login failed: Username '{username}' not found.", self.printer.COLOR_RED)
			return False

		salt = base64.urlsafe_b64decode(user['salt'])
		stored_token = user['token']
		key = derive_key(password, salt)
		f = Fernet(key)

		try:
			f.decrypt(stored_token.encode())

			totp = pyotp.TOTP(user['2fa_secret'])
			if not totp.verify(otp_input):
				self.printer.apply_color("Login failed: Invalid 2FA code.", self.printer.COLOR_RED)
				return False

			self.printer.apply_color(f"Login successful for user: {username}!", self.printer.COLOR_GREEN)
			return True
		except Exception:
			self.printer.apply_color(f"Login failed: Incorrect password for user '{username}'.", self.printer.COLOR_RED)
			return False