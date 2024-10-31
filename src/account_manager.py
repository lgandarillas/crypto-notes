"""
src/account_manager.py

Handles the management of user accounts, including registration and login processes,
leveraging cryptographic utilities for secure password handling and user data encryption.
By: Luis Gandarillas && Carlos Bravo
"""

import os
import json
import base64
from print_manager import PrintManager
from handle_user.register_handler import RegisterHandler
from rsa_utils import generate_rsa_keys, save_rsa_keys
from two_factor_auth import generate_2fa_secret, get_qr_code, open_qr_image

class AccountManager:
	"""Manages user accounts, including registration, login, and data encryption."""

	def __init__(self, database='data/users.json'):
		self.printer = PrintManager()
		self.database = database
		self.users = self.load_users()
		self.register_handler = RegisterHandler(self)

	def register(self, username, password):
		return self.register_handler.register(username, password)

	def load_users(self):
		"""Load user data from the encrypted database file."""
		if not os.path.exists(self.database):
			with open(self.database, 'w') as file:
				file.write("{}")
			return {}
		try:
			with open(self.database, 'r') as file:
				return json.load(file)
		except Exception as e:
			self.printer.print_error(f"Failed to load users {e}")
			return {}

	def save_users(self):
		"""Encrypt and save user data to the database file."""
		with open(self.database, 'w') as file:
			json.dump(self.users, file, indent=4)

	def register(self, username, password):
		"""Registers a new user with a username and password, encrypts their data, and handles 2FA setup."""
		if username in self.users:
			self.printer.print_error(f"Registration failed: Username '{username}' already exists.")
			return False

		self._initialize_user(username, password)
		self._generate_and_store_rsa_keys(username, password)
		self._setup_two_factor_auth(username)

		return True

	def _initialize_user(self, username, password):
		"""Initializes a new user by storing the password in plain text and setting up 2FA."""
		secret = generate_2fa_secret()

		# Store the plain password and 2FA secret
		self.users[username] = {
			'password': password,
			'2fa_secret': secret
		}
		self.save_users()

	def _generate_and_store_rsa_keys(self, username, password):
		"""Generates and stores RSA keys for the user."""
		rsa_private_key, rsa_public_key = generate_rsa_keys(self.printer, password)
		save_rsa_keys(self.printer, None, rsa_public_key, username)
		self.users[username].update({
			'rsa_private_key': base64.b64encode(rsa_private_key).decode('utf-8'),
			'rsa_public_key': base64.b64encode(rsa_public_key).decode('utf-8')
		})
		self.save_users()

	def _setup_two_factor_auth(self, username):
		"""Sets up 2FA by generating a QR code and displaying it."""
		secret = self.users[username]['2fa_secret']
		qr_code_image = get_qr_code(username, secret)
		qr_image_file = f"{username}_qrcode.png"
		with open(qr_image_file, 'wb') as qr_file:
			qr_file.write(qr_code_image)
		open_qr_image(qr_image_file)