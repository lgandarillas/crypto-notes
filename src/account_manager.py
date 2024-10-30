"""
src/account_manager.py

Handles the management of user accounts, including registration and login processes,
leveraging cryptographic utilities for secure password handling and user data encryption.
By: Luis Gandarillas && Carlos Bravo
"""

import os
import json
import base64
from crypto_utils import CryptoUtils
from cryptography.fernet import Fernet
from rsa_utils import generate_rsa_keys, save_rsa_keys
from two_factor_auth import generate_2fa_secret, get_qr_code, open_qr_image

class AccountManager:
	"""Manages user accounts, including registration, login, and data encryption."""

	def __init__(self, printer, encryption_key, database='data/users.json'):
		self.printer = printer
		self.encryption_key = encryption_key
		self.database = database
		self.crypto_utils = CryptoUtils(printer)
		self.users = self.load_users()

	def get_encryption_key(self):
		"""Derive a secure key and salt for encrypting user data."""
		salt = os.urandom(16)
		return self.crypto_utils.derive_key(self.encryption_key, salt), salt

	def load_users(self):
		"""Load user data from the encrypted database file."""
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
				self.printer.print_debug("[CRYPTO LOG] User data decrypted; Fernet, 32 bytes")
				return json.loads(decrypted_data.decode())
		except Exception as e:
			self.printer.print_error(f"Failed to load users {e}")
			return {}

	def save_users(self):
		"""Encrypt and save user data to the database file."""
		key, salt = self.get_encryption_key()
		f = Fernet(key)
		encrypted_data = f.encrypt(json.dumps(self.users).encode())
		self.printer.print_debug("[CRYPTO LOG] User data encrypted for saving; Fernet, 32 bytes")
		with open(self.database, 'wb') as file:
			file.write(salt)
			file.write(encrypted_data)

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
		"""Initializes a new user by generating a salt, deriving a key, and encrypting the password."""
		salt = self.crypto_utils.generate_salt()
		key = self.crypto_utils.derive_key(password, salt)
		f = Fernet(key)
		token = f.encrypt(password.encode())
		self.printer.print_debug("[CRYPTO LOG] User password encrypted for registration; Fernet, 32 bytes")
		secret = generate_2fa_secret()

		self.users[username] = {
			'salt': base64.urlsafe_b64encode(salt).decode(),
			'token': token.decode(),
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
		qr_code_image = get_qr_code(username, secret, self.printer)
		qr_image_file = f"{username}_qrcode.png"
		with open(qr_image_file, 'wb') as qr_file:
			qr_file.write(qr_code_image)
		open_qr_image(qr_image_file, self.printer)