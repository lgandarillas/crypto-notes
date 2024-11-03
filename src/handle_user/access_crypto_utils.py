"""
src/handle_user/access_crypto_utils.py

UserCrypto class is used to handle the user's crypto data.
By: Luis Gandarillas && Carlos Bravo
"""

import os
import json
import base64
from print_manager import PrintManager
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

USERS_DATABASE = 'data/users.json'
SERVER_KEY_PATH = 'data/.server_key.txt'

class UserCrypto:
	def __init__(self):
		self.printer = PrintManager()

	def load_users(self):
		"""Load user data from the encrypted database file."""
		os.makedirs(os.path.dirname(USERS_DATABASE), exist_ok=True)

		if not os.path.exists(USERS_DATABASE):
			self.save_users({})
			return {}

		try:
			encrypted_data = self._read_encrypted_file(USERS_DATABASE)
			decrypted_data = self._decrypt_data(encrypted_data)
			return json.loads(decrypted_data.decode('utf-8'))
		except Exception as e:
			self.printer.print_error(f"Failed to load users: {e}")
			return {}

	def save_users(self, users):
		"""Save user data to the database file."""
		os.makedirs(os.path.dirname(USERS_DATABASE), exist_ok=True)

		try:
			json_data = json.dumps(users).encode('utf-8')
			encrypted_data = self._encrypt_data(json_data)
			self._write_encrypted_file(USERS_DATABASE, encrypted_data)
		except Exception as e:
			self.printer.print_error(f"Failed to save users: {e}")

	def _encrypt_data(self, data):
		"""Encrypt the given data."""
		key = self.get_server_key()
		fernet = Fernet(key)
		return fernet.encrypt(data)

	def _decrypt_data(self, data):
		"""Decrypt the given data."""
		key = self.get_server_key()
		fernet = Fernet(key)
		return fernet.decrypt(data)

	def _read_encrypted_file(self, filepath):
		"""Read and return the encrypted data from the file."""
		with open(filepath, 'rb') as file:
			return file.read()

	def _write_encrypted_file(self, filepath, data):
		"""Write the encrypted data to the file."""
		with open(filepath, 'wb') as file:
			file.write(data)

	def get_server_key(self):
		"""Get the server's Fernet key."""
		if os.path.exists(SERVER_KEY_PATH):
			with open(SERVER_KEY_PATH, 'rb') as file:
				return file.read()
		else:
			os.makedirs("data", exist_ok=True)
			key = self._generate_fernet_key()
			with open(SERVER_KEY_PATH, 'wb') as file:
				file.write(key)
			return key

	#############

	def generate_salt(self):
		"""Generate a new salt."""
		return os.urandom(16)

	def generate_token(self, salt, message):
		"""Generate a new token using the salt and message."""
		message_bytes = message.encode()
		kdf = PBKDF2HMAC(
			algorithm=hashes.SHA256(),
			length=32,
			salt=salt,
			iterations=480000,
		)
		key = base64.urlsafe_b64encode(kdf.derive(message_bytes))
		return key

	def _encrypt_users_json(self):
		"""Encrypt the users.json file."""
		if os.path.exists(USERS_DATABASE):
			with open(USERS_DATABASE, 'rb') as file:
				decrypted_data = file.read()

			key = self.get_server_key()
			fernet = Fernet(key)

			encrypted_data = fernet.encrypt(decrypted_data)
			with open(USERS_DATABASE, 'wb') as file:
				file.write(encrypted_data)

	def _decrypt_users_json(self):
		"""Decrypt the users.json file."""

		key = self.get_server_key()
		fernet = Fernet(key)

		try:
			with open(USERS_DATABASE, 'rb') as file:
				encrypted_data = file.read()

			if not encrypted_data:
				self.printer.print_debug("users.json is empty.")
				return

			try:
				json.loads(encrypted_data.decode())
				return
			except (json.JSONDecodeError, UnicodeDecodeError):
				decrypted_data = fernet.decrypt(encrypted_data)
				with open(USERS_DATABASE, 'wb') as file:
					file.write(decrypted_data)
		except Exception as e:
			self.printer.print_error(f"Failed to decrypt users: {e}")

	def _generate_fernet_key(self):
		"""Generate a new Fernet key."""
		return Fernet.generate_key()