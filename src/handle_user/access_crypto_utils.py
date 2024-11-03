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
			with open(USERS_DATABASE, 'w') as file:
				file.write("{}")
			return {}
		try:
			self.decrypt_users_json()
			with open(USERS_DATABASE, 'r') as file:
				return json.load(file)
		except Exception as e:
			self.printer.print_error(f"Failed to load users: {e}")
			return {}

	def save_users(self, users):
		"""Save user data to the database file."""
		os.makedirs(os.path.dirname(USERS_DATABASE), exist_ok=True)
		with open(USERS_DATABASE, 'w') as file:
			json.dump(users, file, indent=4)
		self.encrypt_users_json()

	# NOT USED
	def encrypt_users_json(self):
		"""Cifra el archivo users.json."""
		if os.path.exists(USERS_DATABASE):
			with open(USERS_DATABASE, 'rb') as file:
				decrypted_data = file.read()
			key = self.get_server_key()
			fernet = Fernet(key)
			encrypted_data = fernet.encrypt(decrypted_data)
			with open(USERS_DATABASE, 'wb') as file:
				file.write(encrypted_data)

	# NOT USED
	def decrypt_users_json(self):
		"""Descifra el archivo users.json."""
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

	# NOT USED
	def generate_salt(self):
		return os.urandom(16)

	# NOT USED
	def generate_token(self, salt, message):
		message_bytes = message.encode()
		kdf = PBKDF2HMAC(
			algorithm=hashes.SHA256(),
			length=32,
			salt=salt,
			iterations=480000,
		)
		key = base64.urlsafe_b64encode(kdf.derive(message_bytes))
		return key

#######################################3

	# NOT USED
	def get_server_key(self):
		if os.path.exists(SERVER_KEY_PATH):
			with open(SERVER_KEY_PATH, 'rb') as file:
				return file.read()
		else:
			os.makedirs("data", exist_ok=True)
			key = self._generate_fernet_key()
			with open(SERVER_KEY_PATH, 'wb') as file:
				file.write(key)
			return key

	# NOT USED
	def _generate_fernet_key(self):
		"""Genera una nueva clave Fernet."""
		return Fernet.generate_key()