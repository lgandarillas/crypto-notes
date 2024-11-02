"""
src/handle_user/access_crypto_utils.py

UserCrypto class is used to handle the user's crypto data.
"""

import os
import json
import base64
from print_manager import PrintManager
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

USERS_DATABSE = 'data/users.json'

class UserCrypto:
	def __init__(self):
		self.printer = PrintManager()

	def load_users(self):
		"""Load user data from the encrypted database file."""

		os.makedirs(os.path.dirname(USERS_DATABSE), exist_ok=True)

		if not os.path.exists(USERS_DATABSE):
			with open(USERS_DATABSE, 'w') as file:
				file.write("{}")
			return {}
		try:
			with open(USERS_DATABSE, 'r') as file:
				return json.load(file)
		except Exception as e:
			self.printer.print_error(f"Failed to load users: {e}")
			return {}

	def save_users(self, users):
		"""Save user data to the database file."""

		os.makedirs(os.path.dirname(USERS_DATABSE), exist_ok=True)

		with open(USERS_DATABSE, 'w') as file:
			json.dump(users, file, indent=4)

	# NOT USED
	def get_server_key(self):
		"""
		Obtains the encryption key for data/users.json by searching for the file data/.server_key.txt.
		If it does not exist, it generates the key and saves it in the same file.
		"""
		path = "data/.server_key.txt"
		if os.path.exists(path):
			with open(path, 'rb') as file:
				return file.read()
		else:
			os.makedirs("data", exist_ok=True)
			key = self._generate_fernet_key()
			with open(path, 'wb') as file:
				file.write(key)
			return key

	# NOT USED
	def _generate_fernet_key(self):
		"""Generates a new Fernet key."""
		return Fernet.generate_key()

	# NOT USED
	def encrypt_users_json(self):
		"""Encrypts the data/users.json file when it is not being used to read or modify data."""
		path = "data/users.json"
		if os.path.exists(path):
			with open(path, 'rb') as file:
				decrypted_data = file.read()
			key = self.get_server_key()
			fernet = Fernet(key)
			encrypted_data = fernet.encrypt(decrypted_data)
			with open(path, 'wb') as file:
				file.write(encrypted_data)
			self.printer.print_debug("Archivo users.json cifrado correctamente.")

	# NOT USED
	def decrypt_users_json(self):
		"""Decrypts the data/users.json file when it is being used to read or modify data."""
		path = "data/users.json"
		if not os.path.exists(path):
			# Crear un archivo JSON vacío si no existe
			with open(path, 'w') as file:
				json.dump({}, file)
			self.printer.print_debug("Archivo users.json creado como un JSON vacío.")
			return

		key = self.get_server_key()
		fernet = Fernet(key)

		try:
			with open(path, 'rb') as file:
				encrypted_data = file.read()
			if not encrypted_data.strip():
				# Si el archivo está vacío, escribir un JSON vacío
				with open(path, 'w') as file:
					json.dump({}, file)
				self.printer.print_debug("Archivo users.json estaba vacío; se creó como JSON vacío.")
				return

			decrypted_data = fernet.decrypt(encrypted_data)
			with open(path, 'wb') as file:
				file.write(decrypted_data)
			self.printer.print_debug("Archivo users.json descifrado correctamente.")
		except Exception as e:
			self.printer.print_error(f"Error al descifrar users.json: {e}")

	# NOT USED
	def generate_salt(self):
		"""Generates a random salt."""
		return os.urandom(16)

	# NOT USED
	def generate_token(self, salt, password):
		"""Generates a token using the salt and password."""
		password_bytes = password.encode()
		kdf = PBKDF2HMAC(
			algorithm=hashes.SHA256(),
			length=32,
			salt=salt,
			iterations=480000,
		)
		key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
		return key