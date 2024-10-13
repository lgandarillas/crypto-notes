"""
src/account_manager.py
This file contains the AccountManager class for the program, which handles user registration and login.
"""

import json
import base64
import os
from cryptography.fernet import Fernet
from src.cryptography_utils import generate_salt, derive_key
from src.two_factor_auth import generate_2fa_secret, get_qr_code, open_qr_in_default_viewer

DATABASE_FILE = 'data/users.json'

class AccountManager:
	def __init__(self, printer, encryption_key):
		self.printer = printer
		self.encryption_key = encryption_key
		self.users = self.load_users()

	def get_key(self):
		salt = b'salt_for_file_encryption'
		return derive_key(self.encryption_key, salt)

	def load_users(self):
		if os.path.exists(DATABASE_FILE):
			with open(DATABASE_FILE, 'rb') as file:
				encrypted_data = file.read()
				try:
					f = Fernet(self.get_key())
					decrypted_data = f.decrypt(encrypted_data)
					return json.loads(decrypted_data.decode())
				except Exception:
					return {}
		else:
			return {}

	def save_users(self):
		f = Fernet(self.get_key())
		encrypted_data = f.encrypt(json.dumps(self.users).encode())
		with open(DATABASE_FILE, 'wb') as file:
			file.write(encrypted_data)

	def register(self, username, password):
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