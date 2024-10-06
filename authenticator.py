"""
This file contains the authenticator class for the program, which handles user registration and login.
"""

import json
import base64
import os
from cryptography.fernet import Fernet
from utils import generate_salt, derive_key, generate_2fa_secret, get_qr_code, open_qr_in_default_viewer

DATABASE_FILE = 'users.json'

class Authenticator:
	def __init__(self, printer):
		self.printer = printer
		self.users = self.load_users()

	def load_users(self):
		if os.path.exists(DATABASE_FILE):
			with open(DATABASE_FILE, 'r') as file:
				try:
					return json.load(file)
				except json.JSONDecodeError:
					return {}
		else:
			return {}

	def save_users(self):
		with open(DATABASE_FILE, 'w') as file:
			json.dump(self.users, file)

	def register(self, username, password):
		if username in self.users:
			self.printer.apply_color(f"Registration failed: Username '{username}' already exists.", self.printer.COLOR_RED)
			return False

		salt = generate_salt()
		key = derive_key(password, salt)
		f = Fernet(key)
		token = f.encrypt(password.encode())
		secret = generate_2fa_secret()
		email_encrypted = f.encrypt(username.encode())

		self.users[username] = {
			'salt': base64.urlsafe_b64encode(salt).decode(),
			'token': token.decode(),
			'email': email_encrypted.decode(),
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