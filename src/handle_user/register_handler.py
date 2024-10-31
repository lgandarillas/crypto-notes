"""
src/handle_user/register_handler.py
Handles the registration process for new users.
By: Luis Gandarillas && Carlos Bravo
"""

import re
import base64
import pwinput
from print_manager import PrintManager
from handle_user.user_manager import load_users, save_users
from rsa_utils import generate_rsa_keys, save_rsa_keys
from two_factor_auth import generate_2fa_secret, get_qr_code, open_qr_image

class RegisterHandler:
	def __init__(self):
		self.users = load_users()
		self.printer = PrintManager()

	def handle_register(self):
		"""Handles the entire registration process."""
		username = self._get_username()
		if username in self.users:
			self.printer.print_error(f"Registration failed: Username '{username}' already exists.")
			return False
		password = self._get_password()
		self.users[username] = {'password': password, '2fa_secret': generate_2fa_secret()}
		self._generate_and_store_rsa_keys(username, password)
		save_users(self.users)
		self._setup_two_factor_auth(username)
		self.printer.print_success(f"User {username} registered successfully!")
		return True

	def _get_username(self):
		try:
			return input("Enter your username: ").strip()
		except KeyboardInterrupt:
			self.printer.print_error("\nRegistration cancelled.")
			return None

	def _get_password(self):
		while True:
			try:
				password = pwinput.pwinput("Enter your password: ", mask='*').strip()
				failed_requirements = self._validate_password(password)
				if not failed_requirements:
					return password
				else:
					self.printer.print_error("Password must have: " + ", ".join(failed_requirements))
			except KeyboardInterrupt:
				self.printer.print_error("\nRegistration cancelled.")
				return None

	def _validate_password(self, password):
		requirements = {
			r".{8,}": "at least 8 characters",
			r"[A-Z]": "one uppercase letter",
			r"[a-z]": "one lowercase letter",
			r"\d": "one digit",
			r"[!@#$%^&*()\-_=+\[\]{}|;:'\",.<>/?`~]": "one special character"
		}
		return [msg for regex, msg in requirements.items() if not re.search(regex, password)]

	def _initialize_user(self, username, password):
		secret = generate_2fa_secret()
		self.users[username] = {'password': password, '2fa_secret': secret}
		save_users(self.users)

	def _generate_and_store_rsa_keys(self, username, password):
		rsa_private_key, rsa_public_key = generate_rsa_keys(self.printer, password)
		save_rsa_keys(self.printer, None, rsa_public_key, username)
		self.users[username].update({
			'rsa_private_key': base64.b64encode(rsa_private_key).decode('utf-8'),
			'rsa_public_key': base64.b64encode(rsa_public_key).decode('utf-8')
		})
		save_users(self.users)

	def _setup_two_factor_auth(self, username):
		secret = self.users[username]['2fa_secret']
		qr_code_image = get_qr_code(username, secret)
		qr_image_file = f"{username}_qrcode.png"
		with open(qr_image_file, 'wb') as qr_file:
			qr_file.write(qr_code_image)
		open_qr_image(qr_image_file)