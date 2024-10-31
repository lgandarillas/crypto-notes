"""
src/handle_user/handle_register.py

Handles the registration process for new users, including the generation of RSA keys,
"""

import re
import base64
import pwinput
from two_factor_auth import generate_2fa_secret, get_qr_code, open_qr_image
from rsa_utils import generate_rsa_keys, save_rsa_keys
from print_manager import PrintManager

class RegisterHandler:

	def __init__(self, account_manager: "AccountManager"):
		self.account_manager = account_manager
		self.printer = PrintManager()

	def handle_register(self):
		username = self._get_username()
		if username is None:
			return True
		password = self._get_password()
		if password is None:
			return True
		if self.account_manager.register(username, password):
			self.printer.print_success(f"User {username} registered successfully!")
		else:
			self.printer.print_error(f"Registration failed for user {username}.")

		return True

	def _get_username(self):
		"""Prompts the user to enter a username, handling interruption."""
		try:
			return input("	Enter your username: ").strip()
		except KeyboardInterrupt:
			self.printer.print_error("\nRegistration cancelled.")
			return None

	def _get_password(self):
		"""Prompts the user to enter a password with validation, handling interruption."""
		while True:
			try:
				password = pwinput.pwinput("	Enter your password: ", mask='*').strip()
			except KeyboardInterrupt:
				self.printer.print_error("\nRegistration cancelled.")
				return None

			failed_requirements = self._validate_register_password(password)
			if not failed_requirements:
				return password
			else:
				self.printer.print_error("Password must have: " + ", ".join(failed_requirements))

	def _validate_register_password(self, password):
		"""Validate the password requirements."""
		password_requirements = {
			r".{8,}": "at least 8 characters",
			r"[A-Z]": "at least one uppercase letter",
			r"[a-z]": "at least one lowercase letter",
			r"\d": "at least one digit",
			r"[!@#$%^&*()\-_=+\[\]{}|;:'\",.<>/?`~]": "at least one special character"
		}

		failed_requirements = []
		for regex, message in password_requirements.items():
			if not re.search(regex, password):
				failed_requirements.append(message)

		return failed_requirements

	def register(self, username, password):
		"""Registers a new user and handles 2FA setup and RSA keys generation."""
		if username in self.account_manager.users:
			self.printer.print_error(f"Registration failed: Username '{username}' already exists.")
			return False

		self._initialize_user(username, password)
		self._generate_and_store_rsa_keys(username, password)
		self._setup_two_factor_auth(username)

		return True

	def _initialize_user(self, username, password):
		"""Initializes a new user by storing the password in plain text and setting up 2FA."""
		secret = generate_2fa_secret()
		self.account_manager.users[username] = {
			'password': password,
			'2fa_secret': secret
		}
		self.account_manager.save_users()

	def _generate_and_store_rsa_keys(self, username, password):
		"""Generates and stores RSA keys for the user."""
		rsa_private_key, rsa_public_key = generate_rsa_keys(self.printer, password)
		save_rsa_keys(self.printer, None, rsa_public_key, username)
		self.account_manager.users[username].update({
			'rsa_private_key': base64.b64encode(rsa_private_key).decode('utf-8'),
			'rsa_public_key': base64.b64encode(rsa_public_key).decode('utf-8')
		})
		self.account_manager.save_users()

	def _setup_two_factor_auth(self, username):
		"""Sets up 2FA by generating a QR code and displaying it."""
		secret = self.account_manager.users[username]['2fa_secret']
		qr_code_image = get_qr_code(username, secret)
		qr_image_file = f"{username}_qrcode.png"
		with open(qr_image_file, 'wb') as qr_file:
			qr_file.write(qr_code_image)
		open_qr_image(qr_image_file)