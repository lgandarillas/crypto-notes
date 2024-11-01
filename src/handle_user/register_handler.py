"""
src/handle_user/register_handler.py
Handles the registration process for new users.
By: Luis Gandarillas && Carlos Bravo
"""

import re
import io
import os
import pyotp
import qrcode
import base64
import pwinput
import subprocess
from print_manager import PrintManager
from rsa_utils import generate_rsa_keys, save_rsa_keys
from handle_user.access_crypto_utils import UserCrypto

class RegisterHandler:
	def __init__(self):
		self.printer = PrintManager()
		self.user_crypto = UserCrypto()
		self.users = self.user_crypto.load_users()

	def handle_register(self):
		"""Handles the entire registration process."""

		username = self._get_username()
		if username in self.users:
			self.printer.print_error(f"Registration failed: Username '{username}' already exists.")
			return False

		password = self._get_password()
		self.users[username] = {
			'password': password,
			'2fa_secret': self._generate_2fa_secret()
		}
		self._generate_and_store_rsa_keys(username, password)
		self.user_crypto.save_users(self.users)
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

	def _generate_and_store_rsa_keys(self, username, password):
		rsa_private_key, rsa_public_key = generate_rsa_keys(self.printer, password)
		save_rsa_keys(self.printer, None, rsa_public_key, username)
		self.users[username].update({
			'rsa_private_key': base64.b64encode(rsa_private_key).decode('utf-8'),
			'rsa_public_key': base64.b64encode(rsa_public_key).decode('utf-8')
		})
		self.user_crypto.save_users(self.users)

	def _setup_two_factor_auth(self, username):
		secret = self.users[username]['2fa_secret']
		qr_code_image = self._get_qr_code(username, secret)
		qr_image_file = f"{username}_qrcode.png"
		with open(qr_image_file, 'wb') as qr_file:
			qr_file.write(qr_code_image)
		self._open_qr_image(qr_image_file)

	def _generate_2fa_secret(self):
		"""Generate a new TOTP secret for 2FA."""
		return pyotp.random_base32()

	def _get_qr_code(self, username, secret):
		"""Generate a QR code image for the user to scan with Google Authenticator."""
		otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(username, issuer_name="Cryptography Carlos & Luis")
		qr = qrcode.make(otp_uri)
		buffer = io.BytesIO()
		qr.save(buffer, "PNG")
		printer = PrintManager()
		printer.print_debug("[CRYPTO LOG] QR code generated for 2FA")
		return buffer.getvalue()

	def _open_qr_image(self, qr_image):
		"""Open the QR code image using the default viewer for the OS."""
		printer = PrintManager()
		try:
			if os.name == 'posix':
				subprocess.Popen(['xdg-open', qr_image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
			elif os.name == 'nt':
				os.startfile(qr_image)
		except Exception as ex:
			self.printer.print_error(f"Error opening QR code image: {ex}")