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
import pycountry
import subprocess
from print_manager import PrintManager
from handle_user.rsa_utils import generate_rsa_keys, save_rsa_keys
from handle_user.access_crypto_utils import UserCrypto
from handle_certificates.intermediate_certificates import ensure_intermediate_certificate

class RegisterHandler:
	def __init__(self):
		self.printer = PrintManager()
		self.user_crypto = UserCrypto()
		self.users = self.user_crypto.load_users()

	def handle_register(self):
		"""Handles the entire registration process."""

		username = self._get_username()
		if username is None:
			return False
		if username in self.users:
			self.printer.print_error(f"Registration failed: Username '{username}' already exists.")
			return False

		password = self._get_password()
		if password is None:
			return False

		country = self._get_country()
		if country is None:
			return False

		root_cert_path = "data/certificates/world/world_headquarters_certificate.pem"
		root_private_key_path = "data/certificates/world/world_headquarters_private.pem"
		ensure_intermediate_certificate(country, root_cert_path, root_private_key_path)

		salt = self.user_crypto.generate_salt()
		token = self.user_crypto.generate_token(salt, password)
		self.users[username] = {
			'salt': salt.hex(),
			'token': token.decode(),
			'2fa_secret': self._generate_2fa_secret(),
			'country': country
		}

		self._generate_and_save_rsa_keys(username, password)
		self.user_crypto.save_users(self.users)
		self._setup_two_factor_auth(username)
		self.printer.print_success(f"User {username} registered successfully!")

		return True

	def _get_country(self):
		"""Prompt the user to select their country of origin."""
		while True:
			try:
				country_name = input("Enter your country of origin: ").strip()
				country = self._validate_country(country_name)
				if country:
					return country
				else:
					self.printer.print_error(f"Invalid country: '{country_name}'. Please try again.")
			except KeyboardInterrupt:
				self.printer.print_error("\nRegistration cancelled.")
				return None

	def _validate_country(self, country_name):
		"""Validate if the provided country name is valid."""
		try:
			country = pycountry.countries.lookup(country_name)
			return country.alpha_2
		except LookupError:
			return None

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

	def _get_password(self):
		"""Prompt the user for a password with an option to cancel registration if requirements are not met."""
		while True:
			password = pwinput.pwinput("Enter your password: ", mask='*').strip()
			failed_requirements = self._validate_password(password)
			if not failed_requirements:
				return password
			else:
				self.printer.print_error("Password must have: " + ", ".join(failed_requirements))
				cancel = input("Do you want to cancel registration? (y/n): ").strip().lower()
				if cancel == 'y':
					self.printer.print_error("Registration cancelled.")
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

	def _generate_and_save_rsa_keys(self, username, password):
		"""Generates and saves RSA private and public keys for the user."""
		rsa_private_key, rsa_public_key = generate_rsa_keys(self.printer, password)
		save_rsa_keys(self.printer, rsa_private_key, rsa_public_key, username)
		self.printer.print_debug("[CRYPTO LOG] RSA keys generated and saved; RSA, 2048 bits.")

	def _setup_two_factor_auth(self, username):
		"""Sets up two-factor authentication for the user by generating a QR code."""
		data_dir = "data/"
		if not os.path.exists(data_dir):
			os.makedirs(data_dir)

		secret = self.users[username]['2fa_secret']
		qr_code_image = self._get_qr_code(username, secret)
		qr_image_file = f"data/{username}_qrcode.png"
		with open(qr_image_file, 'wb') as qr_file:
			qr_file.write(qr_code_image)
		self._open_qr_image(qr_image_file)
		self.printer.print_debug("[CRYPTO LOG] 2FA setup completed with TOTP.")

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