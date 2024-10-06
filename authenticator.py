import os
import json
import base64
import pyotp
import qrcode
import io
import subprocess
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

DATABASE_FILE = 'users.json'

class Authenticator:
	def __init__(self, printer):
		"""Initialize the Authenticator with a printer and load users from the database."""
		self.printer = printer
		self.users = self.load_users()

	def load_users(self):
		"""Load the users from the JSON database. If the file is empty or corrupted, return an empty dictionary."""
		if os.path.exists(DATABASE_FILE):
			with open(DATABASE_FILE, 'r') as file:
				try:
					return json.load(file)
				except json.JSONDecodeError:
					return {}
		else:
			return {}

	def save_users(self):
		"""Save the current user data to the JSON database."""
		with open(DATABASE_FILE, 'w') as file:
			json.dump(self.users, file)

	def generate_salt(self):
		"""Generate a unique salt using os.urandom for each user."""
		return (os.urandom(16))

	def derive_key(self, password, salt):
		"""Derive an encryption key from the user's password and salt using PBKDF2."""
		kdf = PBKDF2HMAC(
			algorithm=hashes.SHA256(),
			length=32,
			salt=salt,
			iterations=100000
		)
		return base64.urlsafe_b64encode(kdf.derive(password.encode()))

	def generate_2fa_secret(self):
		"""Generate a new TOTP secret for 2FA."""
		return pyotp.random_base32()

	def get_qr_code(self, username, secret):
		"""Generate a QR code image for the user to scan with Google Authenticator."""
		otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(username, issuer_name="Cryptography Carlos & Luis")
		qr = qrcode.make(otp_uri)
		buffer = io.BytesIO()
		qr.save(buffer, "PNG")
		return buffer.getvalue()

	def register(self, username, password):
		"""Register a new user. Encrypts the password, generates a salt, and saves the data to the database."""
		if username in self.users:
			self.printer.apply_color(f"Registration failed: Username '{username}' already exists. Please choose a different username.", self.printer.COLOR_RED)
			return False

		salt = self.generate_salt()
		key = self.derive_key(password, salt)
		f = Fernet(key)
		token = f.encrypt(password.encode())

		secret = self.generate_2fa_secret()

		email_encripted = f.encrypt(username.encode())

		self.users[username] = {
			'salt': base64.urlsafe_b64encode(salt).decode(),
			'token': token.decode(),
			'email': email_encripted.decode(),
			'2fa_secret': secret
		}

		self.save_users()

		qr_code_image = self.get_qr_code(username, secret)
		qr_image_file = f"{username}_qrcode.png"
		with open(qr_image_file, 'wb') as qr_file:
			qr_file.write(qr_code_image)

		self.open_qr_in_default_viewer(qr_image_file)

		self.printer.apply_color(f"Registration successful for user: {username}", self.printer.COLOR_GREEN)
		return True

	def login(self, username, password, otp_input):
		"""Authenticate a user by checking the password. Decrypt the token and compare it with the stored one."""
		user = self.users.get(username)
		if not user:
			self.printer.apply_color(f"Login failed: Username '{username}' not found. Make sure you are registered or register a new account.", self.printer.COLOR_RED)
			return False

		salt = base64.urlsafe_b64decode(user['salt'])
		stored_token = user['token']

		key = self.derive_key(password, salt)
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
			self.printer.apply_color(f"Login failed: Incorrect password for user '{username}'. Please check your password and try again.", self.printer.COLOR_RED)
			return False

	def open_qr_in_default_viewer(self, qr_image_file):
		try:
			if os.name == 'posix':
				subprocess.Popen(['xdg-open', qr_image_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
			elif os.name == 'nt':
				os.startfile(qr_image_file)
		except Exception as ex:
			self.printer.apply_color(f"Error opening QR code image: {ex}", self.printer.COLOR_RED)