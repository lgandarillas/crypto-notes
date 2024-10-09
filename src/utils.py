"""
This file contains utility functions for the program, such as generating salts, deriving keys, generating 2FA secrets, and creating QR codes.
"""

import os
import base64
import pyotp
import qrcode
import io
import subprocess
from time import sleep
from progress.bar import Bar
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def generate_salt():
	"""Generate a unique salt using os.urandom for each user."""
	return os.urandom(16)

def derive_key(password, salt):
	"""Derive an encryption key from the user's password and salt using PBKDF2."""
	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=32,
		salt=salt,
		iterations=100000
	)
	return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def generate_2fa_secret():
	"""Generate a new TOTP secret for 2FA."""
	return pyotp.random_base32()

def get_qr_code(username, secret):
	"""Generate a QR code image for the user to scan with Google Authenticator."""
	otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(username, issuer_name="Cryptography Carlos & Luis")
	qr = qrcode.make(otp_uri)
	buffer = io.BytesIO()
	qr.save(buffer, "PNG")
	return buffer.getvalue()

def open_qr_in_default_viewer(qr_image_file, printer):
	"""Open the QR code image using the default viewer for the OS."""
	try:
		if os.name == 'posix':
			subprocess.Popen(['xdg-open', qr_image_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
		elif os.name == 'nt':
			os.startfile(qr_image_file)
	except Exception as ex:
		printer.apply_color(f"Error opening QR code image: {ex}", printer.COLOR_RED)

def show_progress_bar(task_description="Processing... ", duration=2.0):
	"""Show a progress bar with a given task description and duration."""
	with Bar(task_description, max=100) as bar:
		for i in range(100):
			sleep(duration / 100)
			bar.next()