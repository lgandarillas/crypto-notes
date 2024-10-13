"""
This module provides utility functions for two-factor authentication.
"""

import pyotp
import qrcode
import io
import os
import subprocess

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
