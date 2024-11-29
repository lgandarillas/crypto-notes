"""
src/handle_certificates/user_certificate.py
"""

import os
from cryptography import x509
from cryptography.x509 import NameOID
from print_manager import PrintManager
from cryptography.hazmat.primitives import serialization
from certificate_utils import generate_key_pair, save_key, save_certificate, build_certificate

print_manager = PrintManager()

def create_user_certificate(username, country_code, country_name):
	"""Creates a user certificate signed by the intermediate certificate of the user's country."""
	user_dir = f"data/keys/{username}"
	os.makedirs(user_dir, exist_ok=True)

	# Paths for user certificate and keys
	user_cert_path = os.path.join(user_dir, f"{username}_certificate.pem")
	user_private_key_path = os.path.join(user_dir, f"{username}_private_key.pem")
	user_public_key_path = os.path.join(user_dir, f"{username}_public_key.pem")

	# Load intermediate certificate and private key
	intermediate_dir = f"data/certificates/{country_code}"
	intermediate_cert_path = os.path.join(intermediate_dir, f"{country_code}_HQ_certificate.pem")
	intermediate_private_key_path = os.path.join(intermediate_dir, f"{country_code}_HQ_private.pem")

	with open(intermediate_cert_path, "rb") as cert_file:
		intermediate_certificate = x509.load_pem_x509_certificate(cert_file.read())

	with open(intermediate_private_key_path, "rb") as key_file:
		intermediate_private_key = serialization.load_pem_private_key(key_file.read(), password=None)

	# Generate key pair for the user
	user_private_key, user_public_key = generate_key_pair()

	# Define the subject for the user's certificate
	subject = x509.Name([
		x509.NameAttribute(NameOID.COUNTRY_NAME, country_code),
		x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"{country_name} User Certificate"),
		x509.NameAttribute(NameOID.COMMON_NAME, username),
	])

	# Create the user's certificate
	user_certificate = build_certificate(
		subject,
		intermediate_certificate.subject,
		user_public_key,
		intermediate_private_key,
		is_root=False,
	)

	# Save the user's certificate and keys
	save_key(user_private_key_path, user_private_key, is_private=True)
	save_key(user_public_key_path, user_public_key, is_private=False)
	save_certificate(user_cert_path, user_certificate)

	print_manager.print_success(f"[CERTIFICATE LOG] User certificate for {username} created successfully.")
