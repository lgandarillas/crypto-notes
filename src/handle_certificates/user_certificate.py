"""
src/handle_certificates/user_certificate.py
"""

import os
from cryptography import x509
from cryptography.x509 import NameOID
from print_manager import PrintManager
from cryptography.hazmat.primitives import serialization
from handle_certificates.certificate_utils import save_certificate
from handle_certificates.certificate_utils import generate_key_pair, save_key, save_certificate, build_certificate

def create_user_certificate(username, country_code):
	"""
	Creates a user certificate signed by the country's intermediate CA.
	"""
	print_manager = PrintManager()

	# Paths
	country_dir = f"data/certificates/{country_code}"
	intermediate_cert_path = os.path.join(country_dir, f"{country_code}_HQ_certificate.pem")
	intermediate_key_path = os.path.join(country_dir, f"{country_code}_HQ_private.pem")
	user_cert_path = f"data/keys/{username}/{username}_certificate.pem"

	# Load intermediate certificate and private key
	with open(intermediate_cert_path, "rb") as inter_cert_file:
		intermediate_cert = x509.load_pem_x509_certificate(inter_cert_file.read())

	with open(intermediate_key_path, "rb") as inter_key_file:
		intermediate_private_key = serialization.load_pem_private_key(
			inter_key_file.read(),
			password=None
		)

	# Load user's public key
	user_public_key_path = f"data/keys/{username}/{username}_public_key.pem"
	with open(user_public_key_path, "rb") as user_pub_file:
		user_public_key = serialization.load_pem_public_key(user_pub_file.read())

	# Create subject for user certificate
	subject = x509.Name([
		x509.NameAttribute(NameOID.COUNTRY_NAME, country_code),
		x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"{country_code} User Certificate"),
		x509.NameAttribute(NameOID.COMMON_NAME, username),
	])

	# Build and sign user certificate
	user_certificate = build_certificate(
		subject=subject,
		issuer=intermediate_cert.subject,
		public_key=user_public_key,
		private_key=intermediate_private_key,
		is_root=False
	)

	# Save the user certificate
	save_certificate(user_cert_path, user_certificate)
	print_manager.print_success(f"[CERTIFICATE LOG] User certificate for {username} created successfully!")
