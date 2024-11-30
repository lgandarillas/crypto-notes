"""
src/handle_certificates/intermediate_certificate.py
"""

import os
from cryptography import x509
from cryptography.x509 import NameOID
from print_manager import PrintManager
from cryptography.hazmat.primitives import serialization
from handle_certificates.certificate_utils import generate_key_pair, save_key, save_certificate, build_certificate

print_manager = PrintManager()

def ensure_intermediate_certificate(country_code, root_cert_path, root_private_key_path):
	"""
	Creates an intermediate certificate for a given country if it doesn't already exist.
	"""
	# Paths
	country_dir = f"data/certificates/{country_code}"
	cert_path = os.path.join(country_dir, f"{country_code}_HQ_certificate.pem")
	private_key_path = os.path.join(country_dir, f"{country_code}_HQ_private.pem")

	os.makedirs(country_dir, exist_ok=True)

	if os.path.exists(cert_path):
		print_manager.print_debug(f"[CERTIFICATE LOG] Intermediate certificate for {country_code} already exists. Skipping creation.")
		return

	print_manager.print_debug(f"[CERTIFICATE LOG] Creating intermediate certificate for {country_code}...")

	# Load root certificate and private key
	with open(root_cert_path, "rb") as root_cert_file:
		root_cert = x509.load_pem_x509_certificate(root_cert_file.read())

	with open(root_private_key_path, "rb") as root_key_file:
		root_private_key = serialization.load_pem_private_key(
			root_key_file.read(),
			password=None
		)

	# Generate keys for intermediate certificate
	private_key, public_key = generate_key_pair()

	# Create subject details for intermediate certificate
	subject = x509.Name([
		x509.NameAttribute(NameOID.COUNTRY_NAME, country_code),
		x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"{country_code} Headquarters CA"),
		x509.NameAttribute(NameOID.COMMON_NAME, f"{country_code} HQ Intermediate CA"),
	])

	# Build and sign the intermediate certificate
	intermediate_cert = build_certificate(
		subject,
		root_cert.subject,
		public_key,
		root_private_key,
		is_root=False
	)

	# Save private key and certificate
	save_key(private_key_path, private_key, is_private=True)
	save_certificate(cert_path, intermediate_cert)

	print_manager.print_success(f"[CERTIFICATE LOG] Intermediate certificate for {country_code} created successfully.")
