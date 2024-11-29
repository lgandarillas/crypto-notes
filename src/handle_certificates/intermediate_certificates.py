"""
src/handle_certificates/intermediate_certificates.py
"""

import os
from cryptography import x509
from cryptography.x509 import NameOID
from print_manager import PrintManager
from certificate_utils import generate_key_pair, save_key, save_certificate, build_certificate

print_manager = PrintManager()

def create_intermediate_certificate(country_code, country_name):
	"""Creates an intermediate certificate for a given country."""
	root_dir = "data/certificates/world"
	intermediate_dir = f"data/certificates/{country_code}"
	os.makedirs(intermediate_dir, exist_ok=True)

	# Paths for intermediate certificate and keys
	intermediate_cert_path = os.path.join(intermediate_dir, f"{country_code}_HQ_certificate.pem")
	intermediate_private_key_path = os.path.join(intermediate_dir, f"{country_code}_HQ_private.pem")
	intermediate_public_key_path = os.path.join(intermediate_dir, f"{country_code}_HQ_public.pem")

	# Load root certificate and private key
	root_cert_path = os.path.join(root_dir, "world_headquarters_certificate.pem")
	root_private_key_path = os.path.join(root_dir, "world_headquarters_private.pem")

	with open(root_cert_path, "rb") as cert_file:
		root_certificate = x509.load_pem_x509_certificate(cert_file.read())

	with open(root_private_key_path, "rb") as key_file:
		root_private_key = serialization.load_pem_private_key(key_file.read(), password=None)

	# Generate key pair for the intermediate certificate
	intermediate_private_key, intermediate_public_key = generate_key_pair()

	# Define the subject for the intermediate certificate
	subject = x509.Name([
		x509.NameAttribute(NameOID.COUNTRY_NAME, country_code),
		x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"{country_name} Headquarters CA"),
		x509.NameAttribute(NameOID.COMMON_NAME, f"{country_name} Intermediate Certificate"),
	])

	# Create the intermediate certificate
	intermediate_certificate = build_certificate(
		subject,
		root_certificate.subject,
		intermediate_public_key,
		root_private_key,
		is_root=False,
	)

	# Save the intermediate certificate and keys
	save_key(intermediate_private_key_path, intermediate_private_key, is_private=True)
	save_key(intermediate_public_key_path, intermediate_public_key, is_private=False)
	save_certificate(intermediate_cert_path, intermediate_certificate)

	print_manager.print_success(f"[CERTIFICATE LOG] Intermediate certificate for {country_name} created successfully.")
