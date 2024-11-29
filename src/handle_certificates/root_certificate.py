"""
src/handle_certificates/root_certificate.py
"""

import os
from cryptography import x509
from cryptography.x509 import NameOID
from print_manager import PrintManager
from certificate_utils import generate_key_pair, save_key, save_certificate, build_certificate

print_manager = PrintManager()

def create_root_certificate():
	"""Creates a root certificate and saves it in the world directory."""
	root_dir = "data/certificates/world"
	os.makedirs(root_dir, exist_ok=True)

	# Paths for root certificate and keys
	cert_path = os.path.join(root_dir, "world_headquarters_certificate.pem")
	private_key_path = os.path.join(root_dir, "world_headquarters_private.pem")
	public_key_path = os.path.join(root_dir, "world_headquarters_public.pem")

	print_manager.print_debug("[CERTIFICATE LOG] Creating root certificate...")

	# Generate key pair for the root certificate
	private_key, public_key = generate_key_pair()

	# Define the subject for the root certificate
	subject = x509.Name([
		x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
		x509.NameAttribute(NameOID.ORGANIZATION_NAME, "World Headquarters CA"),
		x509.NameAttribute(NameOID.COMMON_NAME, "World Headquarters Root CA"),
	])
	print_manager.print_debug("[CERTIFICATE LOG] Subject details created.")

	# Create the root certificate
	root_certificate = build_certificate(subject, None, public_key, private_key, is_root=True)

	# Save the root certificate and keys
	save_key(private_key_path, private_key, is_private=True)
	save_key(public_key_path, public_key, is_private=False)
	save_certificate(cert_path, root_certificate)

	print_manager.print_success("[CERTIFICATE LOG] Root certificate created successfully.")
