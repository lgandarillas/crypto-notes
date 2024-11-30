"""
src/handle_certificates/root_certificate.py
"""

import os
from cryptography import x509
from cryptography.x509 import NameOID
from print_manager import PrintManager
from handle_certificates.certificate_utils import generate_key_pair, save_key, save_certificate, build_certificate

print_manager = PrintManager()

def _certificate_exists(cert_path):
	"""Checks if the certificate already exists."""
	if os.path.exists(cert_path):
		print_manager.print_debug("[CERTIFICATE LOG] Root certificate already exists. Skipping creation.")
		return True
	return False

def _create_subject_details():
	"""Creates the subject details for the root certificate."""
	print_manager.print_debug("[CERTIFICATE LOG] Creating subject details...")
	return x509.Name([
		x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
		x509.NameAttribute(NameOID.ORGANIZATION_NAME, "World Headquarters CA"),
		x509.NameAttribute(NameOID.COMMON_NAME, "World Headquarters Root CA"),
	])

def ensure_root_certificate():
	"""Creates a root certificate and saves it in the world directory."""
	root_dir = "data/certificates/world"
	cert_path = os.path.join(root_dir, "world_headquarters_certificate.pem")
	private_key_path = os.path.join(root_dir, "world_headquarters_private.pem")

	os.makedirs(root_dir, exist_ok=True)

	if _certificate_exists(cert_path):
		return

	print_manager.print_debug("[CERTIFICATE LOG] Creating root certificate...")

	private_key, _ = generate_key_pair()

	subject = _create_subject_details()
	root_certificate = build_certificate(subject, None, private_key.public_key(), private_key, is_root=True)

	save_key(private_key_path, private_key, is_private=True)
	save_certificate(cert_path, root_certificate)

	print_manager.print_success("[CERTIFICATE LOG] Root certificate created successfully.")
