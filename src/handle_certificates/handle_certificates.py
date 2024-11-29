"""
src/handle_certificates/handle_certificates.py
"""

import os
from cryptography import x509
from print_manager import PrintManager
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import CertificateBuilder, NameOID
from cryptography.hazmat.primitives.asymmetric import rsa

print_manager = PrintManager()

def _generate_key_pair():
	"""Generates a private and public key pair."""
	private_key = rsa.generate_private_key(
		public_exponent=65537,
		key_size=2048,
	)
	public_key = private_key.public_key()
	print_manager.print_debug("[CERTIFICATE LOG] Private and public keys generated.")
	return private_key, public_key


def _build_root_certificate(subject, public_key, private_key):
	"""Builds a root certificate with the given subject and keys."""
	not_valid_before = datetime.now(timezone.utc)
	not_valid_after = not_valid_before + timedelta(days=90)
	root_certificate = (
		CertificateBuilder()
		.subject_name(subject)
		.issuer_name(subject)
		.public_key(public_key)
		.serial_number(x509.random_serial_number())
		.not_valid_before(not_valid_before)
		.not_valid_after(not_valid_after)
		.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
		.sign(private_key, hashes.SHA256())
	)
	print_manager.print_debug(f"[CERTIFICATE LOG] Certificate validity: {not_valid_before} - {not_valid_after}")
	return root_certificate


def _save_key(file_path, key, is_private=True):
	"""Saves a private or public key to a file."""
	with open(file_path, "wb") as key_file:
		if is_private:
			key_file.write(
				key.private_bytes(
					encoding=serialization.Encoding.PEM,
					format=serialization.PrivateFormat.TraditionalOpenSSL,
					encryption_algorithm=serialization.NoEncryption(),
				)
			)
			print_manager.print_debug(f"[CERTIFICATE LOG] Private key saved at {file_path}")
		else:
			key_file.write(
				key.public_bytes(
					encoding=serialization.Encoding.PEM,
					format=serialization.PublicFormat.SubjectPublicKeyInfo,
				)
			)
			print_manager.print_debug(f"[CERTIFICATE LOG] Public key saved at {file_path}")


def _save_certificate(file_path, certificate):
	"""Saves a certificate to a file."""
	with open(file_path, "wb") as cert_file:
		cert_file.write(certificate.public_bytes(encoding=serialization.Encoding.PEM))
	print_manager.print_debug(f"[CERTIFICATE LOG] Certificate saved at {file_path}")


def create_root_certificate():
	"""Creates a root certificate and saves it in the world directory."""
	root_dir = "data/certificates/world"
	os.makedirs(root_dir, exist_ok=True)
	cert_path = os.path.join(root_dir, "world_headquarters_certificate.pem")
	private_key_path = os.path.join(root_dir, "world_headquarters_private.pem")
	public_key_path = os.path.join(root_dir, "world_headquarters_public.pem")

	print_manager.print_debug("[CERTIFICATE LOG] Creating root certificate...")

	private_key, public_key = _generate_key_pair()

	subject = x509.Name([
		x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
		x509.NameAttribute(NameOID.ORGANIZATION_NAME, "World Headquarters CA"),
		x509.NameAttribute(NameOID.COMMON_NAME, "World Headquarters Root CA"),
	])
	print_manager.print_debug("[CERTIFICATE LOG] Subject details created.")

	root_certificate = _build_root_certificate(subject, public_key, private_key)

	_save_key(private_key_path, private_key, is_private=True)
	_save_key(public_key_path, public_key, is_private=False)
	_save_certificate(cert_path, root_certificate)