"""
src/handle_certificates/certificate_utils.py
"""

import os
from cryptography import x509
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

def generate_key_pair():
	"""Generates a private and public key pair."""
	private_key = rsa.generate_private_key(
		public_exponent=65537,
		key_size=2048,
	)
	public_key = private_key.public_key()
	return private_key, public_key

def save_key(file_path, key, is_private=True):
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
		else:
			key_file.write(
				key.public_bytes(
					encoding=serialization.Encoding.PEM,
					format=serialization.PublicFormat.SubjectPublicKeyInfo,
				)
			)

def save_certificate(file_path, certificate):
	"""Saves a certificate to a file."""
	with open(file_path, "wb") as cert_file:
		cert_file.write(certificate.public_bytes(encoding=serialization.Encoding.PEM))

def build_certificate(subject, issuer, public_key, private_key, is_root=False):
	"""Builds a certificate, optionally self-signed for root."""
	not_valid_before = datetime.now(timezone.utc)
	not_valid_after = not_valid_before + timedelta(days=90)
	builder = (
		x509.CertificateBuilder()
		.subject_name(subject)
		.issuer_name(subject if is_root else issuer)
		.public_key(public_key)
		.serial_number(x509.random_serial_number())
		.not_valid_before(not_valid_before)
		.not_valid_after(not_valid_after)
	)
	if is_root:
		builder = builder.add_extension(
			x509.BasicConstraints(ca=True, path_length=None), critical=True
		)
	else:
		builder = builder.add_extension(
			x509.BasicConstraints(ca=True, path_length=0), critical=True
		)
	return builder.sign(private_key, hashes.SHA256())

def verify_certificate(child_cert_path, parent_cert_path):
	"""Verifies that a child certificate was signed by the parent certificate."""
	with open(child_cert_path, "rb") as child_file:
		child_certificate = x509.load_pem_x509_certificate(child_file.read())

	with open(parent_cert_path, "rb") as parent_file:
		parent_certificate = x509.load_pem_x509_certificate(parent_file.read())

	parent_public_key = parent_certificate.public_key()

	try:
		parent_public_key.verify(
			child_certificate.signature,
			child_certificate.tbs_certificate_bytes,
			padding.PKCS1v15(),
			child_certificate.signature_hash_algorithm,
		)
		return True
	except Exception as e:
		print(f"Verification failed: {e}")
		return False
