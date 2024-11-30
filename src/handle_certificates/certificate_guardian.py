"""
src/handle_certificates/certificate_guardian.py
"""

import os
from cryptography import x509
from datetime import datetime
from handle_certificates.certificate_utils import verify_certificate
from print_manager import PrintManager

class CertificateGuardian:
	def __init__(self):
		self.print_manager = PrintManager()

	def validate_root_certificate(self, root_cert_path):
		"""Validates the root certificate."""
		try:
			with open(root_cert_path, "rb") as root_file:
				root_cert = x509.load_pem_x509_certificate(root_file.read())

			if root_cert.not_valid_after < datetime.utcnow():
				self.print_manager.print_error("[GUARDIAN LOG] Root certificate has expired!")
				return False
			self.print_manager.print_debug("[GUARDIAN LOG] Root certificate is valid.")
			return True
		except Exception as e:
			self.print_manager.print_error(f"[GUARDIAN LOG] Failed to validate root certificate: {e}")
			return False

	def validate_intermediate_certificate(self, intermediate_cert_path, root_cert_path):
		"""Validates an intermediate certificate."""
		if not verify_certificate(intermediate_cert_path, root_cert_path):
			self.print_manager.print_error("[GUARDIAN LOG] Intermediate certificate verification failed!")
			return False
		with open(intermediate_cert_path, "rb") as inter_file:
			intermediate_cert = x509.load_pem_x509_certificate(inter_file.read())
		if intermediate_cert.not_valid_after < datetime.utcnow():
			self.print_manager.print_error("[GUARDIAN LOG] Intermediate certificate has expired!")
			return False
		self.print_manager.print_debug("[GUARDIAN LOG] Intermediate certificate is valid.")
		return True

	def validate_user_certificate(self, user_cert_path, intermediate_cert_path):
		"""Validates a user certificate."""
		if not verify_certificate(user_cert_path, intermediate_cert_path):
			self.print_manager.print_error("[GUARDIAN LOG] User certificate verification failed!")
			return False
		with open(user_cert_path, "rb") as user_file:
			user_cert = x509.load_pem_x509_certificate(user_file.read())
		if user_cert.not_valid_after < datetime.utcnow():
			self.print_manager.print_error("[GUARDIAN LOG] User certificate has expired!")
			return False
		self.print_manager.print_debug("[GUARDIAN LOG] User certificate is valid.")
		return True
