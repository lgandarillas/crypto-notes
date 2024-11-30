"""
src/handle_certificates/certificate_guardian.py
"""

import os
from cryptography import x509
from datetime import datetime, timezone
from handle_certificates.certificate_utils import verify_certificate
from print_manager import PrintManager

class CertificateGuardian:
	def __init__(self):
		self.print_manager = PrintManager()

	def _get_not_valid_after(self, cert):
		"""Gets the not_valid_after datetime in a timezone-aware format."""
		if hasattr(cert, "not_valid_after_utc"):
			return cert.not_valid_after_utc
		else:
			return cert.not_valid_after.replace(tzinfo=timezone.utc)

	def validate_root_certificate(self, root_cert_path):
		"""Validates the root certificate."""
		try:
			with open(root_cert_path, "rb") as root_file:
				root_cert = x509.load_pem_x509_certificate(root_file.read())

			# Get offset-aware datetime
			not_valid_after = self._get_not_valid_after(root_cert)
			if not_valid_after < datetime.now(timezone.utc):
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
		try:
			with open(intermediate_cert_path, "rb") as inter_file:
				intermediate_cert = x509.load_pem_x509_certificate(inter_file.read())

			# Get offset-aware datetime
			not_valid_after = self._get_not_valid_after(intermediate_cert)
			if not_valid_after < datetime.now(timezone.utc):
				self.print_manager.print_error("[GUARDIAN LOG] Intermediate certificate has expired!")
				return False
			self.print_manager.print_debug("[GUARDIAN LOG] Intermediate certificate is valid.")
			return True
		except Exception as e:
			self.print_manager.print_error(f"[GUARDIAN LOG] Failed to validate intermediate certificate: {e}")
			return False

	def validate_user_certificate(self, user_cert_path, intermediate_cert_path):
		"""Validates a user certificate."""
		if not verify_certificate(user_cert_path, intermediate_cert_path):
			self.print_manager.print_error("[GUARDIAN LOG] User certificate verification failed!")
			return False
		try:
			with open(user_cert_path, "rb") as user_file:
				user_cert = x509.load_pem_x509_certificate(user_file.read())

			# Get offset-aware datetime
			not_valid_after = self._get_not_valid_after(user_cert)
			if not_valid_after < datetime.now(timezone.utc):
				self.print_manager.print_error("[GUARDIAN LOG] User certificate has expired!")
				return False
			self.print_manager.print_debug("[GUARDIAN LOG] User certificate is valid.")
			return True
		except Exception as e:
			self.print_manager.print_error(f"[GUARDIAN LOG] Failed to validate user certificate: {e}")
			return False
