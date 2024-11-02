"""
src/rsa_utils.py

This module contains utility functions for RSA encryption and decryption.
By: Luis Gandarillas && Carlos Bravo
"""

import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

def generate_rsa_keys(printer, password):
	"""Generates RSA private and public keys."""

	private_key = rsa.generate_private_key(
		public_exponent=65537,
		key_size=2048,
	)
	public_key = private_key.public_key()

	pem_private = private_key.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.PKCS8,
		encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
	)

	pem_public = public_key.public_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PublicFormat.SubjectPublicKeyInfo
	)
	printer.print_debug("[CRYPTO LOG] RSA keys generated; RSA, 2048 bits")
	return pem_private, pem_public

def save_rsa_keys(printer, private_key, public_key, username):
	"""Saves the RSA public key to data/keys/public and private key to data/keys/username."""
	keys_dir = "data/keys"
	public_key_path = f"{keys_dir}/public/{username}_public_key.pem"
	private_key_path = f"{keys_dir}/{username}/{username}_private_key.pem"

	os.makedirs(f"{keys_dir}/public", exist_ok=True)
	os.makedirs(f"{keys_dir}/{username}", exist_ok=True)

	if private_key:
		with open(private_key_path, 'wb') as priv_file:
			priv_file.write(private_key)
		printer.print_debug(f"[CRYPTO LOG] RSA private key saved to {private_key_path}")

	with open(public_key_path, 'wb') as pub_file:
		pub_file.write(public_key)
	printer.print_debug(f"[CRYPTO LOG] RSA public key saved to {public_key_path}")