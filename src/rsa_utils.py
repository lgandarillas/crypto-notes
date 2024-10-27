"""
src/rsa_utils.py

This module contains utility functions for RSA encryption and decryption.
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
	"""Save the RSA keys to files."""
	private_key_path = f"data/{username}_private_key.pem"
	public_key_path = f"data/{username}_public_key.pem"

	with open(private_key_path, 'wb') as priv_file:
		priv_file.write(private_key)

	with open(public_key_path, 'wb') as pub_file:
		pub_file.write(public_key)

	printer.print_debug("[CRYPTO LOG] RSA keys saved; Files, n/a")

def load_rsa_private_key(printer, username, password):
	"""Load the RSA private key from a file."""
	private_key_path = f"data/{username}_private_key.pem"
	with open(private_key_path, 'rb') as key_file:
		private_key = serialization.load_pem_private_key(
			key_file.read(),
			password=password.encode(),
		)
	printer.print_debug("[CRYPTO LOG] RSA private key loaded; RSA, 2048 bits")
	return private_key

def encrypt_with_public_key(username, data):
	"""Encrypt data using the public key."""
	public_key_path = f"data/{username}_public_key.pem"
	with open(public_key_path, 'rb') as key_file:
		public_key = serialization.load_pem_public_key(
			key_file.read(),
		)

	encrypted = public_key.encrypt(
		data,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		)
	)
	return encrypted

def decrypt_with_private_key(username, encrypted_data, password):
	"""Decrypt data using the private key."""
	private_key = load_rsa_private_key(username, password)
	original_data = private_key.decrypt(
		encrypted_data,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		)
	)
	return original_data