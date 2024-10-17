"""
src/cryptography_utils.py
This module provides utility functions for cryptography.
"""

import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def generate_salt():
    """Generate a unique salt using os.urandom for each user."""
    return os.urandom(16)

def derive_key(password, salt):
    """Derive an encryption key from the user's password and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))
