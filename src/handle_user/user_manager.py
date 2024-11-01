"""
src/user_manager.py
Refactored to delegate registration and login functionalities.
By: Luis Gandarillas && Carlos Bravo
"""

import os
import json
from print_manager import PrintManager

USERS_DATABSE = 'data/users.json'
printer = PrintManager()

def load_users():
	"""Load user data from the encrypted database file."""

	os.makedirs(os.path.dirname(USERS_DATABSE), exist_ok=True)

	if not os.path.exists(USERS_DATABSE):
		with open(USERS_DATABSE, 'w') as file:
			file.write("{}")
		return {}
	try:
		with open(USERS_DATABSE, 'r') as file:
			return json.load(file)
	except Exception as e:
		printer.print_error(f"Failed to load users: {e}")
		return {}

def save_users(users):
	"""Save user data to the database file."""

	os.makedirs(os.path.dirname(USERS_DATABSE), exist_ok=True)

	with open(USERS_DATABSE, 'w') as file:
		json.dump(users, file, indent=4)