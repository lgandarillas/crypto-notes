"""
src/user_manager.py
Refactored to delegate registration and login functionalities.
By: Luis Gandarillas && Carlos Bravo
"""

import os
import json
from print_manager import PrintManager
from handle_user.register_handler import RegisterHandler
from handle_user.login_handler import LoginHandler

class UserManager:
	"""Manages user accounts, delegating registration and login."""

	def __init__(self, database='data/users.json'):
		self.printer = PrintManager()
		self.database = database
		self.users = self.load_users()
		self.register_handler = RegisterHandler(self)
		self.login_handler = LoginHandler(self)

	def load_users(self):
		"""Load user data from the encrypted database file."""
		if not os.path.exists(self.database):
			with open(self.database, 'w') as file:
				file.write("{}")
			return {}
		try:
			with open(self.database, 'r') as file:
				return json.load(file)
		except Exception as e:
			self.printer.print_error(f"Failed to load users: {e}")
			return {}

	def save_users(self):
		"""Save user data to the database file."""
		with open(self.database, 'w') as file:
			json.dump(self.users, file, indent=4)