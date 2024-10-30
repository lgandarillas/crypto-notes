"""
This is the main file for the application.
It will be the entry point for the application.

By: Luis Gandarillas && Carlos Bravo
"""

import pwinput
from user_access_handler import UserAccessHandler

def main():
	mode_handler = UserAccessHandler("server_encryptation_key")

	while True:
		try:
			mode_handler.handle_mode()
		except KeyboardInterrupt:
			print("^C")
			mode_handler.handle_exit()

if __name__ == "__main__":
	main()