"""
This is the main file for the application.
It will be the entry point for the application.

By: Luis Gandarillas && Carlos Bravo
"""

import pwinput
from handle_user.access_handler import AccessHandler

def main():
	access_handler = AccessHandler()

	while True:
		try:
			access_handler.handle_mode()
		except KeyboardInterrupt:
			print("^C")
			access_handler._handle_exit()
		except EOFError:
			print("^D")
			access_handler._handle_exit()

if __name__ == "__main__":
	main()