"""
This is the main file for the application.
It will be the entry point for the application.

By: Luis Gandarillas && Carlos Bravo
"""

import pwinput
from handle_user.access_handler import AccessHandler
from handle_certificates.root_certificate import ensure_root_certificate

def main():
	access_handler = AccessHandler()
	ensure_root_certificate()

	while True:
		try:
			access_handler.handle_access()
		except (KeyboardInterrupt, EOFError):
			print("\n")
			access_handler._handle_exit()

if __name__ == "__main__":
	main()