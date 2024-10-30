"""
This is the main file for the application.
It will be the entry point for the application.

By: Luis Gandarillas && Carlos Bravo
"""

import pwinput
from print_manager import PrintManager
from mode_handler import ModeHandler

def main():
	printer = PrintManager()
	mode_handler = ModeHandler("server_encryptation_key")

	while True:
		try:
			mode = input(f"\nSelect a mode ({printer.COLOR_BLUE}register{printer.COLOR_RESET}, {printer.COLOR_BLUE}login{printer.COLOR_RESET}, {printer.COLOR_BLUE}exit{printer.COLOR_RESET}): ").strip().lower()
			if not mode_handler.handle_mode(mode):
				break
		except KeyboardInterrupt:
			print("^C")
			mode_handler.handle_exit()
			break

if __name__ == "__main__":
	main()