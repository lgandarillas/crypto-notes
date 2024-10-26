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
	printer.print_welcome_msg()

	mode_handler = ModeHandler(printer, "server_encryptation_key")
	mode_handler.setup_readline_history()

	while True:
		try:
			mode = input(f"Select a mode ({printer.COLOR_BLUE}register{printer.COLOR_RESET}, {printer.COLOR_BLUE}login{printer.COLOR_RESET}, {printer.COLOR_BLUE}exit{printer.COLOR_RESET}): ").strip().lower()
			if not mode_handler.handle_mode(mode):
				break
		except KeyboardInterrupt:
			print("^C")
			mode_handler.handle_exit()
			break

if __name__ == "__main__":
	main()