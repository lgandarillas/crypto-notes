"""
This is the main file for the application.
It will be the entry point for the application.

By: Luis Gandarillas && Carlos Bravo
"""

import pwinput
from src.prints import PrintManager
from src.mode_handler import ModeHandler

def main():
	printer = PrintManager()
	printer.print_welcome_msg()

	encryption_key_prompt = printer.apply_color("Enter the encryption key for the database: ", printer.COLOR_BLUE)
	encryption_key = pwinput.pwinput(encryption_key_prompt, mask='*').strip()
	mode_handler = ModeHandler(printer, encryption_key)
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