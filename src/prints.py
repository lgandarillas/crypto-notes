"""
src/prints.py

This file contains the print functions for the program.
"""

class PrintManager:
	COLOR_RED = "\033[91m"
	COLOR_GREEN = "\033[92m"
	COLOR_BLUE = "\033[94m"
	COLOR_GRAY = "\033[90m"
	COLOR_RESET = "\033[0m"

	def apply_color(self, text: str, color: str) -> str:
		"""Apply color formatting to the given text."""
		return f"{color}{text}{self.COLOR_RESET}"

	def print_welcome_msg(self):
		"""Print the welcome message with blue color."""
		msg = r"""		__		__   _								 _
		\ \	  / /__| | ___ ___  _ __ ___   ___	   | |_ ___
		 \ \ /\ / / _ \ |/ __/ _ \| '_ ` _ \ / _ \	  | __/ _ \
		  \ V  V /  __/ | (_| (_) | | | | | |  __/	  | || (_) |
 _____	 \_/\_/ \___|_|\___\___/|_| |_| |_|\___| _   _ \__\___/
| ____|_ __   ___ _ __ _   _ _ __ | |_ ___  __| | | \ | | ___ | |_ ___  ___
|  _| | '_ \ / __| '__| | | | '_ \| __/ _ \/ _` | |  \| |/ _ \| __/ _ \/ __|
| |___| | | | (__| |  | |_| | |_) | ||  __/ (_| | | |\  | (_) | ||  __/\__ \
|_____|_| |_|\___|_|   \__, | .__/ \__\___|\__,_| |_| \_|\___/ \__\___||___/
					   |___/|_|											 """
		print(self.apply_color(msg, self.COLOR_BLUE))

	def print_exit_msg(self):
		"""Print the exit message with red color."""
		msg = r""",------.,--.   ,--.,--.,--------.
|  .---' \  `.'  / |  |'--.  .--'
|  `--,   .'	\  |  |   |  |
|  `---. /  .'.  \ |  |   |  |
`------''--'   '--'`--'   `--'"""
		print(self.apply_color(msg, self.COLOR_RED))

	def print_error(self, message: str):
		"""Print error messages in red color to the standard error output."""
		error_msg = self.apply_color(message, self.COLOR_RED)
		print(error_msg, file=sys.stderr)

	def print_success(self, message: str):
		"""Print success messages in green color."""
		success_msg = self.apply_color(message, self.COLOR_GREEN)
		print(success_msg)

	def print_debug(self, message: str):
		"""Print debug messages in gray color."""
		debug_msg = self.apply_color(message, self.COLOR_GRAY)
		print(debug_msg)