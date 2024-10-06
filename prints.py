"""
This file contains the print functions for the program.
"""

class PrintManager:
    COLOR_RED = "\033[91m"
    COLOR_GREEN = "\033[92m"
    COLOR_BLUE = "\033[94m"
    COLOR_RESET = "\033[0m"

    def apply_color(self, text: str, color: str) -> str:
        return f"{color}{text}{self.COLOR_RESET}"

    def print_welcome_msg(self):
        msg = r""",--.   ,--.,------.,--.    ,-----. ,-----. ,--.   ,--.,------.
|  |   |  ||  .---'|  |   '  .--./'  .-.  '|   `.'   ||  .---'
|  |.'.|  ||  `--, |  |   |  |    |  | |  ||  |'.'|  ||  `--,
|   ,'.   ||  `---.|  '--.'  '--'\'  '-'  '|  |   |  ||  `---.
'--'   '--'`------'`-----' `-----' `-----' `--'   `--'`------'"""
        print(self.apply_color(msg, self.COLOR_BLUE))

    def print_exit_msg(self):
        msg = r""",------.,--.   ,--.,--.,--------.
|  .---' \  `.'  / |  |'--.  .--'
|  `--,   .'    \  |  |   |  |
|  `---. /  .'.  \ |  |   |  |
`------''--'   '--'`--'   `--'"""
        print(self.apply_color(msg, self.COLOR_RED))