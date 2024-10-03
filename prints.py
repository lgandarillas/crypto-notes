"""
This file contains the print functions for the program.
"""

class PrintManager:
    COLOR_RED = "\033[91m"
    COLOR_BLUE = "\033[94m"
    COLOR_RESET = "\033[0m"

    def print_welcome_msg(self):
        print(self.COLOR_BLUE)
        print(r""",--.   ,--.,------.,--.    ,-----. ,-----. ,--.   ,--.,------.
|  |   |  ||  .---'|  |   '  .--./'  .-.  '|   `.'   ||  .---'
|  |.'.|  ||  `--, |  |   |  |    |  | |  ||  |'.'|  ||  `--,
|   ,'.   ||  `---.|  '--.'  '--'\'  '-'  '|  |   |  ||  `---.
'--'   '--'`------'`-----' `-----' `-----' `--'   `--'`------'""")
        print(self.COLOR_RESET)

    def print_exit_msg(self):
        print(self.COLOR_RED)
        print(r""",------.,--.   ,--.,--.,--------.
|  .---' \  `.'  / |  |'--.  .--'
|  `--,   .'    \  |  |   |  |
|  `---. /  .'.  \ |  |   |  |
`------''--'   '--'`--'   `--'""")
        print(self.COLOR_RESET)