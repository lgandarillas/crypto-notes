"""
This file contains the print functions for the program.
"""

COLOR_RED = "\033[91m"
COLOR_BLUE = "\033[94m"
COLOR_RESET = "\033[0m"

def print_welcome_msg():
    print(COLOR_BLUE)
    print(r""",--.   ,--.,------.,--.    ,-----. ,-----. ,--.   ,--.,------.
|  |   |  ||  .---'|  |   '  .--./'  .-.  '|   `.'   ||  .---'
|  |.'.|  ||  `--, |  |   |  |    |  | |  ||  |'.'|  ||  `--,
|   ,'.   ||  `---.|  '--.'  '--'\'  '-'  '|  |   |  ||  `---.
'--'   '--'`------'`-----' `-----' `-----' `--'   `--'`------'""")
    print(COLOR_RESET)

def print_exit_msg():
    print(COLOR_RED)
    print(r""",------.,--.   ,--.,--.,--------.
|  .---' \  `.'  / |  |'--.  .--'
|  `--,   .'    \  |  |   |  |
|  `---. /  .'.  \ |  |   |  |
`------''--'   '--'`--'   `--'""")
    print(COLOR_RESET)