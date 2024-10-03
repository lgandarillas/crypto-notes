"""
This is the main file for the application.
It will be the entry point for the application.

By: Luis Gandarillas && Carlos Bravo
"""

import readline
from prints import PrintManager

def setup_readline_history():
    """Add basic commands to the readline history."""
    for cmd in ["register", "login", "exit"]:
        readline.add_history(cmd)

def handle_mode(mode: str, printer: PrintManager) -> None:
    """Handle the user's selected mode."""
    if mode == "register":
        print(f"You selected {printer.COLOR_BLUE}register{printer.COLOR_RESET}\n")
    elif mode == "login":
        print(f"You selected {printer.COLOR_BLUE}login{printer.COLOR_RESET}\n")
    elif mode == "exit":
        printer.print_exit_msg()
        return False
    else:
        print(f"Invalid mode: {printer.COLOR_RED}{mode}{printer.COLOR_RESET}\n")
    return True

def main():
    printer = PrintManager()
    printer.print_welcome_msg()

    setup_readline_history()

    while True:
        try:
            # Get the users mode
            mode = input(f"Select a mode ({printer.COLOR_BLUE}register{printer.COLOR_RESET}, {printer.COLOR_BLUE}login{printer.COLOR_RESET}, {printer.COLOR_BLUE}exit{printer.COLOR_RESET}): ").strip().lower()
            if not handle_mode(mode, printer):
                break
        except KeyboardInterrupt:
            # Handle Ctrl+C by showing the exit message
            print("^C")
            printer.print_exit_msg()
            break

if __name__ == "__main__":
    main()