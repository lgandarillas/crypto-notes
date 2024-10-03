"""
This is the main file for the application.
It will be the entry point for the application.

By: Luis Gandarillas && Carlos Bravo
"""

import readline
from prints import PrintManager

def main():
    printer = PrintManager()
    printer.print_welcome_msg()

    # Inicializar comandos básicos en el historial
    for cmd in ["register", "login", "exit"]:
        readline.add_history(cmd)

    while True:
        try:
            # Get the user's input
            option = input(f"Select an option ({printer.COLOR_BLUE}register{printer.COLOR_RESET}, {printer.COLOR_BLUE}login{printer.COLOR_RESET}, {printer.COLOR_BLUE}exit{printer.COLOR_RESET}): ").strip().lower()
            if option == "register":
                print(f"You selected {printer.COLOR_BLUE}register{printer.COLOR_RESET}\n")
            elif option == "login":
                print(f"You selected {printer.COLOR_BLUE}login{printer.COLOR_RESET}\n")
            elif option == "exit":
                printer.print_exit_msg()
                break
            else:
                print(f"Invalid option: {printer.COLOR_RED}{option}{printer.COLOR_RESET}.")
        except KeyboardInterrupt:
            # Handle Ctrl+C by showing the exit message
            printer.print_exit_msg()
            break

if __name__ == "__main__":
    main()