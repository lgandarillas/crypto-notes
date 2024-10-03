"""
This is the main file for the application.
It will be the entry point for the application.

By: Luis Gandarillas && Carlos Bravo
"""

import readline
from prints import print_welcome_msg, print_exit_msg, COLOR_BLUE, COLOR_RED, COLOR_RESET

def main():
    print_welcome_msg()

    # Optional: Add some basic commands to the history initially
    readline.add_history("register")
    readline.add_history("login")
    readline.add_history("exit")

    while True:
        try:
            option = input("Select an option (register, login, exit): ").strip().lower()
            if option == "register":
                print(f"You selected {COLOR_BLUE}register{COLOR_RESET}\n")
            elif option == "login":
                print(f"You selected {COLOR_BLUE}login{COLOR_RESET}\n")
            elif option == "exit":
                print_exit_msg()
                break
            else:
                print(f"Invalid option: {COLOR_RED}{option}{COLOR_RESET}. Please try again.\n")
        except KeyboardInterrupt:
            # Handle Ctrl+C by showing the exit message
            print_exit_msg()
            break

if __name__ == "__main__":
    main()