"""
This is the main file for the application.
It will be the entry point for the application.

By: Luis Gandarillas && Carlos Bravo
"""

import readline
from prints import print_welcome_msg, print_exit_msg

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
                print("You selected register\n")
            elif option == "login":
                print("You selected login\n")
            elif option == "exit":
                print_exit_msg()
                break
            else:
                print("Invalid option. Please try again.\n")
        except KeyboardInterrupt:
            # Handle Ctrl+C by showing the exit message
            print_exit_msg()
            break

if __name__ == "__main__":
    main()