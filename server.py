import os
import sys

from server_utils import Server
from utils import *

def main():
    config_path = input("Input the path of config file: [./config.yaml]")
    if config_path == "":
        config_path = "./config.yaml"
    config = load_internet_config(config_path)

    server = Server(config)

    while True:
        os.system('clear') # for linux/macOS
        # os.system('cls') for Windows
        print(f" --- Server Interface --- \n")
        print("1. Get Balance Table")
        print("2. Reset Balance Table")
        print("0. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            server.print_balance()
            print('='*30)
            print("Press enter to continue. ")
            input()
        elif choice == '2':
            server.reset_balances()
            print('=' * 30)
            print("Press enter to continue. ")
            input()
        elif choice == '0':
            print("Bye!")
            exit(1)
        else:
            print("Invalid choice. Press enter to continue.")
            input()


if __name__ == '__main__':
    main()