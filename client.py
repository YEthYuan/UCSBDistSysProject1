import os
import sys

from client_utils import Client
from utils import *

def main():
    config_path = input("Input the path of config file: [./config.yaml]")
    if config_path == "":
        config_path = "./config.yaml"
    config = load_internet_config(config_path)
    usr_list = []
    for item in config['clients']:
        usr_list.append(item['username'])

    while True:
        print("Username List: ", usr_list)
        username = input("Input a username to start: ")
        if username in usr_list:
            break
        else:
            print("Input Username Must in the configuration file! Press enter to continue.")
            input()
            os.system('clear')  # for linux/macOS
            # os.system('cls') for Windows

    pid = os.getpid()

    client = Client(pid=pid, username=username, config=config)

    while True:
        os.system('clear') # for linux/macOS
        # os.system('cls') for Windows
        print(f" --- Client {username} Interface --- \n")
        print("1. Get Current Balance")
        print("2. Make Transaction")
        print("3. Print the Current Blockchain")
        print("0. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            client.send_balance_inquery()
            print('=' * 30)
            print("Press enter to continue. ")
            input()
        elif choice == '2':
            to = input("Send money to: ")
            amount = input("Amount: ")
            client.transact(amount=int(amount), to=to)
            print('=' * 30)
            print("Press enter to continue. ")
            input()
        elif choice == '3':
            client.print_blockchain()
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