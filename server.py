import os
import sys

from server_utils import Server
from utils import *

def main():
    config_path = input("Input the path of config file: [./config.yaml]")
    if config_path == "":
        config_path = "./config.yaml"
    config = load_internet_config(config_path)

    # sleep=-1 := sleep=rand(0,3)
    server = Server(config, sleep=3)

    while True:
        clear_screen()
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
            server.stop_udp()
            print("Bye!")
            exit(1)
        else:
            print("Invalid choice. Press enter to continue.")
            input()


if __name__ == '__main__':
    main()