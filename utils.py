import os

import yaml
import platform


def load_internet_config(path="./config.yaml") -> dict:
    with open(path, 'r') as file:
        config = yaml.load(file, Loader=yaml.FullLoader)

    print(f"==>Config file loaded from {path}!")
    # print(config)

    return config


def clear_screen():
    os_type = platform.system().lower()
    if os_type == 'linux' or os_type == 'darwin':
        os.system('clear')  # for linux/macOS
    elif os_type == 'windows':
        os.system('cls')  # for Windows
    else:
        print("Unsupported operating system! Unable to clear the screen!")


if __name__ == '__main__':
    load_internet_config()