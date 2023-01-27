import yaml


def load_internet_config(path="./config.yaml") -> dict:
    with open(path, 'r') as file:
        config = yaml.load(file, Loader=yaml.FullLoader)

    print(f"==>Config file loaded from {path}!")
    print(config)

    return config


if __name__ == '__main__':
    load_internet_config()