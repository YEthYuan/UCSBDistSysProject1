import yaml


def load_internet_config(path="./config.yaml") -> dict:
    with open(path, 'r') as file:
        config = yaml.load(file, Loader=yaml.FullLoader)

    return config
