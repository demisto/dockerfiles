import json


def get_pipfile_lock_data(pipfile_lock_path):
    with open(pipfile_lock_path, 'r') as f:
        return json.load(f)
