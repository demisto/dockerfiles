import json


def get_pipfile_lock_data(pipfile_lock_path):
    with open(pipfile_lock_path, 'r') as f:
        return json.load(f)

def get_dockerfile_content(dockerFilePath):
    with open(dockerFilePath, 'r') as fp:
        return fp.read()

class BaseImagesStore:
    def __init__(self):
        self.base_images = {
            "demisto/python": ("ironbank/opensource/palo-alto-networks/demisto/python", "2"),
            "demisto/python-deb": ("ironbank/opensource/palo-alto-networks/demisto/python", "2"),
            "demisto/python3":("ironbank/opensource/palo-alto-networks/demisto/python3", "3"),
            "demisto/python3-deb": ("ironbank/opensource/palo-alto-networks/demisto/python3", "3")
        }

    def add_base(self, baseDockerHub, baseIronbank):
        self.base_images[baseDockerHub] = baseIronbank
    
    def del_base(self, baseIronBank):
        del self.base_images[baseIronBank]

    def get_inventory(self):
        return self.base_images