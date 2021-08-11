
import json
import os

import requests
import urllib3
import yaml
from dockerfile_parse import DockerfileParser


def get_pipfile_lock_data(pipfile_lock_path):
    with open(pipfile_lock_path, 'r') as f:
        return json.load(f)


def get_dockerfile_content(docker_file_path):
    with open(docker_file_path, 'r') as fp:
        return fp.read()


def get_last_image_tag_ironbank(image_name):
    user_name = os.getenv('REGISTRYONE_USER')
    user_token = os.getenv('REGISTRYONE_ACCESS_TOKEN')
    base_image_basename = os.path.basename(image_name)
    url = "https://" + user_name + ":" + user_token + "@repo1.dso.mil/dsop/opensource/palo-alto-networks/demisto/{0}/-/raw/master/hardening_manifest.yaml".\
        format(base_image_basename)
    print(url)
    req_session = requests.Session()
    req_session.verify = False
    urllib3.disable_warnings()
    hardening_manifest_yaml = req_session.get(url)
    obj_yaml = yaml.load(hardening_manifest_yaml.text, Loader=yaml.FullLoader)
    return obj_yaml.get("tags")[0]


def get_base_image_from_dockerfile(docker_file_path):
    dockerfile_parser = DockerfileParser(docker_file_path)
    base_image, base_image_tag = dockerfile_parser.baseimage.split(":")
    return base_image, base_image_tag


class BaseImagesStore:
    def __init__(self):
        self.base_images = {
            "demisto/python": ("ironbank/opensource/palo-alto-networks/demisto/python", "2"),
            "demisto/python-deb": ("ironbank/opensource/palo-alto-networks/demisto/python", "2"),
            "demisto/python3": ("ironbank/opensource/palo-alto-networks/demisto/python3", "3"),
            "demisto/python3-deb": ("ironbank/opensource/palo-alto-networks/demisto/python3", "3")
        }

    def add_base(self, baseDockerHub, baseIronbank):
        self.base_images[baseDockerHub] = baseIronbank
    
    def del_base(self, baseIronBank):
        del self.base_images[baseIronBank]

    def get_inventory(self):
        return self.base_images