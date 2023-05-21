import json
from glob import glob
import re
from datetime import datetime
from pathlib import Path
from typing import List, Dict
from configparser import ConfigParser, MissingSectionHeaderError
from dateutil.parser import parse


BASE_IMAGE_REGEX = re.compile(r"(?:FROM [\S]+)")
INTERNAL_BASE_IMAGES = re.compile(r"(demisto\/|devdemisto\/)")
LAST_MODIFIED_REGEX = re.compile(r"# Last modified: [^\n]*")


def get_last_modified(docker_file_content: str) -> str:
    """
    Get the last modified section in dockerfile, if not exists return 1.1.2000 12:00:00 +00:00
    Args:
        docker_file_content (full docker file content):
    Returns:
        last modified string e.x. 'Sun, 14 Nov 2021 17:27:37 +0000'
    """

    last_modified_string = re.search(LAST_MODIFIED_REGEX, docker_file_content)
    if last_modified_string:
        last_modified_string = last_modified_string.group(0)
        last_modified_string = last_modified_string.replace("# Last modified: ", "")
        return last_modified_string

    return "2000-01-01T12:00:00.000000+00:00"


def parse_base_image(full_base_image_name: str) -> (str, str, str):
    """
    Get all the base image attributes
    Args:
        full_base_image_name (str): Full image name e.x. 'demisto/python3-deb:3.9.6.22912'

    Returns:
        (repo, image_name, tag)
    """

    if '/' not in full_base_image_name:
        repository = "library"
        full_image_name = full_base_image_name
    else:
        repository, full_image_name = full_base_image_name.split("/")

    image_name, tag = full_image_name.split(":")
    return repository, image_name, tag


def read_build_conf(dockerfile_path: str) -> Dict:
    """
    Reads the build conf and return its content as a dict.

    Returns:
        dict: where the keys are the key name in conf and its value.
    """
    build_conf_path = f"{dockerfile_path}/build.conf"
    try:
        with open(build_conf_path) as f:
            build_conf_content = f.read()

        build_conf_parser = ConfigParser()
        build_conf_parser.read_string(f'[config]\n{build_conf_content}')
        return dict(build_conf_parser['config'])

    except FileNotFoundError:
        print(f'Could not find the file {build_conf_path}')
        return {}

    except MissingSectionHeaderError as error:
        print(f'Could not parse {build_conf_path}, {error=}')
        return {}


def filter_ignored_files(files_list):
    try:
        with open(Path(__file__).with_name('autoupdate-config.json'), 'r') as f:
            ignored_files_by_name = {config['name']: config for config in json.load(f).get('ignored_dockerfiles')}
            ret_list = []
            for file in files_list:
                if not (config := ignored_files_by_name.get(file['name'])) or \
                        not config.get('permanent') and parse(config['valid_until']) < datetime.now():
                    ret_list.append(file)
            return ret_list
    except Exception as e:
        print(f'could not read ignored config {str(e)}')
        return files_list


def get_docker_files(base_path="docker/", devonly=False, external=False, internal=False) -> List[Dict]:
    """
    Get all the relevant dockerfiles from the repository.

    Args:
        base_path (str): base path for docker files
        devonly (bool): whether or not to get devonly images
        external (bool): whether or not to get dockerfiles with external base images
        internal (bool):whether or not to get dockerfiles with internal base images

    Returns:
        list of relevant files: [{'name','path,'content','base_image}]
    """
    dockerfiles_paths = glob(f"{base_path}/**/Dockerfile", recursive=True)
    files_list = []

    for path in dockerfiles_paths:
        dockerfile_dir_path = path.replace("/Dockerfile", "")
        build_conf_content = read_build_conf(dockerfile_dir_path)  # if does not exist will default to empty dict

        # skip if the docker is deprecated
        if build_conf_content.get('deprecated') == 'true':
            print(f"docker {dockerfile_dir_path} is deprecated, hence not updating it")
            continue

        # skip if the docker is only used for dev
        if build_conf_content.get('devonly') == 'true' and not devonly:
            print(f"docker {dockerfile_dir_path} is dev-only, hence not updating it")
            continue

        with open(path) as f:
            docker_file_content = f.read()
            base_image = re.search(BASE_IMAGE_REGEX, docker_file_content)

            if not base_image:
                # The dockerfile doesn't contain base image
                continue

            base_image = base_image.group(0)
            base_image = base_image.replace("FROM ", "")
            is_internal = re.search(INTERNAL_BASE_IMAGES, base_image)
            if (is_internal and internal) or (not is_internal and external):
                repo, image_name, tag = parse_base_image(base_image)
                last_modified = get_last_modified(docker_file_content)
                curr_dockerfile = {"path": path,
                                   "repo": repo,
                                   "image_name": image_name,
                                   "tag": tag,
                                   "last_modified": last_modified,
                                   "content": docker_file_content,
                                   "name": dockerfile_dir_path.split('/')[1],
                                   }

                files_list.append(curr_dockerfile)

    return filter_ignored_files(files_list)
