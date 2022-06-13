from glob import glob
import re
from typing import List, Dict

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


def is_dev_only(dockerfile_path=str) -> bool:
    """
    Check the build.conf for "devonly" flag.
    Args:
        dockerfile_path (str): the dockerfile's path

    Returns:

    """
    path = f"{dockerfile_path}/build.conf"
    try:
        with open(path) as f:
            content = f.read()
            if "devonly=true" in content:
                return True

    except FileNotFoundError:
        return False

    return False


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
        if is_dev_only(dockerfile_dir_path) and not devonly:
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
                                   "content": docker_file_content}

                files_list.append(curr_dockerfile)

    return files_list
