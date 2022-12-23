#!/usr/bin/env python3
import argparse
import requests


DOCKER_FILES_SUFFIX = ["Dockerfle", "Pipfile", "Pipfile.lock"]


def main():
    parser = argparse.ArgumentParser(description='Deploy a pack from a contribution PR to a branch')
    parser.add_argument('-c', '--changed_files', help='list of the changed files')
    args = parser.parse_args()
    changed_files = args.changed_files
    changed_files = args.changed_files.split(" ")
    
    validate_native_docker_image(changed_files)


def validate_native_docker_image(changed_files):
    if is_docker_being_updated(changed_files):
        response = requests.get("https://raw.githubusercontent.com/demisto/content/master/Tests/docker_native_image_config.json")
        print(response)
        # if is_update_related_to_native_docker(changed_files):
        #     return False
    return True


def is_docker_being_updated(changed_files):
    for file in changed_files:
        for suffix in DOCKER_FILES_SUFFIX:
            if file.endswith(suffix):
                return True
    return False


# def is_update_related_to_native_docker(changed_files):
#     dockers = []
#     for file in changed_files:
#         for suffix in DOCKER_FILES_SUFFIX:
#             if file.endswith(suffix):
                

# def get_supported_dockers():
#     supported_docker_images_dict = {}.get("native_images")
#     supported_dockers_ls = []
#     for native_docker in  supported_docker_images_dict.values():
#         supported_dockers_ls.extend(native_docker.get("supported_docker_images", []))
#     return supported_dockers_ls

if __name__ == '__main__':
    main()