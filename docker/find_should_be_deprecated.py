"""
This script is meant to assist in finding docker images that are not being used by content, and could therefore be
deprecated or marked devonly.
This script makes the assumption that the dockerfiles and content repositories are sister directories under the same
folder, if this isnt the case, modify the content_repo constant below.

This script takes no input argument
"""


import functools
import os
import re
import subprocess
from pathlib import Path

dockerfiles_repo_prefix = Path(__file__).parent.parent.resolve()
content_repo = (
            Path(__file__).parent.parent.parent / "content").resolve()  # probably. Change if its in a different place


@functools.lru_cache
def get_dockers_used_by_content(filter_deprecated_out=True) -> set:
    ret_set = set()
    for out in subprocess.getoutput(
            f'grep -Ro --include \*.yml "demisto/[A-Za-z0-9-]*:" {content_repo}').split('\n'):
        (file, image, _) = out.split(':')
        with open(file) as f:
            text = f.read()
            # if deprecated : true isnt nested, the script is deprecated
            deprecated = len(re.findall('^deprecated ?: ?true', text, flags=re.MULTILINE)) > 0
            if not (filter_deprecated_out and deprecated):
                ret_set.add(image)

    return ret_set


def is_docker_deprecated(docker):
    return get_field_from_buildconf(docker, "deprecated", "false").lower() == "true"


def is_docker_devonly(docker):
    return get_field_from_buildconf(docker, "devonly", "false").lower() == "true"


def get_build_conf_file_path(docker):
    if docker.startswith("demisto"):
        docker = docker.split("/")[1]
    return f'{dockerfiles_repo_prefix}/docker/{docker}/build.conf'


def get_field_from_buildconf(docker, field, default_val="false"):
    file_path = get_build_conf_file_path(docker)
    try:
        with open(file_path) as f:
            for line in f:
                if field in line:
                    return line.split('=')[1].strip()
    except:
        return default_val
    return default_val


def deprecate_docker(docker):
    """
    Will add deprecated=true to the build.conf
    :param docker:
    :return:
    """
    with open(get_build_conf_file_path(docker), 'a') as f:
        f.write('deprecated=true\ndeprecated_reason=Image not in use by non-deprecated content item.')


def is_base_image(image) -> bool:
    grep_cmd = f"grep --include *Dockerfile -R '{image}' {dockerfiles_repo_prefix}"
    result = subprocess.run(grep_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0 and result.stdout:
        return True
    else:
        return False


def main():
    # used_dockers = get_used_dockers()
    # should_be_deprecated = get_used_dockers(False) - used_dockers

    dockers_in_dir = {f"demisto/{file}" for file in get_dockerfiles_in_repo()}

    # find dockers not used by non-deprecated content items
    non_used_images = {docker for docker in dockers_in_dir if
                       f'{docker}' not in get_dockers_used_by_content()
                       and not is_docker_deprecated(docker) and not is_docker_devonly(docker)}

    base_images = {image for image in non_used_images if is_base_image(image)}
    print(f"the following wont be included {base_images=}")
    should_be_deprecated = non_used_images - base_images
    print("The following dockers should be deprecated but arent")

    print(f"{len(should_be_deprecated)=}{should_be_deprecated}")

    print(
        f"The following dockers are not devonly but not used by content, {len(should_be_deprecated)=} {should_be_deprecated}")

    for docker in should_be_deprecated:
        if input(f"deprecate {docker}? (y/n)") == "y":
            deprecate_docker(docker)


def get_dockerfiles_in_repo():
    return {path for path in
            os.listdir(f'{dockerfiles_repo_prefix}/docker')
            if Path(f"{dockerfiles_repo_prefix}/docker/{path}/Dockerfile").is_file()
            }


if __name__ == '__main__':
    main()
