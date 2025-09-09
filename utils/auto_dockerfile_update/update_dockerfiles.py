import os
import argparse
from get_dockerfiles import get_docker_files, get_file_path_and_docker_version_if_exist
from get_latest_tag import get_latest_tag, parse_versions
from typing import Dict, List, Tuple
import dateutil
from git import Repo, GitCommandError
import re
from get_dockerfiles import LAST_MODIFIED_REGEX
from datetime import datetime, timezone
from functools import reduce
import subprocess

BATCH_SIZE = 1
PIPFILE_PYTHON_VERSION_REGEX = re.compile(r"\n(python_version = \"([^\"]+)\")")
PYPROJECT_PYTHON_VERSION_REGEX = re.compile(r"\n(python = \"([^\"]+)\")")


def is_docker_file_outdated(
    dockerfile: Dict, latest_tag: str, last_updated: str = "", no_timestamp_updates=True
) -> bool:
    """
    Check if the dockerfile has the latest tag and if there is a new version of it.
    Args:
        dockerfile (Dict): docker file dict
        latest_tag (str): latest tag string
        last_updated (str): last update string
        no_timestamp_updates: whether to disable updates
    Returns:
        True if the latest tag is newer or the latest tag is the same but new updates
    """
    print(f'Checking if dockerfile {dockerfile.get("path")} is outdated')
    current_tag = dockerfile["tag"]
    current_tag_version = parse_versions(current_tag)
    latest_tag_version = parse_versions(latest_tag)
    if current_tag_version < latest_tag_version:
        return True
    elif current_tag == latest_tag and not no_timestamp_updates:
        if last_updated and dateutil.parser.parse(last_updated) > dateutil.parser.parse(
            dockerfile.get("last_modified")
        ):
            # if the latest tag update date is newer than the dockerfile
            return True

    return False


def extract_current_python_version(file_path: str) -> Tuple[str, str, bool]:
    """Extract the current python version from Pipfile or the pyproject.toml.

    Args:
        file_path (str): The file path to the Pipfile or the pyproject.toml file.

    Returns:
        Tuple[str,str, bool]: The python version in list and str.
    """
    python_version = ""
    try:
        with open(file_path, "r") as f:
            file_content = f.read()
        if "Pipfile" in file_path:
            python_version = re.search(PIPFILE_PYTHON_VERSION_REGEX, file_content)
        elif "pyproject.toml" in file_path:
            python_version = re.search(PYPROJECT_PYTHON_VERSION_REGEX, file_content)
    except Exception as e:
        print(f"{e}: Can't read file {file_path}")
    if python_version:
        full_str_python_version = python_version.group(1)
        string_version_number = python_version.group(2)
        return string_version_number, full_str_python_version, True
    else:
        print(f"[ERROR] can't extract python version form:{file_path}")
        return "", "", False


def get_version_to_replace_with(version: str, file_path: str) -> str:
    """Gets the correct version to replace from the version string.

    Args:
        file_path (str): The file path to the Pipfile or the pyproject.toml file.
        version (str): The updated/old version.
    """
    version_array = version.split(".")
    is_numeric_version = all(version.isnumeric() for version in version_array)
    # if we get the docker image version it is only numeric
    # so we want to add it ~ to pyproject.
    # if we get numeric version it should be only for replace
    # it in the pyproject after lock failure.
    if is_numeric_version:
        if "pyproject" in file_path:
            return f"~{version_array[0]}.{version_array[1]}"
        return f"{version_array[0]}.{version_array[1]}"
    return version


def replace_python_version(
    file_path: str, version: str, full_str_python_version: str
) -> bool:
    """Replace the current python version in the Pipfile or the pyproject.toml.

    Args:
        file_path (str): The file path to the Pipfile or the pyproject.toml file.
        version (str): The updated/old version.
        full_str_python_version (str): The older version.
    """
    version_to_replace = get_version_to_replace_with(version, file_path)
    with open(file_path, "r") as f:
        file_content = f.read()
        python_version = (
            f'python_version = "{version_to_replace}"'
            if "Pipfile" in file_path
            else f'python = "{version_to_replace}"'
        )
        if full_str_python_version != python_version:
            print(f"[INFO] change {file_path}")
            file_content = file_content.replace(full_str_python_version, python_version)
            with open(file_path, "w") as f:
                f.write(file_content)
            return True
        return False


def change_python_version(file_path: str, str_version: str) -> Tuple[bool, str]:
    """Replace the current python version in the Pipfile or the pyproject.toml.

    Args:
        file_path (str): The file path to the Pipfile or the pyproject.toml file.
        version (str): The version.
        full_str_python_version (str): The older version.
    """
    (
        current_version,
        full_str_python_version,
        success_extraction,
    ) = extract_current_python_version(file_path)
    if success_extraction:
        result = replace_python_version(file_path, str_version, full_str_python_version)
        return result, current_version
    else:
        print(f"[ERROR] can't extract python version form: {file_path}")
    return False, ""


def run_lock(base_path_docker: str, pipfile_or_pyproject_path: str) -> bool:
    """Runs poetry lock --no-update or pipfile lock --keep-outdated.

    Args:
        base_path_docker (str): The DockerFile path.
        pipfile_or_pyproject_path (str): The file path to the Pipfile
        or the pyproject.toml file.
    """
    base_path = base_path_docker.replace("/Dockerfile", "")
    current_directory = os.getcwd()
    os.chdir(f"{current_directory}/" + base_path)
    try:
        if "Pipfile" in pipfile_or_pyproject_path:
            # waits for the process to end.
            completed_process = subprocess.run(
                ["pipenv", "lock", "--keep-outdated"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            if completed_process.returncode != 0:
                return False
        elif "pyproject.toml" in pipfile_or_pyproject_path:
            completed_process = subprocess.run(
                ["poetry", "lock", "--no-update"],
                stderr=subprocess.PIPE,
                check=True,
                stdout=subprocess.DEVNULL,
            )
            if completed_process.returncode != 0:
                os.chdir(current_directory)
                return False
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Lock failed with error: {str(e.stderr)} for {base_path_docker}")
        return False
    except Exception as e:
        print(f"[ERROR] {e}: for {base_path_docker}")
        os.chdir(current_directory)
        return False
    finally:
        os.chdir(current_directory)
    return True


def update_python_version_pyproject_or_pipfile(
    dockerfile: Dict, latest_tag: str
) -> None:
    """
    Updating dockerfile content with the latest tag
    Args:
        dockerfile (Dict): Dockerfile dict.
        latest_tag (str): latest tag string.
    Returns:
        None
    """
    update_result = False
    image_name = dockerfile["image_name"]
    if "python" not in image_name:
        return
    if result_tuple := get_file_path_and_docker_version_if_exist(
        dockerfile, latest_tag
        ):
        path, docker_version = result_tuple
        update_result, old_version = change_python_version(
            path, docker_version
        )
        if update_result:
            lock_result = run_lock(dockerfile["path"], path)
            if not lock_result:
                print(
                        f"[ERROR] Got Error with lock for: {dockerfile['path']} " \
                        "revert pipfile/pyproject.toml changes"
                )
                change_python_version(path, old_version)


def update_dockerfile(dockerfile: Dict, latest_tag: str) -> None:
    """
    Updating dockerfile content with the latest tag
    Args:
        dockerfile (Dict): Dockerfile dict.
        latest_tag (str): latest tag string.
    Returns:
        None
    """

    old_base_image = f"{dockerfile['image_name']}:{dockerfile['tag']}"
    new_base_image = f"{dockerfile['image_name']}:{latest_tag}"
    old_dockerfile = dockerfile["content"]
    new_dockerfile = old_dockerfile.replace(old_base_image, new_base_image)
    last_modified_string = re.search(LAST_MODIFIED_REGEX, new_dockerfile)

    if last_modified_string:
        now = datetime.now()
        now = now.replace(tzinfo=timezone.utc)
        last_modified_string = last_modified_string.group(0)
        new_last_modified_string = f"# Last modified: {now.isoformat()}"
        new_dockerfile = new_dockerfile.replace(
            last_modified_string, new_last_modified_string
        )

    with open(dockerfile["path"], "w") as f:
        f.write(new_dockerfile)

    dockerfile["content"] = new_dockerfile


def update_external_base_dockerfiles(git_repo: Repo, no_timestamp_updates=True) -> None:
    """
    Update all the dockerfile with external base image
    Args:
        git_repo (Repo): current git repo
        no_timestamp_updates: whether to disable timestamp based updates
    Returns:
        None
    """
    docker_files = get_docker_files(external=True)
    for file in docker_files:
        latest_tag = get_latest_tag(file["repo"], file["image_name"], file["tag"])
        latest_tag_name = latest_tag["name"]
        latest_tag_last_updated = latest_tag.get("last_updated", "")

        if is_docker_file_outdated(
            file, latest_tag_name, latest_tag_last_updated, no_timestamp_updates
        ):
            branch_name = rf"autoupdate/Update_{file['repo']}_{file['image_name']}_from_{file['tag']}_to_{latest_tag_name}"
            update_and_push_dockerfiles(git_repo, branch_name, [file], latest_tag_name)
            print(f"Updated {file['path']}")
    print("Finished to update dockerfiles")


def create_dependencies_json(all_docker_files: List[Dict]) -> Dict:
    """
    Create a dictionary with all the docker images and dependent images.
    Args:
        all_docker_files (List): list of dockerfiles
    Returns:
        {'image name': [dependent dockerfile]}
    """
    dependency_json = {
        f"{file['repo']}/{file['image_name']}": [] for file in all_docker_files
    }

    for file in all_docker_files:
        dependency_json[f"{file['repo']}/{file['image_name']}"].append(file)

    return dependency_json


def batch(iterable, n=1):
    l = len(iterable)
    for ndx in range(0, l, n):
        yield iterable[ndx : min(ndx + n, l)]


def update_internal_base_dockerfile(git_repo: Repo) -> None:
    """
    Update internal docker images in batches
    Args:
        git_repo (Repo): the repository

    Returns:
        None
    """
    docker_files = get_docker_files(internal=True)
    dependency_json = create_dependencies_json(docker_files)
    for base_image, dependency_list in dependency_json.items():
        curr_repo, image_name = base_image.split("/")
        latest_tag = get_latest_tag(curr_repo, image_name, "")
        latest_tag_name = latest_tag["name"]
        latest_tag_last_updated = latest_tag["last_updated"]
        outdated_files = [
            file
            for file in dependency_list
            if is_docker_file_outdated(file, latest_tag_name, latest_tag_last_updated)
        ]
        for batch_slice in batch(outdated_files, BATCH_SIZE):
            image_names = reduce(
                lambda a, b: f"{a}-{b}", [file["name"] for file in batch_slice]
            )
            branch_name = rf"autoupdate/{base_image}_{image_names}_{latest_tag_name}"
            update_and_push_dockerfiles(
                git_repo, branch_name, batch_slice, latest_tag_name
            )
    print("Finished to update dockerfiles")


def update_and_push_dockerfiles(
    git_repo: Repo, branch_name: str, files: List[Dict], latest_tag_name: str
) -> None:
    """
    Update the dockerfiles and push the updated files to a new branch.
    Args:
        git_repo (Repo): Current repository
        branch_name (str): The new branch name.
        files (List[Dict]): list of dockerfiles dict.
        latest_tag_name (str): latest tag string.

    Returns:

    """
    print(f"Trying to create new branch: {branch_name}")
    original_branch = git_repo.active_branch
    if branch_name in git_repo.git.branch("--all"):
        print("Branch already exists.")
        return
    try:
        branch = git_repo.create_head(branch_name)
        branch.checkout()

        for file in files:
            update_python_version_pyproject_or_pipfile(file, latest_tag_name)
            update_dockerfile(file, latest_tag_name)

        changedFiles = [item.a_path for item in git_repo.index.diff(None)]
        print(f"[INFO] changed files are: {','.join(changedFiles)}")
        git_repo.git.add("*")
        git_repo.git.commit(m=f"Update Dockerfiles")
        git_repo.git.push("--set-upstream", "origin", branch)
        print(f"Created branch {branch_name} successfully")
    except GitCommandError as e:
        print(f"Error creating {branch_name}")
        print(e)
    finally:
        original_branch.checkout()


def main():
    parser = argparse.ArgumentParser(
        description="Update dockerfiles in the repo",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-t",
        "--type",
        help="Specify type of dockerfiles to update",
        choices=["internal", "external"],
        default="external",
    )
    parser.add_argument(
        "-tu",
        "--no-timestamp-updates",
        help="Should disable timestamp based updates",
        action="store_true",
    )
    args = parser.parse_args()
    repo = Repo(search_parent_directories=True)
    repo.config_writer().set_value("pull", "rebase", "false").release()
    if args.type == "internal":
        update_internal_base_dockerfile(repo)
    elif args.type == "external":
        print(f"{args.no_timestamp_updates=}")
        update_external_base_dockerfiles(repo, args.no_timestamp_updates)


if __name__ == "__main__":
    main()
