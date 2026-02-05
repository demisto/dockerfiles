#!/usr/bin/env python
import argparse
import json
from pathlib import Path

import requests
import subprocess
import os
import re
import time
from typing import List, Tuple, Optional, Set

ARTIFACTS_FOLDER = Path(os.getenv("ARTIFACTS_FOLDER", "artifacts"))


def get_docker_image_size(docker_image, is_contribution: bool = False) -> str:
    """
    Get the size of the image from docker hub or locally, depending on whether we're contributing or not.

    Arguments:
        docker_image {string} -- the full name of the image
        is_contribution {bool} -- flag whether we should get the image size from Dockerhub, or locally

    Returns:
    - `str` containing the Docker image in MB, e.g. '12.34 MB'.
    """
    size = "N/A"
    if not is_contribution:
        for i in (1, 2, 3):
            try:
                name, tag = docker_image.split(":")
                res = requests.get(
                    "https://hub.docker.com/v2/repositories/{}/tags/{}/".format(
                        name, tag
                    )
                )
                res.raise_for_status()
                size_bytes = res.json()["images"][0]["size"]
                size = "{0:.2f} MB".format(float(size_bytes) / 1024 / 1024)
                break
            except Exception as ex:
                print(
                    "Attempt [{}] failed getting image size for image: {}. Err: {}".format(
                        i, docker_image, ex
                    )
                )
                if i != 3:
                    print("Sleeping 5 seconds and trying again...")
                    time.sleep(5)
    else:
        docker_image_tar = ARTIFACTS_FOLDER / convert_docker_image_tar(docker_image)
        if docker_image_tar.exists():
            size_bytes = docker_image_tar.stat().st_size
            size = "{0:.2f} MB".format(float(size_bytes) / 1024 / 1024)
        else:
            print(f"Docker image '{docker_image_tar}' doesn't exist in filesystem")
    return size


def convert_docker_image_tar(docker_image: str) -> str:
    """
    Helper function to convert the Docker image to a valid path.
    For example, `devdemisto/bottle2:1.0.0.89478.tar.gz` -> `devdemisto_bottle2:1.0.0.89478.tar.gz`.

    Arguments:
    - `docker_image` (``str``): The docker image filename.

    Returns:
    - `str` of the fixed Docker image TAR.
    """
    return f"{docker_image.replace('/', '__')}.tar.gz"


def get_pr_details(
    docker_image: str, upload_mode: bool, files_to_prs: Optional[str]
) -> List[Tuple[int, str]]:
    pr_details = []
    if upload_mode:
        if not files_to_prs or not Path(files_to_prs).exists():
            print(f"{files_to_prs} not found. Cannot determine PR number.")
            return []

        with open(files_to_prs) as f:
            file_to_prs_data = json.load(f)

        image_name = docker_image.split(":")[0].split("/")[1]
        # The key in file_to_prs might be just the directory, or could include Dockerfile
        prs = file_to_prs_data["file_to_prs"].get(f"docker/{image_name}", [])
        if not prs:
            prs = file_to_prs_data["file_to_prs"].get(
                f"docker/{image_name}/Dockerfile", []
            )

        if not prs:
            print(f"No PRs found for image: {image_name}")
            return []

        pr_numbers: Set[int] = set()
        for pr in prs:
            pr_numbers.add(pr["number"])

        for pr_num in pr_numbers:
            pr_details.append(
                (
                    pr_num,
                    f"https://api.github.com/repos/demisto/dockerfiles/issues/{pr_num}",
                )
            )
        return pr_details

    branch_name = os.getenv("CI_COMMIT_REF_NAME")
    if not branch_name:
        print("CI_COMMIT_REF_NAME not set. Cannot determine PR number.")
        return []

    m = re.match(r"(\d+)/.*", branch_name)
    if not m:
        print(f"Could not extract PR number from branch name: {branch_name}")
        return []

    pr_num = int(m.group(1))
    pr_details.append(
        (pr_num, f"https://api.github.com/repos/demisto/dockerfiles/issues/{pr_num}")
    )
    return pr_details


def post_comment(pr_url: str, message: str, dry_run: bool):
    if dry_run:
        print(f"[DRY-RUN] Would have posted comment to {pr_url}:")
        print(message)
    else:
        print(f"Going to post comment to {pr_url}:\n\n{message}")
        res = requests.post(
            f"{pr_url}/comments",
            json={"body": message},
            auth=(os.environ["XSOAR_BOT_GITHUB_TOKEN"], "x-oauth-basic"),
        )
        try:
            res.raise_for_status()
        except Exception as ex:
            print(f"Failed comment post to {pr_url}: {ex}")


def add_label(pr_num: int, label: str, dry_run: bool):
    if dry_run:
        print(f"[DRY-RUN] Would have added label '{label}' to PR #{pr_num}")
    else:
        print(f"Adding '{label}' label to PR #{pr_num}")
        url = f"https://api.github.com/repos/demisto/dockerfiles/issues/{pr_num}/labels"
        res = requests.post(
            url,
            json={"labels": [label]},
            auth=(os.environ["XSOAR_BOT_GITHUB_TOKEN"], "x-oauth-basic"),
        )
        try:
            res.raise_for_status()
        except Exception as ex:
            print(f"Failed to add label to PR #{pr_num}: {ex}")


def main():
    desc = """Post a message to github about the created image. Relies on environment variables:
XSOAR_BOT_GITHUB_TOKEN: api key of user to use for posting
CI_COMMIT_REF_NAME: The branch name to use to get the PR number.
    """
    parser = argparse.ArgumentParser(
        description=desc, formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "docker_image",
        help="The docker image with tag version to use. For example: devdemisto/python3:1.5.0.27",
    )
    parser.add_argument(
        "--is_contribution",
        help="Whether the PR is a contribution or not",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--upload",
        help="Whether running in upload mode",
        action="store_true",
        default=False,
    )
    parser.add_argument("--files-to-prs", help="Path to file_to_prs.json file")
    parser.add_argument(
        "--dry-run", help="Do not post to github", action="store_true", default=False
    )
    args = parser.parse_args()
    print("Posting to github about image: " + args.docker_image)

    pr_details_list = get_pr_details(args.docker_image, args.upload, args.files_to_prs)
    if not pr_details_list:
        print("No PRs found to comment on.")
        return

    inspect_format = f"""
{{{{ range $env := .Config.Env }}}}{{{{ if eq $env "DEPRECATED_IMAGE=true" }}}}## 🔴 IMPORTANT: This image is deprecated 🔴{{{{ end }}}}{{{{ end }}}}
## Docker Metadata
- Image Size: `{get_docker_image_size(args.docker_image, is_contribution=args.is_contribution)}`
- Image ID: `{{{{ .Id }}}}`
- Created: `{{{{ .Created }}}}`
- Arch: `{{{{ .Os }}}}`/`{{{{ .Architecture }}}}`
{{{{ if .Config.Entrypoint }}}}- Entrypoint: `{{{{ json .Config.Entrypoint }}}}`
{{{{ end }}}}{{{{ if .Config.Cmd }}}}- Command: `{{{{ json .Config.Cmd }}}}`
{{{{ end }}}}- Environment:{{{{ range .Config.Env }}}}{{{{ "\\n" }}}}  - `{{{{ . }}}}`{{{{ end }}}}
- Labels:{{{{ range $key, $value := .Config.Labels }}}}{{{{ "\\n" }}}}  - `{{{{ $key }}}}:{{{{ $value }}}}`{{{{ end }}}}
"""
    docker_info = subprocess.check_output(
        ["docker", "inspect", "-f", inspect_format, args.docker_image]
    ).decode()
    base_name = args.docker_image.split(":")[0]
    mode = "Dev"
    if base_name.startswith("demisto/"):
        mode = "Production"
    title = f"# Docker Image Ready - {mode}\n\n"
    if args.is_contribution:
        saved_docker_image = convert_docker_image_tar(args.docker_image)
        message = (
            title
            + "Docker automatic build has completed. The Docker image is available from the assigned reviewer to be loaded locally.\n\n"
            + "To load it locally run the following command:\n"
            + "```bash\n"
            + f"gunzip {saved_docker_image} | docker load\n"
            + "```\n"
            + docker_info
        )
    else:
        message = (
            title
            + "Docker automatic build has deployed your docker image: {}\n".format(
                args.docker_image
            )
            + "It is available now on docker hub at: https://hub.docker.com/r/{}/tags\n".format(
                base_name
            )
            + "Get started by pulling the image:\n"
            + "```\n"
            + "docker pull {}\n".format(args.docker_image)
            + "```\n"
            + docker_info
        )

    for pr_num, pr_url in pr_details_list:
        post_comment(pr_url, message, args.dry_run)
        if args.upload:
            add_label(pr_num, "production", args.dry_run)


if __name__ == "__main__":
    main()
