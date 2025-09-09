from typing import Optional

from pathlib import Path
import argparse
import json
from datetime import datetime


def parse_config_contents(file_contents: str):
    return {
        line.split("=")[0].strip(): line.split("=")[1].strip()
        for line in file_contents.split('\n')
        if line and not line.isspace() and "#" not in line
    }


def get_entry_by_name(image_name, previous_json) -> Optional[dict]:
    """
    Given a deprecatedJson config, return the proper config for a given image name
    :param image_name: the image name to look up
    :param previous_json: the pre-existing file, used for preserving the entered time
    """
    matches = [entry for entry in previous_json if entry["image_name"] == image_name]
    match len(matches):
        case 0:
            return None
        case 1:
            return matches[0]
        case _:
            raise ValueError(f"More than 1 entry exits for image {image_name}")


def compare_deprecated_images(deprecated_json_1, deprecated_json_2):
    """
    Given two versions of deprecated_json file (newly-made and preexisting) will return image names only in each list
    """
    names_in_1 = {i["image_name"] for i in deprecated_json_1}
    names_in_2 = {i["image_name"] for i in deprecated_json_2}
    return names_in_1 - names_in_2, names_in_2 - names_in_1


def main():
    arg_parser = argparse.ArgumentParser(
        description="""Builds a new version of the deprecated json file based on the build.conf files
If in validate mode - will fail if the file is not a match to the existing deprecated.json file
If in fix more - will override the file with the correct version based on the build.conf files"""
    )
    arg_parser.add_argument("--exclude", default="")
    arg_parser.add_argument(
        "--deprecated_path", default="docker/deprecated_images.json"
    )
    arg_parser.add_argument("--docker_dir", default="docker")
    arg_parser.add_argument(
        "--fix",
        action="store_true",
        default=False,
        help="If flag is set will output the file fixed according to the build.conf files",
    )
    args = arg_parser.parse_args()
    excluded = args.exclude.split(",")
    with open(args.deprecated_path) as f:
        previous_json = json.load(f)
    deprecated_info = []
    for path in Path(args.docker_dir).iterdir():
        if path.is_dir() and path.name not in excluded:
            conf_path = path / "build.conf"
            if not conf_path.is_file():
                continue
            config_contents = Path(conf_path).read_text()
            config = parse_config_contents(config_contents)
            if config.get("deprecated", False):
                image_name = f"demisto/{path.name}"
                prev_entry = get_entry_by_name(image_name, previous_json)
                created_time = (
                    prev_entry["created_time_utc"]
                    if prev_entry
                    else str(datetime.now())
                ) # if already in the config take the time entered from previous version
                deprecated_info.append(
                    {
                        "image_name": image_name,
                        "reason": config.get("deprecated_reason", ""),
                        "created_time_utc": created_time,
                    }
                )
    if args.fix:
        with open(args.deprecated_path, "w") as f:
            json.dump(
                sorted(deprecated_info, key=lambda item: item["image_name"]),
                f,
                sort_keys=True,
                indent=4,
            )

    else:
        names_should_be_in_file, names_should_be_in_config = compare_deprecated_images(previous_json, deprecated_info)
        if names_should_be_in_file or names_should_be_in_config:
            raise ValueError(
                f"The deprecated_images.json file is not valid. Did you deprecate an image in this pr? Add it to docker/deprecated_images.json. You can use utils/validate_deprecated_dockers_json.py --fix to do so.\n"
                f"Set of items that are deprecated according to their build.conf but not in the deprecated_images.json: {names_should_be_in_file}\n"
                f"Set of items that are in the file but not deprecated according to the build.conf {names_should_be_in_config}"
            )
        print("deprecated_images.json file is valid")


if __name__ == "__main__":
    main()
