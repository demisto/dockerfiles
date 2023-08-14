#!/usr/bin/env python3
import sys
from typing import List, Tuple
import argparse

if(sys.version_info[0] < 3 or sys.version_info[1] < 7):
    print("This script requires python version 3.7 and above. Please make sure to run with the proper version. Aborting...")
    sys.exit(1)


def get_operator_and_version(version: str) -> Tuple[List,str]:
    """Gets the version and the operator.
    
    Args:
        version (str): The version.

    Returns:
        Tuple[Tuple,str]: A Tuple of a list with the parsed version and the operator.
    """
    operator_list = ["^","<=",">=","<",">","!=","~=", "~","===", "==", "="]
    returned_operator = ""
    for operator in operator_list:
        if operator in version:
            operator_index = version.index(operator)
            version  = version[operator_index+len(operator):]
            returned_operator = operator
            break
    return version.split("."),returned_operator
 
def parse_and_match_versions(docker_python_version: str,file_python_version: str,
                             file_type:str) -> Tuple[bool,str]:
    """Parse the versions and validate versions matching.
    Args:
        docker_python_version (str): The python version from the docker image.
        file_python_version (str): The python version from the pipfile/pyproject.toml.

    Returns:
        Tuple[bool,str]: True for success, False otherwise.
        The version that should be written.
    """

    
    parsed_file_version,file_operator=get_operator_and_version(file_python_version)
    docker_version,_=get_operator_and_version(docker_python_version)
    operator = "~" if file_type == "pyproject.toml" else ""
    correct_version = ""
    if len(docker_version) >= 2:
        correct_version = f"{operator}{docker_version[0]}.{docker_version[1]}"
    else:
        correct_version = f"{operator}{docker_version[0]}.0"
    
    # if we have "^3.10,<3.11" as python version.
     # Define a standard to the version should be in "~X.Y" or "X.Y" format.
    if (len(file_python_version.split(",")) > 1 or
    file_operator not in ["", "~"] or
    "*" in file_python_version or
    file_python_version !=correct_version):
        return False, correct_version
    else: # file_python_version == correct_version
        return True, ""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('docker_python_version')
    parser.add_argument('file_python_version')
    parser.add_argument('image_name')
    parser.add_argument('file_type')
    args = parser.parse_args()
    print(args)
    docker_python_version: str = args.docker_python_version
    file_python_version: str = args.file_python_version
    image_name: str =  args.image_name
    file_type: str = args.file_type

    # There are images without python like powershell.
    if not docker_python_version:
        return 1
    format: str = "~X.Y" if file_type == "pyproject.toml" else "X.Y"
    result, correct_version = parse_and_match_versions(docker_python_version, file_python_version, file_type)
    if result:
        print(f"[SUCCESS] Versions verification. The base version {docker_python_version} is Corresponding to the {file_type} version {file_python_version}")
        return 0
    else:
        msg = "[ERROR] Version mismatch or version is invalid format. "\
        f"The {file_type} version {file_python_version}"\
        f" does not match to the base version {docker_python_version}"\
        f" for {image_name}. "\
        f"Please change it to the {format} format."\
        f" Proposed change is: {correct_version}."
        print(msg)
        return 1


if __name__ == "__main__":
    sys.exit(main())
