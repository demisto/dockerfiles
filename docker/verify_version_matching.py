#!/usr/bin/env python3

import re
import sys
from typing import Optional, List, Tuple


if(sys.version_info[0] < 3 or sys.version_info[1] < 7):
    print("This script requires python version 3.7 and above. Please make sure to run with the proper version. Aborting...")
    sys.exit(1)

_local_version_separators = re.compile(r"[\._-]")


def parse_local_version(local: str) -> List[Optional[int]]:
    """
    Takes a string like abc.1.twelve and turns it into ("abc", 1, "twelve").
    """
    if local is not None:
        return [
            int(part) if part.isnumeric() else part.lower()
            for part in _local_version_separators.split(local)
        ]
    return []


def get_operator_and_version(version) -> Tuple[List,str]:
    """Gets the version and the operator.
    
    Args:
        version (str): The version.

    Returns:
        Tuple[Tuple,str]: The return value. A Tuple of a list with the parsed version and the operator.
    """
    operator_list = ["^","<=",">=","<",">","!=","~=", "~","===", "==", "="]
    returned_operator = ""
    for operator in operator_list:
        if operator in version:
            operator_index = version.index(operator)
            version  = version[operator_index+len(operator):]
            returned_operator = operator
            break
    return parse_local_version(version),returned_operator
 
def parse_and_match_versions(docker_python_version: str,file_python_version: str,
                             file_type:str) -> Tuple[bool,str]:
    """Parse the versions and validate versions matching.
    Args:
        docker_python_version (str): The first parameter.
        file_python_version (str): The second parameter.

    Returns:
        Tuple[bool,str]: The return value. True for success, False otherwise.
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
    if len(file_python_version.split(",")) > 1:
        return False, correct_version
    # Define a standard to the version should be in "~X.Y" or "X.Y" format.
    elif file_operator != "" and file_operator != "~":
        return False, correct_version
    elif "*" in file_python_version:
        return False, correct_version
    elif file_python_version !=correct_version:
        return False, correct_version
    elif file_python_version == correct_version:
        return True, ""


def main():
    args = sys.argv[1:]
    docker_python_version: str = args[0]
    file_python_version: str = args[1]
    image_name: str =  args[2]
    file_type: str = args[3]
    format: str = "~X.Y" if file_type == "pyproject.toml" else "X.Y"
    result, correct_version = parse_and_match_versions(docker_python_version, file_python_version, file_type)
    if result:
        print("[SUCCESS] Versions verification")
        return 0
    else:
        msg = "[ERROR] Version mismatch or version is invalid format. "\
        f"The {file_type} version {file_python_version}"\
        f" does not match to the base version {docker_python_version}"\
        f" for {image_name}."\
        f"Please change it to the {format} format."\
        f" Proposed change is: {correct_version}."
        print(msg)
        return 1


if __name__ == "__main__":
    sys.exit(main())
