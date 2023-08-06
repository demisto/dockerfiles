#!/usr/bin/env python3

import os
import re
import sys
from typing import Optional, List
import requests
import urllib3

if(sys.version_info[0] < 3 or sys.version_info[1] < 7):
    print("This script requires python version 3.7 and above. Please make sure to run with the proper version. Aborting...")
    sys.exit(1)

req_session = requests.Session()

if os.getenv('TRUST_ANY_CERT'):
    req_session.verify = False
    urllib3.disable_warnings()
    
  
_local_version_separators = re.compile(r"[\._-]")


def parse_local_version(local: str) -> Optional[
    List[Optional[int]]]:
    """
    Takes a string like abc.1.twelve and turns it into ("abc", 1, "twelve").
    """
    if local is not None:
        return [
            int(part) if part.isnumeric() else part.lower()
            for part in _local_version_separators.split(local)
        ]
    return None


def compare_versions(versions_docker:List[Optional[int]],
                     versions_file:List[Optional[int]],
                     is_caret: bool) -> bool:
    """Compares the major|minor|revision versions.
    Args:
        versions_docker (List[Optional[int]]): The first parameter.
        versions_file (List[Optional[int]]): The second parameter.
        is_caret (bool): Indicating whether ^ appears in the version or not.

    Returns:
        bool: The return value. True for success, False otherwise.
    """
    for i, (version_docker, version_file) in enumerate(zip(versions_docker,
                                                           versions_file)):
        # caret is ^
        if is_caret:
            # the revision should be equal or bigger 
            if version_docker < version_file and i == 3:
                return False
            elif version_docker != version_file:
                return False
        else:
            if version_docker != version_file:
                return False
    return True
            
            
def parse_and_match_versions(docker_python_version: str,file_python_version: str)-> bool:
    """Parse the versions and validate versions matching.
    Args:
        docker_python_version (str): The first parameter.
        file_python_version (str): The second parameter.

    Returns:
        bool: The return value. True for success, False otherwise.
    """
    is_caret = False
    if "^" in file_python_version:
        is_caret = True
        file_python_version = file_python_version[1:]
    if compare_versions(
        parse_local_version(docker_python_version),
        parse_local_version(file_python_version),
        is_caret
    ):
        return True
    return False
    
    

def main():
    args = sys.argv[1:]
    docker_python_version: str = args[0]
    file_python_version: str = args[1]
    image_name: str =  args[2]
    if parse_and_match_versions(
        docker_python_version, file_python_version, image_name
    ):
        print("[SUCCESS] Versions verification")
    else:
        msg = "[ERROR] Version mismatch. " \
        f"The pipfile/pyproject.toml version {file_python_version}" \
        f" does not match to the base version {docker_python_version}. for {image_name}"
        raise Exception(msg)



if __name__ == "__main__":
    main()
