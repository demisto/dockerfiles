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


def compare_versions(versions_docker:List[Optional[int]],
                     versions_file:tuple) -> bool:
    """Compares the major|minor|revision versions.
    Args:
        versions_docker (List[Optional[int]]): The first parameter.
        versions_file (List[Optional[int]]): The second parameter.
        is_range (bool): Indicating whether ^,<,> appear in the version or not.

    Returns:
        bool: The return value. True for success, False otherwise.
    """
    is_version_range = versions_file[0] != versions_file[1]
    for i, (version_docker, version_file_low_boundary, version_file_high_boundary) in enumerate(
        zip(versions_docker,versions_file[0],versions_file[1])):
        if not is_version_range:
            if version_docker != version_file_low_boundary:
                return False
        else:
            if version_docker < version_file_low_boundary or version_docker > version_file_high_boundary:
                return False
    return True


def parse_version_range(version_1: str,version_2: str) -> tuple[str,str]:
    """Parse the versions ranges using regex.
    Args:
        version_1 (str): The first version.
        version_2 (str): The second version.

    Returns:
        tuple[str,str]: The return value. Tuple with lower and higher version range.
    """
    if version_1 == version_2:
        return version_1, version_2   
    low_version_boundary = None
    high_version_boundary = None
    if result_lower := re.search(r">=*(\d+.*)+|\^+(\d+.*)+",version_1):
        print("here")
        low_version_boundary = result_lower[1] or result_lower[2]
    elif result_lower := re.search(r">=*(\d+.*)+|\^+(\d+.*)+",version_2):
        low_version_boundary = result_lower[1] or result_lower[2]
    if result_higher := re.search(r"<=*(\d+.*)+",version_1):
        high_version_boundary = result_higher[1]
    elif result_higher := re.search(r"<=*(\d+.*)+",version_2):
        high_version_boundary = result_higher[1]  
    return low_version_boundary,high_version_boundary
            
            
def parse_and_match_versions(docker_python_version: str,file_python_version: str)-> bool:
    """Parse the versions and validate versions matching.
    Args:
        docker_python_version (str): The first parameter.
        file_python_version (str): The second parameter.

    Returns:
        bool: The return value. True for success, False otherwise.
    """
    version_range = file_python_version.split(",")
    parsed_docker_version=parse_local_version(docker_python_version)
    is_python_verson_range = len(version_range) > 1
    
    parsed_file_version=((parse_version_range(version_range[0],version_range[1]))
                         if is_python_verson_range 
                         else (parse_version_range(file_python_version,file_python_version)))
    parsed_file_version = (parse_local_version(parsed_file_version[0]),parse_local_version(parsed_file_version[1]))
    return compare_versions(parsed_docker_version,parsed_file_version)


def main():
    args = sys.argv[1:]
    docker_python_version: str = args[0]
    file_python_version: str = args[1]
    image_name: str =  args[2]
    if parse_and_match_versions(
        docker_python_version, file_python_version
    ):
        print("[SUCCESS] Versions verification")
        return 0
    else:
        msg = "[ERROR] Version mismatch. " \
        f"The pipfile/pyproject.toml version {file_python_version}" \
        f" does not match to the base version {docker_python_version} for {image_name}."
        print(msg)
        return 1



if __name__ == "__main__":
    sys.exit(main())
