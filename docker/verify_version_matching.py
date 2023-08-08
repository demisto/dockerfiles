#!/usr/bin/env python3

import os
import re
import sys
from typing import Optional, List, Tuple
import requests
import urllib3
import copy

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


def get_operator_and_version(version) -> Tuple[List,str]:
    """Gets the version and the operator.
    
    Args:
        version (str): The version.

    Returns:
        Tuple[Tuple,str]: The return value. A Tuple of a list with the parsed version and the operator.
    """
    operator_list = ["^","<=",">=","<",">","!=", "~"]
    returned_operator = "="
    for operator in operator_list:
        if operator in version:
            operator_index = version.index(operator)
            version  = version[operator_index+len(operator):]
            returned_operator = operator
            break
    return parse_local_version(version),returned_operator            

 
def parse_and_match_versions(docker_python_version: str,file_python_version: str)-> bool:
    """Parse the versions and validate versions matching.
    Args:
        docker_python_version (str): The first parameter.
        file_python_version (str): The second parameter.

    Returns:
        bool: The return value. True for success, False otherwise.
    """
    versions = file_python_version.split(",")
    parsed_docker_version=parse_local_version(docker_python_version)
    result = True
    for version in versions:
        parsed_version,operator=get_operator_and_version(version)
        # major, minor, revision = parsed_version
        # major_docker, minor_docker, revision_docker=parsed_docker_version
        match operator:
            case "=":
                if parsed_docker_version != parsed_version:
                    result *= False
            case "^":
                # examples: 
                # requirement ---> versions allowed
                # ^1.2.3 --> >=1.2.3 <2.0.0
                # ^1.2 --> >=1.2.0 <2.0.0
                # ^0.2.3 --> >=0.2.3 <0.3.0
                upper_limit_version = copy.deepcopy(parsed_version)
                # gets the first instance of a nonzero number in the version list.
                first_non_zero_of_version = next((index for index, value in enumerate(upper_limit_version) if value), 0)
                for index,version in enumerate(upper_limit_version):
                    if index == first_non_zero_of_version:
                        upper_limit_version[index]=parsed_version[index]+1
                    if index > first_non_zero_of_version:
                        upper_limit_version[index]=0
                if parsed_docker_version < parsed_version or parsed_docker_version > upper_limit_version:
                    result *= False
            case "<=":
                if parsed_docker_version > parsed_version:
                    result *= False
            case ">=":
                if parsed_docker_version < parsed_version:
                    result *= False 
            case "<":
                if parsed_docker_version >= parsed_version:
                    result *= False 
            case ">":
                if parsed_docker_version <= parsed_version:
                    result *= False  
            case "~":
                # examples: 
                # requirement ---> versions allowed
                # ~1.2.3 --> >=1.2.3 <1.3.0
                # ~1.2 --> >=1.2.0 <1.3.0
                # ~1 --> >=1.0.0 <2.0.0
                upper_limit_version = copy.deepcopy(parsed_version)
                upper_limit_version_len = len(upper_limit_version)
                # If you specify a major, minor, and revision version or only a major and minor version, only revision-level changes are allowed.
                if upper_limit_version_len == 3:
                    upper_limit_version[1] = upper_limit_version[1] + 1
                    upper_limit_version[2] = 0
                # If you only specify a major version, then minor- and revision-level changes are allowed.
                else:
                    upper_limit_version[upper_limit_version_len-1]=parsed_version[upper_limit_version_len-1]+1
                if parsed_docker_version < parsed_version or parsed_docker_version >= upper_limit_version:
                    result *= False
            case "!=":
                if parsed_docker_version == parsed_version:
                    result *= False
    return result


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
