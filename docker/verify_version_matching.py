#!/usr/bin/env python3

import re
import sys
from typing import Optional, List, Tuple
from packaging.specifiers import SpecifierSet, InvalidSpecifier
from packaging.version import Version

if Version(sys.version_info) < Version(3.7):
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
    operator_list = ["^","<=",">=","<",">","!=", "~"]
    returned_operator = "="
    for operator in operator_list:
        if operator in version:
            operator_index = version.index(operator)
            version  = version[operator_index+len(operator):]
            returned_operator = operator
            break
    return version,returned_operator            

def create_specifier_set(version_string: str,operator: str) -> SpecifierSet:
    """Gets the specifier set.
    
    Args:
        version_string (str): The version in string representation.
        operator (str): The operator.        

    Returns:
        SpecifierSet: A SpecifierSet.
    """
    version_obj = Version(version_string)
    version_list = parse_local_version(version_string)
    # Caret requirements allow SemVer compatible updates to a specified version.
    # An update is allowed if the new version number does not modify the left-most
    # non-zero digit in the major, minor, patch grouping. 
    if operator == "^":
        non_zero_index=next((i for i, x in enumerate(version_list) if x), len(version_list)-1)
        if non_zero_index == 0:
            return SpecifierSet(f">={str(version_obj)}, <{version_obj.major+1}.0.0")
        elif non_zero_index == 1:
            return SpecifierSet(f">={str(version_obj)}, <{version_obj.major}.{version_obj.minor+1}.0")
        else:
            return SpecifierSet(f">={str(version_obj)}, <{version_obj.major}.{version_obj.minor}.{version_obj.micro+1}")
        
    # Tilde requirements specify a minimal version with some ability to update.
    # If you specify a major, minor, and patch version or only a major and minor version,
    # only patch-level changes are allowed. If you only specify a major version, 
    # then minor- and patch-level changes are allowed.
    if operator ==  "~":
        if version_obj.major:
            if (version_obj.minor and version_obj.micro) or version_obj.minor:
                return SpecifierSet(f">={str(version_obj)}, <{version_obj.major}.{version_obj.minor+1}.0")
            # If you only specify a major version, then minor- and patch-level changes are allowed.
            else:
                return SpecifierSet(f">={version_obj.major}.0.0, <{version_obj.major+1}.0.0")
    return SpecifierSet("")
 
def parse_and_match_versions(docker_python_version: str,file_python_version: str) -> bool:
    """Parse the versions and validate versions matching.
    Args:
        docker_python_version (str): The first parameter.
        file_python_version (str): The second parameter.

    Returns:
        bool: The return value. True for success, False otherwise.
    """
    result = True
    versions = file_python_version.split(",")
    docker_version = Version(docker_python_version)
    for version in versions:
        try:
            specifier = SpecifierSet(file_python_version)
            result *= docker_version in specifier
        except InvalidSpecifier as e:
                # Specifier support ~=|==|!=|<=|>=|<|>|=== 
                # we have ^ and ~ in the pyproject.toml files.
                version,operator=get_operator_and_version(file_python_version)
                try:
                    specifier = create_specifier_set(version,operator)
                    result *= docker_version in specifier
                except InvalidSpecifier as e:
                    raise(e)
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
