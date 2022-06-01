#!/usr/bin/env python3

import os
import sys
import argparse
from datetime import datetime, timezone
from enum import IntEnum
import json
from json import JSONDecodeError


class Error(IntEnum):
    entry_was_added = 0 
    entry_exists = 0
    empty_reason = 1
    file_not_exists = 2
    error_reading_file = 3
    bad_json_file = 4
    general_error = 5


def add_image_to_deprecated_list(image_name: str, reason: str, file_path: str, verbose=False):
    """ adding giving docker image to the deprecation list. make sure no duplictation etc....

    Args:
        image_name: The docker image name.
        reason: a free text to be added to the entry as the reason for the deprecation/internal user.
        file_path: A file path to the deprecated list (i.e.: deprecated.json)
        verbose: to print out extra information help to investigate
    Returns:
        error
    """
    file_is_empty = os.path.exists(file_path) and os.stat(file_path).st_size == 0
    with open(file_path, 'r+') as fp:
        try:
            if not file_is_empty:
                image_list = json.loads(fp.read())
            else:
                image_list = []

            if not reason or len(reason) <= 0:
                print("reason field for the entry is empty")
                return Error.empty_reason

            if any(image_name == image["image_name"] for image in image_list):
                fp.close()
                print(f"{image_name} already exists in the list {file_path}")                
                return Error.entry_exists
            
            fp.seek(0)
            addition_time_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            image_list.append(dict({ 
                "image_name": f"{image_name}",
                "reason": f"{reason}",
                "created_time_utc": f"{addition_time_str}"
            }))
            image_list_string = json.dumps(image_list, indent=4)
            if verbose:
                print(image_list_string)
            fp.write(image_list_string)
            fp.close()
            print(f"{image_name}: was added to the list {file_path}")
            return Error.entry_was_added
        
        except FileExistsError as exp:
            print(f"{file_path}: does not exists. make sure you are running from the the root folder of the "
                  f"dockerfiles repo (i.e.: /home/developer_name/dev/dockerfiles or make sure you are running the "
                  f"tools with full file path to the file.")
            if verbose:
                print(f"Exception: {exp}")
            return Error.file_not_exists
        except OSError as exp:
            print(f"{file_path}: permission error ")
            if verbose:
                print(f"Exception: {exp}")
            if fp:
                fp.close()
            return Error.error_reading_file
        except JSONDecodeError or TypeError as exp:
            print(f"{file_path}: has bad format or decoding issue")
            if verbose:
                print(f"Exception: {exp}")
            if fp:
                fp.close()
            return Error.bad_json_file
        except Exception as exp:
            print(f"unexpected error occured exception ")
            if verbose:
                print(f"Exception: {exp}")
            if fp:
                fp.close()
            return Error.general_error


def handle_args():
    parser = argparse.ArgumentParser(description='add giving image to the deprecated/internal image list')
    parser.add_argument("name", help="The image name to get the tag for. For example: demisto/python3")
    parser.add_argument("reason", help="A free text argument to be added to the entry as the reason for addition")
    parser.add_argument("file_path", help="file path to the deprectaed file list")
    parser.add_argument("--verbose", help="Specify if to print verbose data while adding the new entry to list",
                        choices=['true', 'false'], default='false')
    args = parser.parse_args()
    return args


def main():
    args = handle_args()
    image_name = args.name
    reason = args.reason
    file_path = args.file_path
    verbose = args.verbose == 'true'
    return_value = add_image_to_deprecated_list(image_name, reason, file_path, verbose)
    print(return_value, int(return_value))
    sys.exit(int(return_value))


if __name__ == "__main__":
    main()
