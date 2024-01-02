from typing import Optional

from pathlib import Path
import argparse
import json
from datetime import datetime


def parse_file(f):
    return {line.split('=')[0].strip(): line.split('=')[1].strip() for line in f.readlines() if
            not line.isspace() and '#' not in line}


def get_entry(image_name, previous_json) -> Optional[dict]:
    matches = [entry for entry in previous_json if entry['image_name'] == image_name]
    match len(matches):
        case 0:
            return None
        case 1:
            return matches[0]
        case _:
            raise ValueError(f'More than 1 entry exits for image {image_name}')


def compare_deprecated_images(deprecated_json_file, deprecated_json_from_configs):
    names_in_file = {i['image_name'] for i in deprecated_json_file}
    names_in_configs = {i['image_name'] for i in deprecated_json_from_configs}

    names_should_be_in_file = names_in_configs - names_in_file
    names_should_be_in_config = names_in_file - names_in_configs
    if names_should_be_in_file or names_should_be_in_config:
        raise ValueError(
            f'The deprecated_images.json file is not valid. Did you deprecate an image in this pr? Add it to docker/deprecated_images.json'
            f'Set of items that are deprecated according to their build.conf but not in the deprecated_images.json: {names_should_be_in_file}\n'
            f'Set of items that are in the file but not deprecated according to the build.conf {names_should_be_in_config}')


def main():
    arg_parser = argparse.ArgumentParser(
        description="Generate json for deprecated images."
    )
    arg_parser.add_argument('--exclude', default='')
    arg_parser.add_argument('--deprecated_path', default='docker/deprecated_images.json')
    arg_parser.add_argument('--docker_dir', default='docker')
    arg_parser.add_argument('--fix', action='store_true', default=False, help='If flag is set will output the file fixed according to the build.conf files')
    args = arg_parser.parse_args()
    excluded = args.exclude.split(',')
    with open(args.deprecated_path) as f:
        previous_json = json.load(f)
    deprecated_info = []
    for path in Path(args.docker_dir).iterdir():
        if path.is_dir() and path.name not in excluded:
            conf_path = path / 'build.conf'
            if not conf_path.is_file():
                continue
            with open(conf_path) as f:
                config = parse_file(f)
                if config.get('deprecated', False):
                    image_name = f'demisto/{path.name}'
                    prev_entry = get_entry(image_name, previous_json)
                    created_time = prev_entry['created_time_utc'] if prev_entry else str(datetime.now())
                    deprecated_info.append({
                        'image_name': image_name,
                        'reason': config.get('deprecated_reason', ''),
                        'created_time_utc': created_time,
                    })
    if args.fix:
        with open(args.deprecated_path, 'w') as f:
            json.dump(sorted(deprecated_info, key=lambda item: item['image_name']), f, sort_keys=True, indent=4)

    else:
        compare_deprecated_images(previous_json, deprecated_info)
        print('deprecated_images.json file is valid')


if __name__ == "__main__":
    main()
