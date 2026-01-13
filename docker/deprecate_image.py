#!/usr/bin/env python3

import argparse
import json
import sys
import re
from datetime import datetime, timezone
from pathlib import Path


def update_deprecated_json(image_name: str, reason: str, file_path: Path) -> bool:
    """Adds the image to the deprecated JSON list."""
    try:
        if file_path.exists():
            with open(file_path, 'r') as f:
                image_list = json.load(f)
        else:
            image_list = []

        if any(image.get("image_name") == image_name for image in image_list):
            print(f"Image '{image_name}' already exists in {file_path}")
            return True

        addition_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        image_list.append({
            "created_time_utc": addition_time,
            "image_name": image_name,
            "reason": reason
        })

        with open(file_path, 'w') as f:
            json.dump(image_list, f, indent=4)
        
        print(f"Added '{image_name}' to {file_path}")
        return True
    except Exception as e:
        print(f"Error updating {file_path}: {e}")
        return False


def update_build_conf(image_name: str, reason: str) -> bool:
    """Updates the build.conf file for the image."""
    image_dir_name = image_name.split('/')[-1]
    build_conf_path = Path("docker") / image_dir_name / "build.conf"

    if not build_conf_path.exists():
        print(f"Warning: build.conf not found at {build_conf_path}")
        return False

    try:
        lines = build_conf_path.read_text().splitlines()
        new_lines = []
        deprecated_found = False
        reason_found = False

        for line in lines:
            if line.startswith("deprecated="):
                new_lines.append("deprecated=true")
                deprecated_found = True
            elif line.startswith("deprecated_reason="):
                new_lines.append(f"deprecated_reason={reason}")
                reason_found = True
            else:
                new_lines.append(line)

        if not deprecated_found:
            new_lines.append("deprecated=true")
        if not reason_found:
            new_lines.append(f"deprecated_reason={reason}")

        build_conf_path.write_text("\n".join(new_lines) + "\n")
        print(f"Updated {build_conf_path} with deprecation info.")
        return True
    except Exception as e:
        print(f"Error updating {build_conf_path}: {e}")
        return False


def update_dependabot_config(image_name: str) -> bool:
    """Removes the image directory from .github/dependabot.yml using regex to minimize diffs."""
    dependabot_path = Path(".github/dependabot.yml")
    if not dependabot_path.exists():
        print(f"Warning: {dependabot_path} not found.")
        return False

    image_dir_name = image_name.split('/')[-1]
    target_dir = f"/docker/{image_dir_name}"

    try:
        content = dependabot_path.read_text()
        
        # Regex to find the block starting with '  - package-ecosystem: pip' 
        # and containing 'directory: /docker/image_dir_name'
        # We look for the start of a list item '-' and then match until the next list item or end of file
        # while ensuring it contains the target directory.
        
        pattern = rf"(?m)^  - package-ecosystem: pip\s*\n(?:^    .*\n)*?^    directory: {re.escape(target_dir)}\s*\n(?:^    .*\n)*"
        
        new_content = re.sub(pattern, "", content)

        if new_content != content:
            dependabot_path.write_text(new_content)
            print(f"Removed {target_dir} from {dependabot_path} (surgical edit)")
        else:
            print(f"Directory {target_dir} not found in {dependabot_path}")
        
        return True
    except Exception as e:
        print(f"Error updating {dependabot_path}: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description='Deprecate a Docker image.')
    parser.add_argument("-n", "--name", required=True, help="The image name (e.g., demisto/python3)")
    parser.add_argument("-r", "--reason", required=True, help="Reason for deprecation")
    parser.add_argument("-f", "--file", default="docker/deprecated_images.json", help="Path to deprecated_images.json")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    success = True
    
    # 1. Update deprecated_images.json
    if not update_deprecated_json(args.name, args.reason, Path(args.file)):
        success = False

    # 2. Update build.conf
    if not update_build_conf(args.name, args.reason):
        pass

    # 3. Update dependabot.yml
    if not update_dependabot_config(args.name):
        success = False

    if not success:
        sys.exit(1)
    
    print(f"\nSuccessfully deprecated {args.name}")


if __name__ == "__main__":
    main()