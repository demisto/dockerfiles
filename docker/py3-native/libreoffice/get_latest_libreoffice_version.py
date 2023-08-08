import requests
import re
from time import sleep
import os
from packaging.version import Version

URL = "http://download.documentfoundation.org/libreoffice/stable/"

DEFAULT_LIBRE_OFFICE_VERSION = "7.5.5"
VERSION_REGEX_PATTERN = "([0-9]+\.[0-9]+\.[0-9]+)"


def get_libre_office_html(sleep_time: int = 10, num_of_retries: int = 5) -> str:
    """
    Get the raw html of the latest libre office website, returns default libre-office version if not found.
    """
    for i in range(1, num_of_retries + 1):
        try:
            response = requests.get(URL)
            if status_code := response.status_code != 200:
                raise Exception(f'got bad status code: {status_code} in try number {i}')
            html = response.text
            print(f'got {html} from {URL=}')
            return html
        except Exception as e:
            print(f'got error when querying {URL} URL, error: {e} in retry number {i}')
            if i == num_of_retries:
                print(f"return default version of libre-office: {DEFAULT_LIBRE_OFFICE_VERSION}")
                return DEFAULT_LIBRE_OFFICE_VERSION
            # sleep 10 seconds in case of http error
            print(f"sleeping for {sleep} seconds")
            sleep(sleep_time)


def get_libre_office_versions(html: str):
    return set(map(lambda v: Version(v), set(re.findall(VERSION_REGEX_PATTERN, html))))


def main():
    html = get_libre_office_html()

    print(f'got {html=} from {URL}')
    libre_versions = get_libre_office_versions(html)
    print(f'{libre_versions=}')

    latest_libre_version = max(libre_versions)
    print(f'{latest_libre_version=}')

    major_minor_version = f'{latest_libre_version.major}.{latest_libre_version.minor}'

    print(f"Setting LIBRE_OFFICE_MAJOR_VERSION environment variable to '{major_minor_version}'")
    os.environ["LIBRE_OFFICE_MAJOR_MINOR_VERSION"] = major_minor_version

    print(f"Setting LIBRE_OFFICE_FULL_VERSION environment variable to '{latest_libre_version}'")
    os.environ["LIBRE_OFFICE_FULL_VERSION"] = str(latest_libre_version)

    file_name = f"LibreOffice_${latest_libre_version}_Linux_x86-64_rpm"

    print(f"Setting LIBRE_OFFICE_INSTALLATION_FILE_NAME environment variable to '{file_name}'")
    os.environ["LIBRE_OFFICE_INSTALLATION_FILE_NAME"] = file_name

    print(f'Going to install version {latest_libre_version}')

if __name__ in ["__builtin__", "builtins", '__main__']:
    main()