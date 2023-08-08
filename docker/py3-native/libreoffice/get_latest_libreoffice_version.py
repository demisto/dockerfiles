import requests
import re
from time import sleep
import os
from packaging.version import Version

URL = "https://mirror.isoc.org.il/pub/tdf/libreoffice/stable/"

DEFAULT_LIBRE_OFFICE_VERSION = "7.5.5"
VERSION_REGEX_PATTERN = r"([0-9]+\.[0-9]+\.[0-9]+)"


def get_libre_office_html(sleep_time: int = 10, num_of_retries: int = 5) -> str:
    """
    Get the raw html of the latest libre-office website, returns default libre-office version if not found.
    """
    for i in range(1, num_of_retries + 1):
        try:
            response = requests.get(URL)
            if status_code := response.status_code != 200:
                raise Exception(f'got bad status code: {status_code} in try number {i}')
            html = response.text
            print(f'got {html=} from {URL=}')
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
    """
    Returns a set of all the versions found in the raw mirror html.
    """
    return set(map(lambda v: Version(v), set(re.findall(VERSION_REGEX_PATTERN, html))))


def main():
    html = get_libre_office_html()

    libre_versions = get_libre_office_versions(html)
    print(f'{libre_versions=}')

    latest_libre_version = max(libre_versions)
    print(f'{latest_libre_version=}')

    major_minor_version = f'{latest_libre_version.major}.{latest_libre_version.minor}'

    with open("libre_office_major_minor_version.txt", "w") as f:
        f.write(major_minor_version)

    with open("libre_office_full_version.txt", "w") as f:
        f.write(str(latest_libre_version))

    file_name = f"LibreOffice_{latest_libre_version}_Linux_x86-64_rpm"
    with open("libre_office_installation_file_name.txt", "w") as f:
        f.write(file_name)

    print(
        f'Going to install libre-office version {str(latest_libre_version)} '
        f'from URL {URL}/{latest_libre_version}/rpm/x86_64/{file_name}.tar.gz'
    )


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
