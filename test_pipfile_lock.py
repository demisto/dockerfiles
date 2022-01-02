import os

import re
from pathlib import Path

from pipenv.project import Project

PROHIBITED_FILES = {'requirements.txt'}
REQUIRED_FILES = {'Dockerfile'}


class DockerFileValidator:
    def __init__(self, path: str = ''):
        self.path = Path(path)
        os.chdir(self.path)  # for debug purposes # todo remove
        self.project = Project()
        self.docker_file = Path('Dockerfile')

    def validate(self):
        # print("START ", "\t", str(self.path)) # todo remove
        self._validate_files()
        self._validate_pipfile_lock()
        self._validate_dockerfile_pip_install()
        # print("VALID ", "\t", str(self.path)) # todo remove

    def _validate_dockerfile_pip_install(self):
        dockerfile = self.docker_file.read_text() \
            .replace("&&", "") \
            .replace("\\", " ") \
            .replace("\n", " ")

        matches = tuple(re.finditer(r"pip install (?P<flags>-[\w\- .]+?) (?P<installed>[^-][\w+.]+)", dockerfile))

        assert len(matches) == dockerfile.count("pip install"), 'Error parsing `pip install` commands'

        for match in matches:
            installed = match.group('installed')
            if installed != 'requirements.txt':
                raise ValueError(
                    "pip install commands in the Dockerfile can only be used on requirements.txt"
                    " (found {})".format(installed)
                )

    def _validate_pipfile_lock(self):
        if self.project.pipfile_exists and not self.project.lockfile_exists:
            raise ValueError("Missing Pipfile.lock\n"
                             "Please run `pipenv lock` to generate it.")

        if self.project.lockfile_exists and self.project.calculate_pipfile_hash() != self.project.get_lockfile_hash():
            raise ValueError("Pipfile hash is different than the Pipfile.lock hash.\n"
                             "Please run `pipenv lock` to update the Pipfile.lock")

    def _validate_files(self):
        files = tuple(file.name for file in self.path.glob('*'))
        prohibited_but_exist = PROHIBITED_FILES.intersection(files)
        required_but_missing = REQUIRED_FILES.difference(files)

        errors = []
        if prohibited_but_exist:
            errors.append('The following files are not allowed: ' + ",".join(prohibited_but_exist))

        if required_but_missing:
            errors.append('The following files are required: ' + ",".join(required_but_missing))

        if errors:
            raise ValueError("\n".join(errors))


def main():
    validator = DockerFileValidator()
    validator.validate()  # raises on error


if __name__ == '__main__':
    main()
