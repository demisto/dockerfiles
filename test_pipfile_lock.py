from pathlib import Path
from pipenv.project import Project

PROHIBITED_FILES = {'requirements.txt'}
REQUIRED_FILES = {'Dockerfile'}


class DockerFileValidator:
    def __init__(self):
        self.project = Project()

    def validate(self):
        self._validate_files()
        self._validate_pipfile_lock()

    def _validate_pipfile_lock(self):
        if self.project.pipfile_exists and not self.project.lockfile_exists:
            raise ValueError("Missing Pipfile.lock\n"
                             "Please run `pipenv lock` to generate it.")

        if self.project.lockfile_exists and self.project.calculate_pipfile_hash() != self.project.get_lockfile_hash():
            raise ValueError("Pipfile hash is different than the Pipfile.lock hash.\n"
                             "Please run `pipenv lock` to update the Pipfile.lock")

    @staticmethod
    def _validate_files():
        files = tuple(Path().glob('*'))
        prohibited_but_exist = PROHIBITED_FILES.intersection(files)
        required_but_missing = REQUIRED_FILES.difference(files)

        errors = []
        if prohibited_but_exist:
            prohibited_message = ",".join(prohibited_but_exist)
            errors.append(f'The following files are not allowed: {prohibited_message}')

        if required_but_missing:
            required_message = ",".join(required_but_missing)
            errors.append(f'The following files are required: {required_message}')

        if errors:
            raise ValueError("\n".join(errors))


def main():
    validator = DockerFileValidator()
    validator.validate()  # raises on error


if __name__ == '__main__':
    main()
