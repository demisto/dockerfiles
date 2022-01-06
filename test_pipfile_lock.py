import re
from pathlib import Path

from pipenv.project import Project
from yaml import safe_load

REQUIREMENTS_TXT = 'requirements.txt'
BUILD_CONF = 'build.conf'
DOCKERFILE = 'Dockerfile'

PROHIBITED_FILES = {REQUIREMENTS_TXT}
REQUIRED_FILES = {DOCKERFILE, BUILD_CONF}


class DockerFileValidator:
    def __init__(self, path: Path = Path()):
        if not path.parent.name == 'docker':
            raise RuntimeError(f"called to run on {path}, which is not directly under the `docker` folder")

        self.path = path.absolute()

        self.project = Project()
        self.docker_file = self.path / Path(DOCKERFILE)
        self.build_conf = self.path / Path(BUILD_CONF)

    def validate(self):
        self._validate_files()
        self._validate_dependabot()
        self._validate_pipfile_lock()
        self._validate_dockerfile_pip_install()
        # todo precommit

    def _validate_dependabot(self):
        if any(line.startswith('devonly=true')
               for line in self.build_conf.read_text().split("\n")):
            print(f"skipping {self.path.name} - dev only")
            return  # skip dev-only images

        dependabot_file = self.path.parent.parent / '.github/dependabot.yml'

        with dependabot_file.open() as f:
            dependabot_config = safe_load(f)

        dependabot_configured_directories = {update['directory']
                                             for update in dependabot_config['updates']
                                             if update.get('package-ecosystem') == 'pip'}

        if f'/docker/{self.path.name}' not in dependabot_configured_directories:
            raise ValueError("\n".join((f"/docker/{self.path.name} is not configured on dependabot.",
                                        "To add the config run: ./docker/add_dependabot.sh docker/")))

    def _validate_dockerfile_pip_install(self):
        dockerfile = self.docker_file.read_text() \
            .replace("&&", "") \
            .replace("\\", " ")

        matches = tuple(re.finditer(r"pip install (?P<flags>-[\w\- .]*?) (?P<installed>[^-\s].+)\n", dockerfile))

        assert len(matches) == dockerfile.count("pip install"), 'Error parsing `pip install` commands'

        for match in matches:
            installed_raw = match.group('installed')
            if installed_raw.split() != [REQUIREMENTS_TXT]:
                raise ValueError("pip install commands in the Dockerfile can only be used on requirements.txt"
                                 " (found {})\n"
                                 "In special cases, force-merging the PR is possible, overriding this validation. "
                                 "Contact the PR reviewer for more information.".format(installed_raw))

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
