import json
from pathlib import Path
from typing import Any, NamedTuple
import requests
import toml
import sys

DOCKER_FOLDER = Path(__file__).parent.parent / "docker"
NATIVE_IMAGE = "py3-native"
PYPROJECT =  "pyproject.toml"
PIPFILE = "Pipfile"


class Discrepancy(NamedTuple):
    dependency: str
    image: str
    path: Path
    in_image: str | None = None
    in_native: str | None = None

    def __str__(self) -> str:
        return (
            f"{self.dependency} is {self.in_image or 'missing'} in {self.image}, "
            f"but {self.in_native or 'missing'} in the native image. "
            "This discrepancy may cause issues when running content."
        )
def get_dependency_file_path(dir_name: str) -> Path:
    dir_path = DOCKER_FOLDER / dir_name

    if not dir_path.exists():
        raise FileNotFoundError(dir_path)

    pip_path = dir_path / PIPFILE
    pyproject_path = dir_path / PYPROJECT

    if pip_path.exists() and pyproject_path.exists():
        raise ValueError(
            f"Can't have both pyproject and Pipfile in a dockerfile folder ({dir_path})"
        )
    if pip_path.exists():
        return pip_path

    if pyproject_path.exists():
        return pyproject_path
    
    raise ValueError(f"Neither pyproject nor Pipfile found in {dir_path}")

def parse_constraints(name: str) -> dict[str, str]:
    path = get_dependency_file_path(name)
    if path.suffix == PIPFILE:
        return lower_dict_keys(_parse_pipfile(path))

    return lower_dict_keys(_parse_pyproject(path))



def _parse_pipfile(path: Path) -> dict[str, str]:
    return toml.load(path).get("packages", {})


def _parse_pyproject(path: Path) -> dict[str, str]:
    return toml.load(path).get("tool", {}).get("poetry", {}).get("dependencies", {})


def lower_dict_keys(dictionary: dict[str, Any]) -> dict[str, Any]:
    return {k.lower(): v for k, v in dictionary.items()}


def find_library_line_number(lib_name: str, file_path: Path) -> int:
    """
    Searches for a library in the pyproject.toml or Pipfile file and returns the line number where it is found.

    Parameters:
    - lib_name: The name of the library to search for.
    - file_path: The directory containing the pyproject.toml or Pipfile.

    Returns:
    - The line number containing the library name, or 1 if the library is not found.
    """
    for line_number, line in enumerate(
        file_path.read_text().splitlines(), start=1
    ):  # Start counting from line 1
        if lib_name in line:
            return line_number

    return 1  # default


def compare_constraints(images_contained_in_native: list[str]):
    native_constraints = (
        parse_constraints("python3-ubi")
        | parse_constraints("py3-tools-ubi")
        | parse_constraints(NATIVE_IMAGE)
    )
    native_constraint_keys = set(native_constraints.keys())
    discrepancies: list[Discrepancy] = []
    for image in images_contained_in_native:
        path = get_dependency_file_path(image)
        constraints = parse_constraints(image)
        constraint_keys = set(constraints.keys())

        discrepancies.extend(  # image dependencies missing from native
            (
                Discrepancy(
                    dependency=dependency,
                    image=image,
                    in_image=constraints[dependency],
                    path=path
                )
                for dependency in sorted(
                    constraint_keys.difference(native_constraint_keys)
                )
            )
        )
        discrepancies.extend(  # shared dependencies with native, different versions
            (
                Discrepancy(
                    dependency=dependency,
                    image=image,
                    in_image=constraints[dependency],
                    in_native=native_constraints[dependency],
                    path=path
                )
                for dependency in sorted(
                    constraint_keys.intersection(native_constraint_keys)
                )
                if constraints[dependency] != native_constraints[dependency]
            )
        )

    for discrepancy in discrepancies:

        line_number = find_library_line_number(discrepancy.dependency, discrepancy.path)

        print(
            f"::error file={discrepancy.path},line={line_number},endLine={line_number},title=Native Image Discrepancy::{discrepancy}"
        )
    return int(bool(discrepancies))


def load_native_image_conf() -> list[str]:
    return json.loads(
        requests.get(
            "https://raw.githubusercontent.com/demisto/content/master/Tests/docker_native_image_config.json",
            verify=False,
        ).text
    )["native_images"]["native:candidate"]["supported_docker_images"]


if __name__ == "__main__":
    sys.exit(compare_constraints(load_native_image_conf()))
