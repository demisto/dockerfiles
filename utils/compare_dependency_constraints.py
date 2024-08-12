import json
from pathlib import Path
from typing import Any, NamedTuple
import requests
import toml
import sys

DOCKER_FOLDER = Path(__file__).parent.parent / "docker"
NATIVE_IMAGE = "py3-native"
PY3_TOOLS_UBI_IMAGE = "py3-tools-ubi"
PY3_TOOLS_IMAGE = "py3-tools"
PYPROJECT = "pyproject.toml"
PIPFILE = "Pipfile"


class Discrepancy(NamedTuple):
    """Represents a discrepancy between dependencies in different images."""

    dependency: str
    image: str
    reference_image: str
    path: Path
    in_image: str | None = None
    in_reference: str | None = None

    def __str__(self) -> str:
        return (
            f"{self.dependency} is {self.in_image or 'missing'} in {self.image}, "
            f"but {self.in_reference or 'missing'} in the {self.reference_image} image. "
            "This discrepancy may cause issues when running content."
        )


def get_dependency_file_path(dir_name: str) -> Path:
    """Returns the path to the dependency file (Pipfile or pyproject.toml) in the given directory."""
    dir_path = DOCKER_FOLDER / dir_name

    if not dir_path.exists():
        raise FileNotFoundError(f"Directory {dir_path} does not exist.")

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
    """Parses the dependency constraints from the given image name."""
    path = get_dependency_file_path(name)
    if path.suffix == PIPFILE:
        return lower_dict_keys(_parse_pipfile(path))

    return lower_dict_keys(_parse_pyproject(path))


def _parse_pipfile(path: Path) -> dict[str, str]:
    """Parses the Pipfile and returns the dependencies."""
    return toml.load(path).get("packages", {})


def _parse_pyproject(path: Path) -> dict[str, str]:
    """Parses the pyproject.toml file and returns the dependencies."""
    return toml.load(path).get("tool", {}).get("poetry", {}).get("dependencies", {})


def lower_dict_keys(dictionary: dict[str, Any]) -> dict[str, Any]:
    """Converts all keys in the dictionary to lowercase."""
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


def compare_constraints(images_contained_in_native: list[str]) -> int:
    """Compares the dependency constraints between different images and reports discrepancies.

    This function compares the dependencies of the following images:
    - `py3-tools`
    - `py3-tools-ubi`
    - `native`

    against the dependencies of the images listed in `images_contained_in_native`.

    Additionally, it compares the dependencies of `py3-tools` against `py3-tools-ubi`.

    Args:
        images_contained_in_native (list[str]): A list of image names to compare against the native image.

    Returns:
        int: Returns 1 if there are discrepancies, 0 otherwise.
    """

    native_constraints = (
        parse_constraints(PY3_TOOLS_IMAGE)
        | parse_constraints(PY3_TOOLS_UBI_IMAGE)
        | parse_constraints(NATIVE_IMAGE)
    )
    py3_tools_constraints = parse_constraints(PY3_TOOLS_IMAGE)
    py3_tools_ubi_constraints = parse_constraints(PY3_TOOLS_UBI_IMAGE)
    discrepancies: list[Discrepancy] = []

    for image in images_contained_in_native:
        discrepancies.extend(compare_with_native(image, native_constraints))

    discrepancies.extend(
        compare_py3_tools_with_ubi(py3_tools_constraints, py3_tools_ubi_constraints)
    )


    for discrepancy in discrepancies:
        line_number = find_library_line_number(discrepancy.dependency, discrepancy.path)
        print(
            f"::error file={discrepancy.path},line={line_number},endLine={line_number},title=Native Image Discrepancy::{discrepancy}"
        )
    return int(bool(discrepancies))


def compare_with_native(image: str, native_constraints: dict) -> list[Discrepancy]:
    path = get_dependency_file_path(image)
    constraints = parse_constraints(image)
    constraint_keys = set(constraints.keys())
    native_constraint_keys = set(native_constraints.keys())

    discrepancies: list[Discrepancy] = []

    discrepancies.extend(  # image dependencies missing from native
        (
            Discrepancy(
                dependency=dependency,
                image=image,
                reference_image=NATIVE_IMAGE,
                in_image=constraints[dependency],
                path=path,
            )
            for dependency in sorted(constraint_keys.difference(native_constraint_keys))
        )
    )
    discrepancies.extend(  # shared dependencies with native, different versions
        (
            Discrepancy(
                dependency=dependency,
                image=image,
                reference_image=NATIVE_IMAGE,
                in_image=constraints[dependency],
                in_reference=native_constraints[dependency],
                path=path,
            )
            for dependency in sorted(
                constraint_keys.intersection(native_constraint_keys)
            )
            if constraints[dependency] != native_constraints[dependency]
        )
    )

    return discrepancies


def compare_py3_tools_with_ubi(
    py3_tools_constraints: dict, py3_tools_ubi_constraints: dict
) -> list[Discrepancy]:
    py3_tools_keys = set(py3_tools_constraints.keys())
    py3_tools_ubi_keys = set(py3_tools_ubi_constraints.keys())

    discrepancies: list[Discrepancy] = []

    discrepancies.extend(  # py3-tools-ubi dependencies missing from py3-tools
        (
            Discrepancy(
                dependency=dependency,
                image=PY3_TOOLS_UBI_IMAGE,
                reference_image=PY3_TOOLS_IMAGE,
                in_image=py3_tools_ubi_constraints.get(dependency),
                in_reference=py3_tools_constraints.get(dependency),
                path=get_dependency_file_path(PY3_TOOLS_UBI_IMAGE),
            )
            for dependency in sorted(py3_tools_ubi_keys.difference(py3_tools_keys))
        )
    )
    discrepancies.extend(  # shared dependencies with py3-tools, different versions
        (
            Discrepancy(
                dependency=dependency,
                image=PY3_TOOLS_UBI_IMAGE,
                reference_image=PY3_TOOLS_IMAGE,
                in_image=py3_tools_ubi_constraints.get(dependency),
                in_reference=py3_tools_constraints.get(dependency),
                path=get_dependency_file_path(PY3_TOOLS_UBI_IMAGE),
            )
            for dependency in sorted(py3_tools_ubi_keys.intersection(py3_tools_keys))
            if py3_tools_ubi_constraints.get(dependency)
            != py3_tools_constraints.get(dependency)
        )
    )

    return discrepancies


def load_native_image_conf() -> list[str]:
    """Returns the supported docker images by the native image from a remote JSON file."""
    return json.loads(
        requests.get(
            "https://raw.githubusercontent.com/demisto/content/master/Tests/docker_native_image_config.json",
            verify=False,
        ).text
    )["native_images"]["native:candidate"]["supported_docker_images"]


if __name__ == "__main__":
    sys.exit(compare_constraints(load_native_image_conf()))
