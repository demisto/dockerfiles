import json
from pathlib import Path
from typing import Any, NamedTuple
import requests
import toml
import sys

DOCKER_FOLDER = Path(__file__).parent.parent / "docker"
NATIVE_IMAGE = "py3-native"


def parse_constraints(dir_name: str) -> dict[str, str]:
    dir_path = DOCKER_FOLDER / dir_name
    if not dir_path.exists():
        raise FileNotFoundError(dir_path)

    pip_path = dir_path / "Pipfile"
    pyproject_path = dir_path / "pyproject.toml"

    if pip_path.exists() and pyproject_path.exists():
        raise ValueError(
            f"Can't have both pyproject and Pipfile in a dockerfile folder ({dir_name})"
        )

    if pip_path.exists():
        return lower_dict_keys(_parse_pipfile(pip_path))

    if pyproject_path.exists():
        return lower_dict_keys(_parse_pyproject(pyproject_path))

    raise ValueError(f"Neither pyproject nor Pipfile found in {dir_name}")


def _parse_pipfile(path: Path) -> dict[str, str]:
    return toml.load(path).get("packages", {})


def _parse_pyproject(path: Path) -> dict[str, str]:
    return toml.load(path).get("tool", {}).get("poetry", {}).get("dependencies", {})


def lower_dict_keys(dictionary: dict[str, Any]) -> dict[str, Any]:
    return {k.lower(): v for k, v in dictionary.items()}


class Discrepancy(NamedTuple):
    dependency: str
    image: str
    in_image: str | None = None
    in_native: str | None = None

    def __str__(self) -> str:
        return f"{self.dependency}: {self.in_image or 'missing'} in {self.image}, {self.in_native or 'missing'} in native"


def compare_constraints(images_contained_in_native: list[str]):
    native_constraints = (
        parse_constraints("python3-ubi")
        | parse_constraints("py3-tools-ubi")
        | parse_constraints(NATIVE_IMAGE)
    )
    native_constraint_keys = set(native_constraints.keys())

    for image in images_contained_in_native:
        discrepancies: list[Discrepancy] = []

        constraints = parse_constraints(image)
        constraint_keys = set(constraints.keys())

        discrepancies.extend(  # image dependencies missing from native
            (
                Discrepancy(
                    dependency=dependency,
                    image=image,
                    in_image=constraints[dependency],
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
                )
                for dependency in sorted(
                    constraint_keys.intersection(native_constraint_keys)
                )
                if constraints[dependency] != native_constraints[dependency]
            )
        )

    for discrepancy in discrepancies:
        print(str(discrepancy))
        print(  # noqa: T201
            f"::error file=docker/{discrepancy.image}/Dockerfile,line=1,endLine=1,title=Native Image Discrepancy::{discrepancy}"
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
