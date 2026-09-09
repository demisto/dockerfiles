"""Unit tests for docker/dockerfile_matrix/get_changed_images.py (CIAC-17423)."""
from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

# Load the module under test by path (it lives under docker/, not on sys.path).
_MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "docker"
    / "dockerfile_matrix"
    / "get_changed_images.py"
)
_spec = importlib.util.spec_from_file_location("get_changed_images", _MODULE_PATH)
assert _spec and _spec.loader
gci = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gci)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=str(repo), check=True, capture_output=True)


def _write(path: Path, content: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    """Create a tiny git repo with a docker/ tree and one baseline commit."""
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "t@t.t")
    _git(tmp_path, "config", "user.name", "t")
    # Baseline docker images.
    _write(tmp_path / "docker" / "alpha" / "Dockerfile", "FROM scratch\n")
    _write(tmp_path / "docker" / "beta" / "Dockerfile", "FROM scratch\n")
    _write(
        tmp_path / "docker" / "legacy" / "Dockerfile", "FROM scratch\n"
    )
    _write(
        tmp_path / "docker" / "legacy" / "build.conf",
        "version=1.0.0\ndeprecated=true\ndeprecated_reason=use newer\n",
    )
    _write(tmp_path / "docker" / "nodockerfile" / "notes.txt", "x\n")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "baseline")
    return tmp_path


def test_only_changed_images_returned(repo: Path) -> None:
    (repo / "docker" / "alpha" / "Dockerfile").write_text(
        "FROM scratch\n# changed\n", encoding="utf-8"
    )
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "touch alpha")
    result = gci.get_changed_image_names("HEAD~1...HEAD", repo_root=repo)
    assert result == ["alpha"]


def test_deprecated_image_skipped(repo: Path) -> None:
    (repo / "docker" / "legacy" / "Dockerfile").write_text(
        "FROM scratch\n# changed\n", encoding="utf-8"
    )
    (repo / "docker" / "beta" / "Dockerfile").write_text(
        "FROM scratch\n# changed\n", encoding="utf-8"
    )
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "touch legacy+beta")
    result = gci.get_changed_image_names("HEAD~1...HEAD", repo_root=repo)
    # legacy is deprecated -> skipped; beta is buildable -> kept.
    assert result == ["beta"]


def test_dir_without_dockerfile_skipped(repo: Path) -> None:
    (repo / "docker" / "nodockerfile" / "notes.txt").write_text(
        "changed\n", encoding="utf-8"
    )
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "touch notes")
    result = gci.get_changed_image_names("HEAD~1...HEAD", repo_root=repo)
    assert result == []


def test_result_is_sorted_and_deduped(repo: Path) -> None:
    (repo / "docker" / "beta" / "Dockerfile").write_text(
        "FROM scratch\n# a\n", encoding="utf-8"
    )
    (repo / "docker" / "beta" / "extra.txt").write_text("b\n", encoding="utf-8")
    (repo / "docker" / "alpha" / "Dockerfile").write_text(
        "FROM scratch\n# a\n", encoding="utf-8"
    )
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "touch alpha+beta(2 files)")
    result = gci.get_changed_image_names("HEAD~1...HEAD", repo_root=repo)
    assert result == ["alpha", "beta"]  # sorted, beta not duplicated


def test_is_deprecated_missing_build_conf(repo: Path) -> None:
    assert gci.is_deprecated(repo / "docker" / "alpha") is False


def test_is_deprecated_true(repo: Path) -> None:
    assert gci.is_deprecated(repo / "docker" / "legacy") is True


@pytest.mark.parametrize(
    "fmt,expected",
    [
        ("json", '["a", "b"]'),
        ("matrix", '{"IMAGE": ["a", "b"]}'),
        ("lines", "a\nb"),
        ("dotenv", 'IMAGES_JSON=["a", "b"]'),
    ],
)
def test_format_output(fmt: str, expected: str) -> None:
    assert gci.format_output(["a", "b"], fmt) == expected


def test_dotenv_value_is_valid_json_array() -> None:
    line = gci.format_output(["ml", "python3"], "dotenv")
    key, _, value = line.partition("=")
    assert key == "IMAGES_JSON"
    assert json.loads(value) == ["ml", "python3"]


def test_format_output_unknown() -> None:
    with pytest.raises(ValueError):
        gci.format_output(["a"], "bogus")


def test_matrix_format_is_valid_json() -> None:
    parsed = json.loads(gci.format_output(["ml", "python3"], "matrix"))
    assert parsed == {"IMAGE": ["ml", "python3"]}
