#!/usr/bin/env python3
"""Unit tests for docker/validate_image_names.py."""
from docker import validate_image_names


def _make_docker_dir(tmp_path, names):
    docker_dir = tmp_path / "docker"
    docker_dir.mkdir()
    for name in names:
        (docker_dir / name).mkdir()
    return docker_dir


def test_no_offenders_when_names_are_clean(tmp_path):
    docker_dir = _make_docker_dir(tmp_path, ["python3", "crypto", "boto3"])
    assert validate_image_names.find_reserved_prefixed_images(docker_dir) == []


def test_detects_reserved_prefix(tmp_path):
    docker_dir = _make_docker_dir(tmp_path, ["python3", "sig-python3", "sig-foo"])
    assert validate_image_names.find_reserved_prefixed_images(docker_dir) == [
        "sig-foo",
        "sig-python3",
    ]


def test_prefix_match_is_exact_start_only(tmp_path):
    # "signal" contains "sig" but does not start with the "sig-" prefix.
    docker_dir = _make_docker_dir(tmp_path, ["signal", "mysig-tool", "sig-bad"])
    assert validate_image_names.find_reserved_prefixed_images(docker_dir) == [
        "sig-bad"
    ]


def test_ignores_files_only_directories(tmp_path):
    docker_dir = tmp_path / "docker"
    docker_dir.mkdir()
    (docker_dir / "python3").mkdir()
    (docker_dir / "sig-file.txt").write_text("not a dir")  # a file, not an image
    assert validate_image_names.find_reserved_prefixed_images(docker_dir) == []


def test_missing_docker_dir_returns_empty(tmp_path):
    assert validate_image_names.find_reserved_prefixed_images(tmp_path / "nope") == []


def test_custom_prefix(tmp_path):
    docker_dir = _make_docker_dir(tmp_path, ["sig-a", "signed-b", "c"])
    assert validate_image_names.find_reserved_prefixed_images(
        docker_dir, reserved_prefix="signed-"
    ) == ["signed-b"]


def test_main_passes_on_real_repo():
    """The real docker/ directory must not contain any reserved-prefix images."""
    assert validate_image_names.main() == 0
