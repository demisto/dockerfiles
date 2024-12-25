from utils.auto_dockerfile_update.get_dockerfiles import get_docker_files


def test_get_docker_files_multiple_from_internal():
    """
    Given
        - Docker file with multiple FROM statements
    When
        - running get_docker_files
    Then
        - Verify length of output list is as expected
    """
    files_list = get_docker_files(base_path="utils/auto_dockerfile_update/tests/test_data/", internal=True)
    assert len(files_list) == 2


def test_get_docker_files_multiple_from_external():
    """
    Given
        - Docker file with multiple FROM statements
    When
        - running get_docker_files
    Then
        - Verify length of output list is as expected
    """
    files_list = get_docker_files(base_path="utils/auto_dockerfile_update/tests/test_data/", external=True)
    assert len(files_list) == 1