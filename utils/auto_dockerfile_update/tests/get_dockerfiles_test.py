from get_dockerfiles import get_docker_files


def test_get_docker_files_multiple_from():
    """
    Given
        - Docker file with multiple FROM statements
    When
        - running get_docker_files
    Then
        - Verify length of output list is as expected
    """
    files_list = get_docker_files(base_path="test_data/")
    assert len(files_list) == 3