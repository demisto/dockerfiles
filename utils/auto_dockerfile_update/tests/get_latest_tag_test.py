from unittest.mock import MagicMock, patch

import pytest

from utils.auto_dockerfile_update import get_latest_tag as glt


def _response(status_code, json_data=None, headers=None):
    res = MagicMock(status_code=status_code, headers=headers or {}, text=str(json_data))
    res.json.return_value = json_data
    return res


@pytest.fixture(autouse=True)
def reset_jwt_cache(monkeypatch):
    monkeypatch.setattr(glt, "_dockerhub_jwt", None)
    monkeypatch.setattr(glt, "_dockerhub_jwt_fetched", False)


def test_tags_request_is_authenticated_and_login_cached(monkeypatch):
    """
    Given
        - DOCKERHUB_USER/DOCKERHUB_PASSWORD are set
    When
        - fetching tags twice
    Then
        - login happens once and both tag requests carry the Bearer token
    """
    monkeypatch.setenv("DOCKERHUB_USER", "u")
    monkeypatch.setenv("DOCKERHUB_PASSWORD", "p")
    with patch.object(glt.requests, "post", return_value=_response(200, {"token": "jwt"})) as post, \
            patch.object(glt.requests, "get", return_value=_response(200, {"results": []})) as get:
        assert glt.get_dockerhub_tags_list(repo="demisto", image_name="python3") == {"results": []}
        glt.get_dockerhub_tags_list(repo="demisto", image_name="python3")
    assert post.call_count == 1
    assert all(c.kwargs["headers"] == {"Authorization": "Bearer jwt"} for c in get.call_args_list)


def test_anonymous_without_credentials_and_none_on_403(monkeypatch):
    """
    Given
        - no Docker Hub credentials and the API answers 403
    When
        - fetching tags
    Then
        - no login is attempted, no auth header is sent and None is returned
    """
    monkeypatch.delenv("DOCKERHUB_USER", raising=False)
    monkeypatch.delenv("DOCKERHUB_PASSWORD", raising=False)
    with patch.object(glt.requests, "post") as post, \
            patch.object(glt.requests, "get", return_value=_response(403, "Forbidden")) as get:
        assert glt.get_dockerhub_tags_list(repo="demisto", image_name="python3") is None
    post.assert_not_called()
    assert get.call_args.kwargs["headers"] == {}


def test_retries_on_429(monkeypatch):
    """
    Given
        - the API answers 429 with Retry-After, then 200
    When
        - calling dockerhub_get
    Then
        - it sleeps for Retry-After and returns the successful response
    """
    monkeypatch.delenv("DOCKERHUB_USER", raising=False)
    responses = [_response(429, headers={"Retry-After": "3"}), _response(200, {"ok": True})]
    with patch.object(glt.requests, "get", side_effect=responses), patch.object(glt.time, "sleep") as sleep:
        assert glt.dockerhub_get("https://hub.docker.com/x").status_code == 200
    sleep.assert_called_once_with(3)
