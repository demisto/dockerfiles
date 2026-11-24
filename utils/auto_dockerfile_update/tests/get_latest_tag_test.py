from unittest.mock import MagicMock, patch

import pytest

from utils.auto_dockerfile_update import get_latest_tag as glt


def _response(status_code, json_data=None, headers=None):
    res = MagicMock(status_code=status_code, text=str(json_data), headers=headers or {})
    res.json.return_value = json_data
    res.raise_for_status.side_effect = None if status_code < 400 else glt.requests.HTTPError(str(status_code))
    return res


@pytest.fixture(autouse=True)
def reset_token_cache():
    glt._get_dockerhub_token.cache_clear()
    yield
    glt._get_dockerhub_token.cache_clear()


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
    with patch.object(glt.requests, "post", return_value=_response(200, {"access_token": "jwt"})) as post, \
            patch.object(glt.requests, "get", return_value=_response(200, {"results": []})) as get:
        assert glt.get_dockerhub_tags_list(repo="demisto", image_name="python3") == {"results": []}
        glt.get_dockerhub_tags_list(repo="demisto", image_name="python3")
    assert post.call_count == 1
    assert all(c.kwargs["headers"] == {"Authorization": "Bearer jwt"} for c in get.call_args_list)


def test_anonymous_without_credentials(monkeypatch):
    """
    Given
        - no Docker Hub credentials
    When
        - fetching tags
    Then
        - no login is attempted and no auth header is sent
    """
    monkeypatch.delenv("DOCKERHUB_USER", raising=False)
    monkeypatch.delenv("DOCKERHUB_PASSWORD", raising=False)
    with patch.object(glt.requests, "post") as post, \
            patch.object(glt.requests, "get", return_value=_response(200, {"results": []})) as get:
        glt.get_dockerhub_tags_list(repo="demisto", image_name="python3")
    post.assert_not_called()
    assert get.call_args.kwargs["headers"] == {}


def test_expired_token_triggers_one_relogin(monkeypatch):
    """
    Given
        - a cached Docker Hub token that has expired (tags request returns 401)
    When
        - fetching tags
    Then
        - a fresh token is fetched once and the request is retried with it
    """
    monkeypatch.setenv("DOCKERHUB_USER", "u")
    monkeypatch.setenv("DOCKERHUB_PASSWORD", "p")
    logins = [_response(200, {"access_token": "old"}), _response(200, {"access_token": "new"})]
    with patch.object(glt.requests, "post", side_effect=logins) as post, \
            patch.object(glt.requests, "get", side_effect=[_response(401), _response(200, {"results": []})]) as get:
        assert glt.get_dockerhub_tags_list(repo="demisto", image_name="python3") == {"results": []}
    assert post.call_count == 2
    assert [c.kwargs["headers"] for c in get.call_args_list] == [
        {"Authorization": "Bearer old"}, {"Authorization": "Bearer new"}]


@pytest.mark.parametrize("retry_after, expected_wait", [("5", 5), ("3600", glt.RATE_LIMIT_MAX_WAIT), ("", glt.RATE_LIMIT_MAX_WAIT)])
def test_rate_limit_waits_retry_after_capped_and_retries_once(monkeypatch, retry_after, expected_wait):
    """
    Given
        - the tags request is rate limited (429) with a Retry-After header
    When
        - fetching tags
    Then
        - the request is retried once after Retry-After seconds, capped at RATE_LIMIT_MAX_WAIT
    """
    monkeypatch.delenv("DOCKERHUB_USER", raising=False)
    monkeypatch.delenv("DOCKERHUB_PASSWORD", raising=False)
    responses = [_response(429, headers={"Retry-After": retry_after}), _response(200, {"results": []})]
    with patch.object(glt.requests, "get", side_effect=responses) as get, patch.object(glt.time, "sleep") as sleep:
        assert glt.get_dockerhub_tags_list(repo="demisto", image_name="python3") == {"results": []}
    sleep.assert_called_once_with(expected_wait)
    assert get.call_count == 2


def test_falls_back_to_anonymous_when_login_fails(monkeypatch):
    """
    Given
        - DOCKERHUB_USER/DOCKERHUB_PASSWORD are set but the login call returns 401
    When
        - fetching tags
    Then
        - the tags request is still sent, anonymously
    """
    monkeypatch.setenv("DOCKERHUB_USER", "u")
    monkeypatch.setenv("DOCKERHUB_PASSWORD", "wrong")
    with patch.object(glt.requests, "post", return_value=_response(401, "Unauthorized")), \
            patch.object(glt.requests, "get", return_value=_response(200, {"results": []})) as get:
        assert glt.get_dockerhub_tags_list(repo="demisto", image_name="python3") == {"results": []}
    assert get.call_args.kwargs["headers"] == {}
