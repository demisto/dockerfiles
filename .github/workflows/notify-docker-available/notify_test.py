import json
import os
from pathlib import Path
from typing import Any, Dict

import pytest
from notify import (
	get_tar_url,
	post_comment,
	GITHUB_API_POST_COMMENT_ENDPOINT,
	GITHUB_API_REPLACE_COMMENT_ENDPOINT,
	CIRCLECI_API_V2_GET_JOB_ARTIFACTS_ENDPOINT,
	main
)

CURRENT_DIR = Path(__file__).resolve().parent
TEST_FILES_PATH = CURRENT_DIR / "test_files"


class TestGetTarUrl:

	def test_get_tar_url(self):
		"""
		Happy-path test to make sure we get the URL of the 
		tar.gz when there are valid artifacts.

		Given:
		- A response to get the build artifacts.

		When:
		- The list artifacts is defined and there's a tar archive in the list.

		Then:
		- We get the tar URL.
		"""

		artifacts = json.loads((TEST_FILES_PATH / self.__class__.__name__ / "get_build_artifacts.json").read_text("utf-8"))

		actual = get_tar_url(artifacts)
		expected = "mock://ci.job/output/job/d03e492c-75e1-4c38-9a1b-0b03893a85ae/artifacts/0/docker_images/devorg_name:tag.tar.gz"

		assert actual == expected

	
	def test_get_tar_url_dne(self):
		"""
		Test for when there's no archive in the build artifacts.

		Given:
		- A response to get the build artifacts.

		When:
		- The list artifacts is defined but there's no tar archive in the list.

		Then:
		- We get nothing back.
		"""

		artifacts: Dict[str, Any] = json.loads((TEST_FILES_PATH / self.__class__.__name__ / "get_build_artifacts.json").read_text("utf-8"))

		items = artifacts.get("items")
		del items[-1]

		actual = get_tar_url(artifacts)

		assert not actual

	def test_get_tar_url_empty_artifacts(self):
		"""
		Test for when there's no build artifacts.

		Given:
		- Build artifacts.

		When:
		- The list artifacts is undefined.

		Then:
		- We get nothing back.
		"""

		actual = get_tar_url({})

		assert not actual 


class TestPostComment:

	pr_number = 1337
	docker_image_url = "mock://docker_image_url.dev"

	def test_post_comment_no_gh_token(self):
		
		with pytest.raises(ValueError, match="Can't post comment. GITHUB_TOKEN env variable is not set"):
			post_comment("mock://docker_image_url.dev", "1337")

	def test_post_comment_no_previous_comments(self, requests_mock, mocker):

		response = TEST_FILES_PATH / self.__class__.__name__ / "get_pr_comments.json"

		mocker.patch.dict(os.environ, {"GITHUB_TOKEN": "strongpwd"})
		requests_mock.get(GITHUB_API_POST_COMMENT_ENDPOINT.format(self.pr_number), json=json.loads(response.read_text("utf-8")))
		requests_mock.post(GITHUB_API_POST_COMMENT_ENDPOINT.format(self.pr_number), json={})

		post_comment(self.docker_image_url, self.pr_number)

	
	def test_post_comment_previous_comments(self, requests_mock, mocker):

		response = TEST_FILES_PATH / self.__class__.__name__ / "get_pr_comments_need_replace.json"

		mocker.patch.dict(os.environ, {"GITHUB_TOKEN": "strongpwd"})
		requests_mock.get(GITHUB_API_POST_COMMENT_ENDPOINT.format(self.pr_number), json=json.loads(response.read_text("utf-8")))
		requests_mock.patch(GITHUB_API_REPLACE_COMMENT_ENDPOINT.format(1760602050), json={})

		post_comment(self.docker_image_url, self.pr_number)

class TestNotify:

	def test_notify(self, capsys, mocker, requests_mock):

		event_path = TEST_FILES_PATH / self.__class__.__name__ / "gh_event.json"
		artifacts_response = json.loads((TEST_FILES_PATH / "TestGetTarUrl" / "get_build_artifacts.json").read_text("utf-8"))
		comments_response = TEST_FILES_PATH / "TestPostComment" / "get_pr_comments.json"

		mocker.patch.dict(os.environ, {"GITHUB_TOKEN": "strongpwd"})
		requests_mock.get(CIRCLECI_API_V2_GET_JOB_ARTIFACTS_ENDPOINT.format('5542'), json=artifacts_response)
		requests_mock.get(GITHUB_API_POST_COMMENT_ENDPOINT.format(TestPostComment.pr_number), json=json.loads(comments_response.read_text("utf-8")))
		requests_mock.post(GITHUB_API_POST_COMMENT_ENDPOINT.format(TestPostComment.pr_number), json={})

		main(["--event", str(event_path)])
		captured = capsys.readouterr()

		output = captured[0].splitlines()

		assert len(output) == 2
		assert output[0] == "target_url: mock://circleci.com/gh/org/repo/5542"
		assert output[1] == "circleci build: 5542"
