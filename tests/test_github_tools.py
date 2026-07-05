"""Unit tests for GitHub tools using mocked HTTP (no real API calls).

Tests post_pr_comment and open_remediation_ticket with various inputs.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from tools.github_tools import open_remediation_ticket, post_pr_comment


# ---------------------------------------------------------------------------
# post_pr_comment tests
# ---------------------------------------------------------------------------

class TestPostPrComment:
    """Tests for post_pr_comment."""

    @patch("tools.github_tools.requests.post")
    def test_posts_comment_successfully(self, mock_post):
        """Should post a comment and return comment_id + html_url."""
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "id": 42,
            "html_url": "https://github.com/acme/infra/pull/7#issuecomment-42",
        }
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        result = post_pr_comment(
            repo="acme/infra",
            pr_number=7,
            body="## Review\n\nLooks good!",
            github_token="ghs_fake_token_12345",
        )

        assert result["comment_id"] == 42
        assert "html_url" in result

        # Verify the request was made correctly
        call_args = mock_post.call_args
        assert "acme/infra" in call_args[0][0]
        assert call_args[1]["json"]["body"] == "## Review\n\nLooks good!"
        assert "Bearer ghs_fake_token_12345" in call_args[1]["headers"]["Authorization"]

    @patch("tools.github_tools.requests.post")
    def test_handles_http_error(self, mock_post):
        """HTTP errors should return a sanitized error message."""
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
            "Forbidden", response=mock_response
        )
        mock_post.return_value = mock_response

        result = post_pr_comment(
            repo="acme/infra",
            pr_number=7,
            body="Test",
            github_token="ghs_fake_token",
        )

        assert "error" in result

    def test_invalid_repo_format(self):
        """Repo without '/' should return an error."""
        result = post_pr_comment(
            repo="invalid-repo",
            pr_number=1,
            body="Test",
            github_token="ghs_token",
        )
        assert "error" in result
        assert "owner/repo" in result["error"]

    def test_invalid_pr_number(self):
        """Non-positive pr_number should return an error."""
        result = post_pr_comment(
            repo="acme/infra",
            pr_number=0,
            body="Test",
            github_token="ghs_token",
        )
        assert "error" in result

    def test_empty_body(self):
        """Empty body should return an error."""
        result = post_pr_comment(
            repo="acme/infra",
            pr_number=1,
            body="",
            github_token="ghs_token",
        )
        assert "error" in result

    def test_empty_token(self):
        """Empty github_token should return an error."""
        result = post_pr_comment(
            repo="acme/infra",
            pr_number=1,
            body="Test",
            github_token="",
        )
        assert "error" in result


# ---------------------------------------------------------------------------
# open_remediation_ticket tests
# ---------------------------------------------------------------------------

class TestOpenRemediationTicket:
    """Tests for open_remediation_ticket."""

    @patch("tools.github_tools.requests.post")
    def test_creates_issue_successfully(self, mock_post):
        """Should create an issue and return issue_number + html_url."""
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "number": 99,
            "html_url": "https://github.com/acme/infra/issues/99",
        }
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        result = open_remediation_ticket(
            repo="acme/infra",
            title="[Stale Key] admin — 120 days old",
            body="Key AKIA... is past rotation threshold.",
            labels=["security", "stale-key", "automated"],
            github_token="ghs_fake_token_12345",
        )

        assert result["issue_number"] == 99
        assert "html_url" in result

        # Verify labels were sent
        call_args = mock_post.call_args
        assert call_args[1]["json"]["labels"] == [
            "security",
            "stale-key",
            "automated",
        ]

    @patch("tools.github_tools.requests.post")
    def test_handles_http_error(self, mock_post):
        """HTTP errors should return a sanitized error message."""
        mock_response = MagicMock()
        mock_response.status_code = 422
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
            "Unprocessable", response=mock_response
        )
        mock_post.return_value = mock_response

        result = open_remediation_ticket(
            repo="acme/infra",
            title="Test Issue",
            body="Test body",
            labels=["security"],
            github_token="ghs_fake_token",
        )

        assert "error" in result

    def test_invalid_repo_format(self):
        """Repo without '/' should return an error."""
        result = open_remediation_ticket(
            repo="no-slash",
            title="Test",
            body="Test",
            labels=["security"],
            github_token="ghs_token",
        )
        assert "error" in result

    def test_empty_title(self):
        """Empty title should return an error."""
        result = open_remediation_ticket(
            repo="acme/infra",
            title="",
            body="Test",
            labels=["security"],
            github_token="ghs_token",
        )
        assert "error" in result

    def test_empty_body(self):
        """Empty body should return an error."""
        result = open_remediation_ticket(
            repo="acme/infra",
            title="Test",
            body="",
            labels=["security"],
            github_token="ghs_token",
        )
        assert "error" in result

    def test_invalid_labels_type(self):
        """Non-list labels should return an error."""
        result = open_remediation_ticket(
            repo="acme/infra",
            title="Test",
            body="Test",
            labels="not-a-list",
            github_token="ghs_token",
        )
        assert "error" in result

    def test_empty_token(self):
        """Empty github_token should return an error."""
        result = open_remediation_ticket(
            repo="acme/infra",
            title="Test",
            body="Test",
            labels=["security"],
            github_token="",
        )
        assert "error" in result
