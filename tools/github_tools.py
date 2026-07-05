"""GitHub integration tools — PR comments and issue creation.

The GitHub token is ephemeral and payload-based: it arrives in the
invocation request from the GitHub Actions workflow and is used for a
single call, then discarded. It is never stored in env vars, on disk,
or in logs.
"""

from __future__ import annotations

import logging
from typing import Any

import requests

logger = logging.getLogger(__name__)

_GITHUB_API_BASE = "https://api.github.com"
_REQUEST_TIMEOUT_SECONDS = 30


def _build_headers(github_token: str) -> dict[str, str]:
    """Build GitHub API request headers.

    The token is validated to be non-empty but never logged.
    """
    return {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def post_pr_comment(
    repo: str,
    pr_number: int,
    body: str,
    github_token: str,
) -> dict[str, Any]:
    """Post a review comment on a GitHub Pull Request.

    Args:
        repo: Repository in ``owner/repo`` format.
        pr_number: The pull request number.
        body: Markdown body of the comment.
        github_token: Ephemeral GitHub token from the workflow payload.

    Returns:
        A dict with ``comment_id``, ``html_url`` on success, or ``error``.
    """
    if not repo or "/" not in repo:
        return {"error": "repo must be in 'owner/repo' format"}
    if not isinstance(pr_number, int) or pr_number <= 0:
        return {"error": "pr_number must be a positive integer"}
    if not body or not isinstance(body, str):
        return {"error": "body must be a non-empty string"}
    if not github_token or not isinstance(github_token, str):
        return {"error": "github_token must be a non-empty string"}

    url = f"{_GITHUB_API_BASE}/repos/{repo}/issues/{pr_number}/comments"

    try:
        response = requests.post(
            url,
            headers=_build_headers(github_token),
            json={"body": body},
            timeout=_REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        data = response.json()
        return {
            "comment_id": data.get("id"),
            "html_url": data.get("html_url"),
        }
    except requests.exceptions.HTTPError:
        status = response.status_code if response is not None else "unknown"
        logger.exception("GitHub API error posting PR comment (HTTP %s)", status)
        return {"error": f"GitHub API returned HTTP {status}"}
    except requests.exceptions.RequestException:
        logger.exception("Network error posting PR comment")
        return {"error": "Network error contacting GitHub API"}


def open_remediation_ticket(
    repo: str,
    title: str,
    body: str,
    labels: list[str],
    github_token: str,
) -> dict[str, Any]:
    """Create a GitHub Issue as a remediation ticket.

    Args:
        repo: Repository in ``owner/repo`` format.
        title: Issue title.
        body: Markdown body with finding details.
        labels: List of labels to apply (e.g. ``["security", "stale-key"]``).
        github_token: Ephemeral GitHub token from the workflow payload.

    Returns:
        A dict with ``issue_number``, ``html_url`` on success, or ``error``.
    """
    if not repo or "/" not in repo:
        return {"error": "repo must be in 'owner/repo' format"}
    if not title or not isinstance(title, str):
        return {"error": "title must be a non-empty string"}
    if not body or not isinstance(body, str):
        return {"error": "body must be a non-empty string"}
    if not isinstance(labels, list):
        return {"error": "labels must be a list of strings"}
    if not github_token or not isinstance(github_token, str):
        return {"error": "github_token must be a non-empty string"}

    url = f"{_GITHUB_API_BASE}/repos/{repo}/issues"

    try:
        response = requests.post(
            url,
            headers=_build_headers(github_token),
            json={
                "title": title,
                "body": body,
                "labels": labels,
            },
            timeout=_REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        data = response.json()
        return {
            "issue_number": data.get("number"),
            "html_url": data.get("html_url"),
        }
    except requests.exceptions.HTTPError:
        status = response.status_code if response is not None else "unknown"
        logger.exception("GitHub API error creating issue (HTTP %s)", status)
        return {"error": f"GitHub API returned HTTP {status}"}
    except requests.exceptions.RequestException:
        logger.exception("Network error creating remediation ticket")
        return {"error": "Network error contacting GitHub API"}
