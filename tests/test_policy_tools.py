"""Unit tests for policy analysis tools (pure logic, no AWS calls).

Tests diff_policy_against_baseline and detect_risky_permissions with
various policy configurations.
"""

import json
import os
import tempfile

import pytest

from tools.policy_tools import detect_risky_permissions, diff_policy_against_baseline


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def baseline_policy():
    """A sample baseline policy for diff tests."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowS3Read",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [
                    "arn:aws:s3:::my-bucket",
                    "arn:aws:s3:::my-bucket/*",
                ],
            },
            {
                "Sid": "AllowEC2Describe",
                "Effect": "Allow",
                "Action": ["ec2:DescribeInstances"],
                "Resource": "*",
            },
        ],
    }


@pytest.fixture
def baseline_file(baseline_policy, tmp_path):
    """Write the baseline policy to a temp file and return the path."""
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(baseline_policy))
    return str(path)


# ---------------------------------------------------------------------------
# diff_policy_against_baseline tests
# ---------------------------------------------------------------------------

class TestDiffPolicyAgainstBaseline:
    """Tests for diff_policy_against_baseline."""

    def test_identical_policy_no_changes(self, baseline_policy, baseline_file):
        """An identical policy should produce no diff."""
        result = diff_policy_against_baseline(
            proposed_policy=json.dumps(baseline_policy),
            baseline_path=baseline_file,
        )
        assert result["has_changes"] is False
        assert result["added_actions"] == []
        assert result["removed_actions"] == []
        assert result["added_resources"] == []
        assert result["removed_resources"] == []

    def test_added_action_detected(self, baseline_policy, baseline_file):
        """A newly added action should appear in added_actions."""
        proposed = baseline_policy.copy()
        proposed["Statement"] = [s.copy() for s in proposed["Statement"]]
        proposed["Statement"][0] = {
            **proposed["Statement"][0],
            "Action": ["s3:GetObject", "s3:ListBucket", "s3:PutObject"],
        }
        result = diff_policy_against_baseline(
            proposed_policy=json.dumps(proposed),
            baseline_path=baseline_file,
        )
        assert result["has_changes"] is True
        assert "s3:PutObject" in result["added_actions"]

    def test_removed_action_detected(self, baseline_policy, baseline_file):
        """A removed action should appear in removed_actions."""
        proposed = baseline_policy.copy()
        proposed["Statement"] = [s.copy() for s in proposed["Statement"]]
        proposed["Statement"][0] = {
            **proposed["Statement"][0],
            "Action": ["s3:GetObject"],  # Removed s3:ListBucket
        }
        result = diff_policy_against_baseline(
            proposed_policy=json.dumps(proposed),
            baseline_path=baseline_file,
        )
        assert result["has_changes"] is True
        assert "s3:ListBucket" in result["removed_actions"]

    def test_added_statement_detected(self, baseline_policy, baseline_file):
        """A new statement (by Sid) should appear in added_statements."""
        proposed = baseline_policy.copy()
        proposed["Statement"] = list(proposed["Statement"]) + [
            {
                "Sid": "AllowIAMFull",
                "Effect": "Allow",
                "Action": "iam:*",
                "Resource": "*",
            }
        ]
        result = diff_policy_against_baseline(
            proposed_policy=json.dumps(proposed),
            baseline_path=baseline_file,
        )
        assert result["has_changes"] is True
        assert "AllowIAMFull" in result["added_statements"]

    def test_removed_statement_detected(self, baseline_policy, baseline_file):
        """A removed statement should appear in removed_statements."""
        proposed = baseline_policy.copy()
        # Keep only the first statement
        proposed["Statement"] = [proposed["Statement"][0]]
        result = diff_policy_against_baseline(
            proposed_policy=json.dumps(proposed),
            baseline_path=baseline_file,
        )
        assert result["has_changes"] is True
        assert "AllowEC2Describe" in result["removed_statements"]

    def test_invalid_json_returns_error(self, baseline_file):
        """Invalid JSON input should return an error dict."""
        result = diff_policy_against_baseline(
            proposed_policy="not-json",
            baseline_path=baseline_file,
        )
        assert "error" in result

    def test_empty_proposed_policy_returns_error(self, baseline_file):
        """Empty string should return an error."""
        result = diff_policy_against_baseline(
            proposed_policy="",
            baseline_path=baseline_file,
        )
        assert "error" in result

    def test_missing_baseline_returns_error(self):
        """Missing baseline file should return an error."""
        result = diff_policy_against_baseline(
            proposed_policy=json.dumps({"Version": "2012-10-17", "Statement": []}),
            baseline_path="/nonexistent/path/baseline.json",
        )
        assert "error" in result


# ---------------------------------------------------------------------------
# detect_risky_permissions tests
# ---------------------------------------------------------------------------

class TestDetectRiskyPermissions:
    """Tests for detect_risky_permissions."""

    def test_detects_iam_wildcard(self):
        """iam:* should be flagged as a risky permission."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "FullIAM",
                    "Effect": "Allow",
                    "Action": "iam:*",
                    "Resource": "*",
                }
            ],
        }
        findings = detect_risky_permissions(json.dumps(policy))
        assert len(findings) > 0
        assert any(f["action"] == "iam:*" for f in findings)
        # Wildcard action + wildcard resource = CRITICAL
        assert any(f["severity"] == "CRITICAL" for f in findings)

    def test_detects_s3_wildcard(self):
        """s3:* should be flagged as risky."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "FullS3",
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*",
                }
            ],
        }
        findings = detect_risky_permissions(json.dumps(policy))
        assert len(findings) > 0
        assert any(f["action"] == "s3:*" for f in findings)

    def test_detects_sts_assume_role(self):
        """sts:AssumeRole should be flagged."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AssumeAny",
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Resource": "*",
                }
            ],
        }
        findings = detect_risky_permissions(json.dumps(policy))
        assert len(findings) > 0
        assert any(f["matched_risky_pattern"] == "sts:AssumeRole" for f in findings)

    def test_safe_policy_no_findings(self):
        """A policy with only safe, scoped actions should produce no findings."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "SafeRead",
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "ec2:DescribeInstances"],
                    "Resource": "arn:aws:s3:::specific-bucket/*",
                }
            ],
        }
        findings = detect_risky_permissions(json.dumps(policy))
        assert len(findings) == 0

    def test_deny_effect_lower_severity(self):
        """Deny statements with risky actions should be MEDIUM, not CRITICAL."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyIAM",
                    "Effect": "Deny",
                    "Action": "iam:*",
                    "Resource": "*",
                }
            ],
        }
        findings = detect_risky_permissions(json.dumps(policy))
        assert len(findings) > 0
        assert all(f["severity"] == "MEDIUM" for f in findings)

    def test_scoped_resource_high_not_critical(self):
        """Allow with risky action but scoped resource = HIGH, not CRITICAL."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ScopedIAM",
                    "Effect": "Allow",
                    "Action": "iam:*",
                    "Resource": "arn:aws:iam::123456789012:user/specific-user",
                }
            ],
        }
        findings = detect_risky_permissions(json.dumps(policy))
        assert len(findings) > 0
        assert all(f["severity"] == "HIGH" for f in findings)

    def test_invalid_json_returns_error(self):
        """Invalid JSON should return an error list."""
        findings = detect_risky_permissions("not valid json")
        assert len(findings) == 1
        assert "error" in findings[0]

    def test_multiple_risky_actions_in_one_statement(self):
        """Multiple risky actions in one statement should each produce a finding."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "MultiRisky",
                    "Effect": "Allow",
                    "Action": ["iam:*", "s3:*", "lambda:*"],
                    "Resource": "*",
                }
            ],
        }
        findings = detect_risky_permissions(json.dumps(policy))
        risky_actions = {f["action"] for f in findings}
        assert "iam:*" in risky_actions
        assert "s3:*" in risky_actions
        assert "lambda:*" in risky_actions
