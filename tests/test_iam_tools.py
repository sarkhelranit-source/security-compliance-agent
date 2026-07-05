"""Unit tests for IAM tools using botocore Stubber (no real AWS calls).

Tests get_iam_policy, simulate_policy, scan_access_keys, and
scan_inactive_roles with mocked AWS responses.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

import boto3
import pytest
from botocore.stub import Stubber

import tools.iam_tools as iam_tools_module
from tools.iam_tools import (
    get_iam_policy,
    scan_access_keys,
    scan_inactive_roles,
    simulate_policy,
)


@pytest.fixture(autouse=True)
def reset_iam_client():
    """Reset the module-level IAM client before each test."""
    iam_tools_module._iam_client = None
    yield
    iam_tools_module._iam_client = None


@pytest.fixture
def iam_client():
    """Create a stubbed IAM client and inject it into the module."""
    client = boto3.client("iam", region_name="us-east-1")
    iam_tools_module._iam_client = client
    return client


# ---------------------------------------------------------------------------
# get_iam_policy tests
# ---------------------------------------------------------------------------

class TestGetIamPolicy:
    """Tests for get_iam_policy."""

    def test_fetches_policy_document(self, iam_client):
        """Should return the full policy document."""
        policy_arn = "arn:aws:iam::123456789012:policy/TestPolicy"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                }
            ],
        }

        with Stubber(iam_client) as stubber:
            stubber.add_response(
                "get_policy",
                {
                    "Policy": {
                        "PolicyName": "TestPolicy",
                        "PolicyId": "ANPAJ2UCCR6DPCEXAMPLE",
                        "Arn": policy_arn,
                        "Path": "/",
                        "DefaultVersionId": "v1",
                        "AttachmentCount": 0,
                        "PermissionsBoundaryUsageCount": 0,
                        "IsAttachable": True,
                        "CreateDate": datetime(2024, 1, 1, tzinfo=timezone.utc),
                        "UpdateDate": datetime(2024, 1, 1, tzinfo=timezone.utc),
                    }
                },
                {"PolicyArn": policy_arn},
            )
            stubber.add_response(
                "get_policy_version",
                {
                    "PolicyVersion": {
                        "Document": json.dumps(policy_document),
                        "VersionId": "v1",
                        "IsDefaultVersion": True,
                        "CreateDate": datetime(2024, 1, 1, tzinfo=timezone.utc),
                    }
                },
                {"PolicyArn": policy_arn, "VersionId": "v1"},
            )

            result = get_iam_policy(policy_arn)

        assert result["policy_arn"] == policy_arn
        assert result["default_version_id"] == "v1"
        assert result["policy_document"] == policy_document

    def test_invalid_arn_returns_error(self):
        """Empty policy_arn should return an error."""
        result = get_iam_policy("")
        assert "error" in result


# ---------------------------------------------------------------------------
# simulate_policy tests
# ---------------------------------------------------------------------------

class TestSimulatePolicy:
    """Tests for simulate_policy."""

    def test_returns_simulation_results(self, iam_client):
        """Should parse simulation results correctly."""
        policy_json = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
            ],
        })

        with Stubber(iam_client) as stubber:
            stubber.add_response(
                "simulate_custom_policy",
                {
                    "EvaluationResults": [
                        {
                            "EvalActionName": "s3:GetObject",
                            "EvalDecision": "allowed",
                            "EvalResourceName": "*",
                            "MatchedStatements": [],
                            "MissingContextValues": [],
                        },
                        {
                            "EvalActionName": "s3:PutObject",
                            "EvalDecision": "implicitDeny",
                            "EvalResourceName": "*",
                            "MatchedStatements": [],
                            "MissingContextValues": [],
                        },
                    ],
                    "IsTruncated": False,
                },
                {
                    "PolicyInputList": [policy_json],
                    "ActionNames": ["s3:GetObject", "s3:PutObject"],
                    "ResourceArns": ["*"],
                },
            )

            result = simulate_policy(
                policy_json=policy_json,
                action_names=["s3:GetObject", "s3:PutObject"],
            )

        assert "simulation_results" in result
        assert result["simulation_results"]["s3:GetObject"]["decision"] == "allowed"
        assert result["simulation_results"]["s3:PutObject"]["decision"] == "implicitDeny"

    def test_invalid_input_returns_error(self):
        """Empty policy_json should return an error."""
        result = simulate_policy(policy_json="", action_names=["s3:GetObject"])
        assert "error" in result

    def test_empty_actions_returns_error(self):
        """Empty action list should return an error."""
        result = simulate_policy(policy_json='{"Version":"2012-10-17"}', action_names=[])
        assert "error" in result


# ---------------------------------------------------------------------------
# scan_access_keys tests
# ---------------------------------------------------------------------------

class TestScanAccessKeys:
    """Tests for scan_access_keys."""

    def test_flags_old_keys(self, iam_client):
        """Keys older than the threshold should be flagged."""
        now = datetime.now(timezone.utc)
        old_date = now - timedelta(days=120)
        new_date = now - timedelta(days=30)

        with Stubber(iam_client) as stubber:
            # list_users response
            stubber.add_response(
                "list_users",
                {
                    "Users": [
                        {
                            "UserName": "old-user",
                            "UserId": "AIDA1111111111111111",
                            "Arn": "arn:aws:iam::123456789012:user/old-user",
                            "Path": "/",
                            "CreateDate": old_date,
                        },
                        {
                            "UserName": "new-user",
                            "UserId": "AIDA2222222222222222",
                            "Arn": "arn:aws:iam::123456789012:user/new-user",
                            "Path": "/",
                            "CreateDate": new_date,
                        },
                    ],
                    "IsTruncated": False,
                },
                {},
            )

            # list_access_keys for old-user
            stubber.add_response(
                "list_access_keys",
                {
                    "AccessKeyMetadata": [
                        {
                            "UserName": "old-user",
                            "AccessKeyId": "AKIAIOSFODNN7OLD",
                            "Status": "Active",
                            "CreateDate": old_date,
                        }
                    ],
                    "IsTruncated": False,
                },
                {"UserName": "old-user"},
            )

            # list_access_keys for new-user
            stubber.add_response(
                "list_access_keys",
                {
                    "AccessKeyMetadata": [
                        {
                            "UserName": "new-user",
                            "AccessKeyId": "AKIAIOSFODNN7NEW",
                            "Status": "Active",
                            "CreateDate": new_date,
                        }
                    ],
                    "IsTruncated": False,
                },
                {"UserName": "new-user"},
            )

            result = scan_access_keys(max_age_days=90)

        assert len(result) == 1
        assert result[0]["user"] == "old-user"
        assert result[0]["access_key_id"] == "AKIAIOSFODNN7OLD"
        assert result[0]["age_days"] >= 120

    def test_no_stale_keys_returns_empty(self, iam_client):
        """If all keys are fresh, should return empty list."""
        now = datetime.now(timezone.utc)
        recent_date = now - timedelta(days=10)

        with Stubber(iam_client) as stubber:
            stubber.add_response(
                "list_users",
                {
                    "Users": [
                        {
                            "UserName": "fresh-user",
                            "UserId": "AIDA3333333333333333",
                            "Arn": "arn:aws:iam::123456789012:user/fresh-user",
                            "Path": "/",
                            "CreateDate": recent_date,
                        }
                    ],
                    "IsTruncated": False,
                },
                {},
            )
            stubber.add_response(
                "list_access_keys",
                {
                    "AccessKeyMetadata": [
                        {
                            "UserName": "fresh-user",
                            "AccessKeyId": "AKIAIOSFODNN7FRE",
                            "Status": "Active",
                            "CreateDate": recent_date,
                        }
                    ],
                    "IsTruncated": False,
                },
                {"UserName": "fresh-user"},
            )

            result = scan_access_keys(max_age_days=90)

        assert len(result) == 0

    def test_invalid_max_age_returns_error(self):
        """Non-positive max_age_days should return an error."""
        result = scan_access_keys(max_age_days=0)
        assert len(result) == 1
        assert "error" in result[0]


# ---------------------------------------------------------------------------
# scan_inactive_roles tests
# ---------------------------------------------------------------------------

class TestScanInactiveRoles:
    """Tests for scan_inactive_roles."""

    def test_flags_inactive_roles(self, iam_client):
        """Roles not used within the threshold should be flagged."""
        now = datetime.now(timezone.utc)
        old_date = now - timedelta(days=180)
        recent_date = now - timedelta(days=10)

        with Stubber(iam_client) as stubber:
            stubber.add_response(
                "list_roles",
                {
                    "Roles": [
                        {
                            "RoleName": "stale-role",
                            "RoleId": "AROA1111111111111111",
                            "Arn": "arn:aws:iam::123456789012:role/stale-role",
                            "Path": "/",
                            "AssumeRolePolicyDocument": "{}",
                            "CreateDate": old_date,
                            "RoleLastUsed": {
                                "LastUsedDate": old_date,
                                "Region": "us-east-1",
                            },
                        },
                        {
                            "RoleName": "active-role",
                            "RoleId": "AROA2222222222222222",
                            "Arn": "arn:aws:iam::123456789012:role/active-role",
                            "Path": "/",
                            "AssumeRolePolicyDocument": "{}",
                            "CreateDate": old_date,
                            "RoleLastUsed": {
                                "LastUsedDate": recent_date,
                                "Region": "us-east-1",
                            },
                        },
                    ],
                    "IsTruncated": False,
                },
                {},
            )

            result = scan_inactive_roles(inactive_days=90)

        assert len(result) == 1
        assert result[0]["role_name"] == "stale-role"
        assert result[0]["days_inactive"] >= 180

    def test_never_used_role_flagged(self, iam_client):
        """Roles that have never been used should be flagged."""
        now = datetime.now(timezone.utc)
        old_create = now - timedelta(days=120)

        with Stubber(iam_client) as stubber:
            stubber.add_response(
                "list_roles",
                {
                    "Roles": [
                        {
                            "RoleName": "never-used",
                            "RoleId": "AROA3333333333333333",
                            "Arn": "arn:aws:iam::123456789012:role/never-used",
                            "Path": "/",
                            "AssumeRolePolicyDocument": "{}",
                            "CreateDate": old_create,
                            "RoleLastUsed": {},
                        },
                    ],
                    "IsTruncated": False,
                },
                {},
            )

            result = scan_inactive_roles(inactive_days=90)

        assert len(result) == 1
        assert result[0]["role_name"] == "never-used"
        assert result[0]["last_used"] == "never"

    def test_skips_service_linked_roles(self, iam_client):
        """AWS service-linked roles should be skipped."""
        now = datetime.now(timezone.utc)
        old_date = now - timedelta(days=200)

        with Stubber(iam_client) as stubber:
            stubber.add_response(
                "list_roles",
                {
                    "Roles": [
                        {
                            "RoleName": "AWSServiceRoleForECS",
                            "RoleId": "AROA4444444444444444",
                            "Arn": "arn:aws:iam::123456789012:role/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS",
                            "Path": "/aws-service-role/ecs.amazonaws.com/",
                            "AssumeRolePolicyDocument": "{}",
                            "CreateDate": old_date,
                            "RoleLastUsed": {},
                        },
                    ],
                    "IsTruncated": False,
                },
                {},
            )

            result = scan_inactive_roles(inactive_days=90)

        assert len(result) == 0

    def test_invalid_inactive_days_returns_error(self):
        """Non-positive inactive_days should return an error."""
        result = scan_inactive_roles(inactive_days=-1)
        assert len(result) == 1
        assert "error" in result[0]
