"""IAM inspection tools — all read-only.

Uses boto3 with IAM-role-based credentials (no access keys).
Every function is designed to be wrapped as an ADK FunctionTool.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

import boto3

from config.settings import AWS_REGION

logger = logging.getLogger(__name__)

_iam_client = None


def _get_iam_client():
    """Lazy-initialize the IAM client.

    boto3 automatically resolves credentials from the IAM role attached to
    the execution environment (AgentCore Runtime, Lambda, or OIDC-assumed role).
    """
    global _iam_client
    if _iam_client is None:
        _iam_client = boto3.client("iam", region_name=AWS_REGION)
    return _iam_client


def get_iam_policy(policy_arn: str) -> dict[str, Any]:
    """Fetch the full policy document for a managed IAM policy.

    Args:
        policy_arn: The ARN of the managed IAM policy to retrieve.

    Returns:
        A dict with ``policy_arn``, ``default_version_id``, and the full
        ``policy_document`` (parsed JSON).
    """
    if not policy_arn or not isinstance(policy_arn, str):
        return {"error": "policy_arn must be a non-empty string"}

    iam = _get_iam_client()
    try:
        policy_meta = iam.get_policy(PolicyArn=policy_arn)
        version_id = policy_meta["Policy"]["DefaultVersionId"]

        policy_version = iam.get_policy_version(
            PolicyArn=policy_arn, VersionId=version_id
        )
        document = policy_version["PolicyVersion"]["Document"]

        # The document may already be a dict or a URL-encoded JSON string
        if isinstance(document, str):
            document = json.loads(document)

        return {
            "policy_arn": policy_arn,
            "default_version_id": version_id,
            "policy_document": document,
        }
    except iam.exceptions.NoSuchEntityException:
        return {"error": f"Policy not found: {policy_arn}"}
    except Exception:
        logger.exception("Failed to fetch IAM policy: %s", policy_arn)
        return {"error": "Failed to fetch IAM policy. Check agent logs for details."}


def simulate_policy(
    policy_json: str,
    action_names: list[str],
    resource_arns: list[str] | None = None,
) -> dict[str, Any]:
    """Simulate an IAM policy to determine allow/deny for given actions.

    Calls ``iam:SimulateCustomPolicy`` to test blast radius.

    Args:
        policy_json: The IAM policy document as a JSON string.
        action_names: List of IAM actions to simulate (e.g. ``["s3:GetObject"]``).
        resource_arns: Optional list of resource ARNs to scope the simulation.
                       Defaults to ``["*"]``.

    Returns:
        A dict mapping each action to its evaluation decision.
    """
    if not policy_json or not isinstance(policy_json, str):
        return {"error": "policy_json must be a non-empty JSON string"}
    if not action_names or not isinstance(action_names, list):
        return {"error": "action_names must be a non-empty list of strings"}

    if resource_arns is None:
        resource_arns = ["*"]

    iam = _get_iam_client()
    try:
        response = iam.simulate_custom_policy(
            PolicyInputList=[policy_json],
            ActionNames=action_names,
            ResourceArns=resource_arns,
        )

        results = {}
        for result in response.get("EvaluationResults", []):
            results[result["EvalActionName"]] = {
                "decision": result["EvalDecision"],
                "matched_statements": [
                    s.get("SourcePolicyId", "unknown")
                    for s in result.get("MatchedStatements", [])
                ],
            }

        return {"simulation_results": results}
    except Exception:
        logger.exception("IAM policy simulation failed")
        return {"error": "IAM policy simulation failed. Check agent logs."}


def scan_access_keys(max_age_days: int = 90) -> list[dict[str, Any]]:
    """Scan all IAM users for access keys older than the rotation threshold.

    Args:
        max_age_days: Flag keys older than this many days. Defaults to 90.

    Returns:
        A list of dicts, each describing a stale access key with user, key ID,
        creation date, and age in days.
    """
    if not isinstance(max_age_days, int) or max_age_days <= 0:
        return [{"error": "max_age_days must be a positive integer"}]

    iam = _get_iam_client()
    stale_keys: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc)

    try:
        users_paginator = iam.get_paginator("list_users")
        for users_page in users_paginator.paginate():
            for user in users_page["Users"]:
                username = user["UserName"]
                keys_paginator = iam.get_paginator("list_access_keys")
                for keys_page in keys_paginator.paginate(UserName=username):
                    for key_meta in keys_page["AccessKeyMetadata"]:
                        create_date = key_meta["CreateDate"]
                        # Ensure timezone-aware comparison
                        if create_date.tzinfo is None:
                            create_date = create_date.replace(tzinfo=timezone.utc)
                        age_days = (now - create_date).days
                        if age_days > max_age_days:
                            stale_keys.append(
                                {
                                    "user": username,
                                    "access_key_id": key_meta["AccessKeyId"],
                                    "status": key_meta["Status"],
                                    "created": create_date.isoformat(),
                                    "age_days": age_days,
                                    "threshold_days": max_age_days,
                                }
                            )
    except Exception:
        logger.exception("Failed to scan access keys")
        return [{"error": "Failed to scan access keys. Check agent logs."}]

    return stale_keys


def scan_inactive_roles(inactive_days: int = 90) -> list[dict[str, Any]]:
    """Scan all IAM roles for roles with no recent activity.

    Args:
        inactive_days: Flag roles not used within this many days. Defaults to 90.

    Returns:
        A list of dicts, each describing an inactive role with name, ARN,
        last-used date, and days since last use.
    """
    if not isinstance(inactive_days, int) or inactive_days <= 0:
        return [{"error": "inactive_days must be a positive integer"}]

    iam = _get_iam_client()
    inactive_roles: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc)

    try:
        roles_paginator = iam.get_paginator("list_roles")
        for roles_page in roles_paginator.paginate():
            for role in roles_page["Roles"]:
                role_name = role["RoleName"]

                # Skip AWS service-linked roles
                if role.get("Path", "").startswith("/aws-service-role/"):
                    continue

                last_used_info = role.get("RoleLastUsed", {})
                last_used_date = last_used_info.get("LastUsedDate")

                if last_used_date is None:
                    # Role has never been used
                    create_date = role.get("CreateDate", now)
                    if create_date.tzinfo is None:
                        create_date = create_date.replace(tzinfo=timezone.utc)
                    days_since = (now - create_date).days
                    if days_since > inactive_days:
                        inactive_roles.append(
                            {
                                "role_name": role_name,
                                "role_arn": role["Arn"],
                                "last_used": "never",
                                "created": create_date.isoformat(),
                                "days_inactive": days_since,
                                "threshold_days": inactive_days,
                            }
                        )
                else:
                    if last_used_date.tzinfo is None:
                        last_used_date = last_used_date.replace(tzinfo=timezone.utc)
                    days_since = (now - last_used_date).days
                    if days_since > inactive_days:
                        inactive_roles.append(
                            {
                                "role_name": role_name,
                                "role_arn": role["Arn"],
                                "last_used": last_used_date.isoformat(),
                                "last_used_region": last_used_info.get("Region", "unknown"),
                                "days_inactive": days_since,
                                "threshold_days": inactive_days,
                            }
                        )
    except Exception:
        logger.exception("Failed to scan inactive roles")
        return [{"error": "Failed to scan inactive roles. Check agent logs."}]

    return inactive_roles
