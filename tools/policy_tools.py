"""Policy analysis tools — pure logic, no AWS calls.

These tools diff proposed IAM policies against an approved baseline and
detect risky permissions. They operate on policy JSON strings and files,
making them easy to unit-test without mocking AWS.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from config.settings import BASELINE_POLICY_PATH, RISKY_PERMISSIONS

logger = logging.getLogger(__name__)


def _load_json_file(path: str) -> dict[str, Any] | None:
    """Safely load and parse a JSON file.

    Returns None and logs a warning if the file is missing or malformed.
    """
    if not os.path.isfile(path):
        logger.warning("JSON file not found: %s", path)
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        logger.exception("Failed to read JSON file: %s", path)
        return None


def _extract_actions(policy: dict[str, Any]) -> set[str]:
    """Extract all actions from a policy document into a flat set."""
    actions: set[str] = set()
    for statement in policy.get("Statement", []):
        raw = statement.get("Action", [])
        if isinstance(raw, str):
            raw = [raw]
        actions.update(raw)
    return actions


def _extract_resources(policy: dict[str, Any]) -> set[str]:
    """Extract all resources from a policy document into a flat set."""
    resources: set[str] = set()
    for statement in policy.get("Statement", []):
        raw = statement.get("Resource", [])
        if isinstance(raw, str):
            raw = [raw]
        resources.update(raw)
    return resources


def diff_policy_against_baseline(
    proposed_policy: str,
    baseline_path: str | None = None,
) -> dict[str, Any]:
    """Compute a semantic diff between a proposed policy and the approved baseline.

    Args:
        proposed_policy: The proposed IAM policy document as a JSON string.
        baseline_path: Path to the approved baseline JSON file. Defaults to
                       the path configured in ``config.settings``.

    Returns:
        A dict with ``added_actions``, ``removed_actions``, ``added_resources``,
        ``removed_resources``, ``added_statements``, ``removed_statements``,
        and a boolean ``has_changes``.
    """
    if not proposed_policy or not isinstance(proposed_policy, str):
        return {"error": "proposed_policy must be a non-empty JSON string"}

    try:
        proposed = json.loads(proposed_policy)
    except json.JSONDecodeError:
        return {"error": "proposed_policy is not valid JSON"}

    if baseline_path is None:
        baseline_path = BASELINE_POLICY_PATH

    baseline = _load_json_file(baseline_path)
    if baseline is None:
        return {"error": f"Could not load baseline policy from {baseline_path}"}

    # --- Actions diff ---
    proposed_actions = _extract_actions(proposed)
    baseline_actions = _extract_actions(baseline)
    added_actions = sorted(proposed_actions - baseline_actions)
    removed_actions = sorted(baseline_actions - proposed_actions)

    # --- Resources diff ---
    proposed_resources = _extract_resources(proposed)
    baseline_resources = _extract_resources(baseline)
    added_resources = sorted(proposed_resources - baseline_resources)
    removed_resources = sorted(baseline_resources - proposed_resources)

    # --- Statement-level diff (by Sid) ---
    proposed_sids = {
        s.get("Sid", f"unnamed-{i}"): s
        for i, s in enumerate(proposed.get("Statement", []))
    }
    baseline_sids = {
        s.get("Sid", f"unnamed-{i}"): s
        for i, s in enumerate(baseline.get("Statement", []))
    }
    added_statements = sorted(set(proposed_sids) - set(baseline_sids))
    removed_statements = sorted(set(baseline_sids) - set(proposed_sids))

    has_changes = bool(
        added_actions
        or removed_actions
        or added_resources
        or removed_resources
        or added_statements
        or removed_statements
    )

    return {
        "has_changes": has_changes,
        "added_actions": added_actions,
        "removed_actions": removed_actions,
        "added_resources": added_resources,
        "removed_resources": removed_resources,
        "added_statements": added_statements,
        "removed_statements": removed_statements,
    }


def _matches_risky_pattern(action: str, risky: str) -> bool:
    """Check if an action matches a risky permission pattern.

    Supports wildcard patterns like ``iam:*`` matching ``iam:CreateUser``,
    and exact matches like ``sts:AssumeRole``.
    """
    action = action.lower()
    risky = risky.lower()

    if risky == action or action == "*":
        return True

    # High-risk administrative services where ANY action is considered risky
    high_risk_services = {"iam", "organizations", "kms", "sts", "lambda"}

    if risky.endswith(":*"):
        risky_service = risky.split(":")[0]
        if risky_service in high_risk_services:
            prefix = risky[:-1]  # e.g. "iam:"
            if action.startswith(prefix):
                return True
        else:
            # For other services (like s3, ec2), only match if the action is a wildcard
            if action.endswith(":*") or action == "*":
                prefix = risky[:-1]
                if action.startswith(prefix):
                    return True
    
    if action.endswith(":*"):
        prefix = action[:-1]
        if risky.startswith(prefix):
            return True

    return False


def detect_risky_permissions(policy_json: str) -> list[dict[str, Any]]:
    """Scan a policy document for overly-broad or dangerous permissions.

    Each action in the policy's statements is checked against the configured
    ``RISKY_PERMISSIONS`` list.

    Args:
        policy_json: The IAM policy document as a JSON string.

    Returns:
        A list of findings, each with ``action``, ``matched_risky_pattern``,
        ``statement_sid``, ``effect``, and ``severity``.
    """
    if not policy_json or not isinstance(policy_json, str):
        return [{"error": "policy_json must be a non-empty JSON string"}]

    try:
        policy = json.loads(policy_json)
    except json.JSONDecodeError:
        return [{"error": "policy_json is not valid JSON"}]

    findings: list[dict[str, Any]] = []

    for i, statement in enumerate(policy.get("Statement", [])):
        effect = statement.get("Effect", "Allow")
        sid = statement.get("Sid", f"Statement-{i}")

        raw_actions = statement.get("Action", [])
        if isinstance(raw_actions, str):
            raw_actions = [raw_actions]

        raw_resources = statement.get("Resource", [])
        if isinstance(raw_resources, str):
            raw_resources = [raw_resources]

        for action in raw_actions:
            for risky in RISKY_PERMISSIONS:
                if _matches_risky_pattern(action, risky):
                    # Higher severity for Allow + wildcard resource
                    has_wildcard_resource = "*" in raw_resources
                    severity = (
                        "CRITICAL"
                        if effect == "Allow" and has_wildcard_resource
                        else "HIGH" if effect == "Allow" else "MEDIUM"
                    )
                    findings.append(
                        {
                            "action": action,
                            "matched_risky_pattern": risky,
                            "statement_sid": sid,
                            "effect": effect,
                            "resource": raw_resources,
                            "severity": severity,
                            "reason": (
                                f"Action '{action}' matches risky pattern '{risky}' "
                                f"in {effect} statement '{sid}'"
                            ),
                        }
                    )

    return findings
