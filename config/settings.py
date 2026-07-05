"""Centralized configuration for the Security/Compliance Agent.

All settings are loaded from environment variables or have secure defaults.
No secrets are hardcoded. AWS credentials come from IAM roles (never access keys).
The GitHub token arrives in each invocation payload (never stored as env var).
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# AWS
# ---------------------------------------------------------------------------
AWS_REGION: str = os.environ.get("AWS_REGION", "us-east-1")

# boto3 uses the IAM role attached to the execution environment
# (AgentCore Runtime execution role, Lambda execution role, or
# GitHub Actions OIDC-assumed role). No access keys needed.

# ---------------------------------------------------------------------------
# Key / Role hygiene thresholds
# ---------------------------------------------------------------------------
KEY_ROTATION_THRESHOLD_DAYS: int = int(
    os.environ.get("KEY_ROTATION_THRESHOLD_DAYS", "90")
)
ROLE_INACTIVITY_THRESHOLD_DAYS: int = int(
    os.environ.get("ROLE_INACTIVITY_THRESHOLD_DAYS", "90")
)

# ---------------------------------------------------------------------------
# Risky IAM permissions that should trigger a review flag
# ---------------------------------------------------------------------------
RISKY_PERMISSIONS: list[str] = [
    "iam:*",
    "s3:*",
    "ec2:*",
    "sts:AssumeRole",
    "lambda:*",
    "organizations:*",
    "kms:*",
]

# ---------------------------------------------------------------------------
# Approved baseline policy path (relative to project root)
# ---------------------------------------------------------------------------
BASELINE_POLICY_PATH: str = os.environ.get(
    "BASELINE_POLICY_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "approved_baseline.json"),
)
