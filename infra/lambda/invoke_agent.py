"""Lambda bridge — forwards GitHub Actions payloads to AgentCore Runtime.

This thin Lambda function receives the payload from GitHub Actions
(via the aws CLI's ``lambda invoke``), forwards it to the AgentCore
Runtime endpoint, and returns the agent's response.

The Lambda execution role needs:
- ``bedrock:InvokeAgentRuntime`` on the target AgentCore Runtime ARN

The Lambda does NOT need IAM read permissions — those belong to the
AgentCore Runtime's execution role.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# The AgentCore Runtime endpoint URL — set via Lambda environment variable
AGENTCORE_RUNTIME_ENDPOINT = os.environ.get("AGENTCORE_RUNTIME_ENDPOINT", "")


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Lambda handler — bridge between GitHub Actions and AgentCore Runtime.

    Args:
        event: The invocation payload from GitHub Actions, containing
               ``task_type``, ``repo``, ``github_token``, etc.
        context: Lambda context (unused).

    Returns:
        The agent's response wrapped in a Lambda-compatible response dict.
    """
    task_type = event.get("task_type", "unknown")
    logger.info("Lambda bridge invoked: task_type=%s", task_type)

    if not AGENTCORE_RUNTIME_ENDPOINT:
        logger.error("AGENTCORE_RUNTIME_ENDPOINT not set")
        return {
            "statusCode": 500,
            "body": json.dumps(
                {"error": "AGENTCORE_RUNTIME_ENDPOINT not configured"}
            ),
        }

    # Validate that required fields are present
    required_fields = ["task_type", "github_token", "repo"]
    missing = [f for f in required_fields if not event.get(f)]
    if missing:
        logger.error("Missing required fields: %s", missing)
        return {
            "statusCode": 400,
            "body": json.dumps(
                {"error": f"Missing required fields: {missing}"}
            ),
        }

    try:
        # Use the Bedrock AgentCore Runtime client to invoke the agent
        bedrock_client = boto3.client("bedrock-agent-runtime")

        response = bedrock_client.invoke_agent(
            agentId=os.environ.get("AGENTCORE_AGENT_ID", ""),
            agentAliasId=os.environ.get("AGENTCORE_AGENT_ALIAS_ID", ""),
            sessionId=f"{task_type}-{context.aws_request_id}" if context else task_type,
            inputText=json.dumps(event),
        )

        # Collect the streamed response
        result_text = ""
        for event_stream in response.get("completion", []):
            chunk = event_stream.get("chunk", {})
            if "bytes" in chunk:
                result_text += chunk["bytes"].decode("utf-8")

        logger.info("Agent invocation complete: task_type=%s", task_type)

        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "task_type": task_type,
                    "status": "completed",
                    "response": result_text,
                }
            ),
        }

    except Exception:
        logger.exception("Failed to invoke AgentCore Runtime")
        return {
            "statusCode": 500,
            "body": json.dumps(
                {"error": "Failed to invoke agent. Check Lambda logs."}
            ),
        }
