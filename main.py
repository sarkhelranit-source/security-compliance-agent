"""Application entrypoint for the Security/Compliance Agent.

Runs as a BedrockAgentCoreApp, handling invocations from the Lambda bridge.
The app wraps the ADK root orchestrator agent and manages session lifecycle.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from bedrock_agentcore import BedrockAgentCoreApp
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

from agents import root_agent

# ---------------------------------------------------------------------------
# Logging — sanitized output, never includes secrets
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ADK session and runner (shared across invocations within the same microVM)
# ---------------------------------------------------------------------------
session_service = InMemorySessionService()
runner = Runner(
    agent=root_agent,
    app_name="security_compliance_agent",
    session_service=session_service,
)

# ---------------------------------------------------------------------------
# BedrockAgentCoreApp
# ---------------------------------------------------------------------------
app = BedrockAgentCoreApp()


def _build_prompt(payload: dict[str, Any]) -> str:
    """Build a structured prompt from the invocation payload.

    The prompt includes all context the agent needs: task_type, repo,
    github_token, and task-specific fields.

    The github_token is passed in the prompt so tools can use it, but
    the agent instructions forbid echoing it in responses.
    """
    task_type = payload.get("task_type", "unknown")

    if task_type == "policy_review":
        return (
            f"Task type: policy_review\n"
            f"Repository: {payload.get('repo', 'unknown')}\n"
            f"PR Number: {payload.get('pr_number', 'unknown')}\n"
            f"Policy ARN: {payload.get('policy_arn', 'N/A')}\n"
            f"GitHub Token: {payload.get('github_token', '')}\n"
            f"\nProposed Policy:\n```json\n{payload.get('proposed_policy', '{}')}\n```\n"
            f"\nPlease review this IAM policy change and post your recommendation "
            f"as a PR comment."
        )
    elif task_type == "hygiene_sweep":
        return (
            f"Task type: hygiene_sweep\n"
            f"Repository: {payload.get('repo', 'unknown')}\n"
            f"GitHub Token: {payload.get('github_token', '')}\n"
            f"\nPlease scan for stale access keys and inactive IAM roles, "
            f"then open remediation tickets for each finding."
        )
    else:
        return (
            f"Unknown task_type: '{task_type}'. "
            f"Valid types are 'policy_review' and 'hygiene_sweep'."
        )


@app.entrypoint
async def invoke(payload: dict[str, Any]) -> dict[str, Any]:
    """Handle an invocation from the Lambda bridge / AgentCore Runtime.

    Args:
        payload: The request payload containing task_type and context.

    Returns:
        A dict with the agent's response text and metadata.
    """
    task_type = payload.get("task_type", "unknown")
    logger.info("Received invocation: task_type=%s", task_type)

    # Create a session for this invocation
    session = await session_service.create_session(
        app_name="security_compliance_agent",
        user_id=f"system-{task_type}",
    )

    # Build the prompt and run the agent
    prompt = _build_prompt(payload)

    response_text = ""
    async for event in runner.run_async(
        session_id=session.id,
        user_id=session.user_id,
        new_message=types.Content(
            role="user",
            parts=[types.Part(text=prompt)],
        ),
    ):
        # Collect the final agent response
        if event.is_final_response():
            for part in event.content.parts:
                if part.text:
                    response_text += part.text

    logger.info("Invocation complete: task_type=%s", task_type)

    return {
        "task_type": task_type,
        "status": "completed",
        "response": response_text,
    }


if __name__ == "__main__":
    # Local development: runs the HTTP server on port 8080
    # In AgentCore Runtime: the container CMD runs this same entrypoint
    app.run()
