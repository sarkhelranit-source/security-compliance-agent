"""Root Orchestrator — routes tasks to the correct sub-agent.

This is the top-level agent that receives all invocations. Based on the
``task_type`` in the payload, it delegates to either the IAM Policy Reviewer
or the Secrets Hygiene Agent.

Uses Claude Sonnet via Bedrock for routing decisions (lightweight prompt).
"""

from google.adk.agents import LlmAgent
from google.adk.models.lite_llm import LiteLlm

from agents.iam_policy_reviewer import iam_policy_reviewer
from agents.secrets_hygiene_agent import secrets_hygiene_agent

INSTRUCTION = """\
You are the Security/Compliance Orchestrator. You receive task payloads and
route them to the appropriate sub-agent.

## Routing Rules

Examine the ``task_type`` field in the user's message:

- **``policy_review``**: Delegate the ENTIRE message to the
  ``iam_policy_reviewer`` sub-agent. This agent will review the proposed IAM
  policy, diff it against the baseline, detect risky permissions, simulate
  blast radius, and post a PR comment.

- **``hygiene_sweep``**: Delegate the ENTIRE message to the
  ``secrets_hygiene_agent`` sub-agent. This agent will scan for stale access
  keys and inactive roles, then open remediation tickets.

## Important Rules

- Always delegate to a sub-agent. Do NOT attempt to handle the task yourself.
- Pass the full context (including ``github_token``, ``repo``, ``pr_number``,
  ``proposed_policy``, etc.) to the sub-agent.
- If ``task_type`` is missing or unrecognized, respond with an error message
  explaining the valid task types.
- Never log, echo, or include the ``github_token`` in your response.
"""

root_agent = LlmAgent(
    name="security_compliance_orchestrator",
    model=LiteLlm(model="bedrock/amazon.nova-pro-v1:0"),
    instruction=INSTRUCTION,
    sub_agents=[iam_policy_reviewer, secrets_hygiene_agent],
)
