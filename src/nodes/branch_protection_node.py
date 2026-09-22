"""AgentCore Platform v1.0 — BranchProtectionWriteNode (CMN-C1-660).

The `main` slot — the core capability. Applies the effective protection rules
via the GitHub API, but ONLY when both gates passed and there is no upstream
error. `dry_run` returns the projected rules without writing (lockout-safe
preview). A gate refusal is a valid business outcome (status SUCCESS), not an
execution error — post_process renders it.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.services.github_client import GitHubClient, GitHubClientError


class BranchProtectionWriteNode(FunctionNode):
    """Guarded branch-protection write — only after baseline + downgrade PASS."""

    # INTERNAL, and it stays INTERNAL. This node changes branch protection on the customer's GitHub repository.
    # `run_agent_marketplace()` stamps every caller VERIFIED_EXTERNAL with no surface to
    # raise it, so declaring that level here makes the change reachable by every
    # Marketplace user. CoE ruled write modes out of scope for this entry point and named
    # the lowering as the prohibited workaround (an internal ruling / the framework contract; (internal reference removed)
    # lists it as option one and rejects it).
    #
    # The S-1 gate runs in BaseNode.__call__() BEFORE execute(), so this node cannot make
    # the check itself: it would never run, and the whole invocation would end at status
    # error, which the runner raises on. Graph.add_edges() routes around it instead.
    required_trust_level: ClassVar[TrustLevel] = TrustLevel.INTERNAL

    def __init__(self, client: GitHubClient | None = None) -> None:
        super().__init__()
        self._client = client or GitHubClient()

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        blocked = self._blocked_reason(state)
        if blocked:
            emit_trace_event("protection_skipped", {"reason": blocked}, state)
            return {
                "write_result": json.dumps({"applied": False, "dry_run": False, "reason": blocked}, ensure_ascii=False),
                "status": AgentStatus.SUCCESS.value,
            }

        target = json.loads(state.get("target_context") or "{}")
        effective = json.loads(state.get("effective_rules") or "{}")
        dry_run = bool(target.get("dry_run"))

        if dry_run:
            emit_trace_event("protection_dry_run", {"repo": f"{target['owner']}/{target['repo']}"}, state)
            return {
                "write_result": json.dumps({"applied": False, "dry_run": True, "rules": effective}, ensure_ascii=False),
                "status": AgentStatus.SUCCESS.value,
            }

        # FAIL-CLOSED: a real apply is a live GitHub write. When no GITHUB_TOKEN is
        # provisioned (e.g. the STG smoke) never attempt it — return a safe
        # plan-only "cannot execute (no credential)" outcome at SUCCESS. (dry_run
        # above is a pure projection and does not reach here. The upstream S-5 gate
        # already fails closed on a missing credential; this mirrors it so the write
        # path is fail-closed even if reached directly.)
        if not self._client.credential_available():
            emit_trace_event("protection_no_credential", {}, state)
            return {
                "validation_error": "Cannot execute: no GitHub credential is configured.",
                "write_result": json.dumps(
                    {"applied": False, "dry_run": False, "no_credential": True, "reason": "no GitHub credential"},
                    ensure_ascii=False,
                ),
                "status": AgentStatus.SUCCESS.value,
            }

        try:
            applied = self._client.set_branch_protection(target["owner"], target["repo"], target["branch"], effective)
        except GitHubClientError as exc:
            emit_trace_event("protection_write_error", {"reason": str(exc)}, state)
            return {
                "validation_error": f"Branch protection write failed: {exc}",
                "write_result": json.dumps(
                    {"applied": False, "dry_run": False, "reason": str(exc)}, ensure_ascii=False
                ),
                "status": AgentStatus.SUCCESS.value,
            }

        emit_trace_event(
            "protection_applied",
            {"repo": f"{target['owner']}/{target['repo']}", "branch": target["branch"]},
            state,
        )
        return {
            "write_result": json.dumps({"applied": True, "dry_run": False, "rules": applied}, ensure_ascii=False),
            "status": AgentStatus.SUCCESS.value,
        }

    @staticmethod
    def _blocked_reason(state: dict[str, Any]) -> str:
        if state.get("status") == AgentStatus.ERROR.value:
            return "input rejected by security gate"
        if state.get("validation_error"):
            reason: str = str(state["validation_error"])
            return reason
        if state.get("baseline_verdict") == "REFUSED":
            return f"below security baseline: {state.get('baseline_reason', '')}"
        if state.get("downgrade_verdict") == "REFUSED":
            return f"would weaken current protection: {state.get('downgrade_diff', '')}"
        return ""
