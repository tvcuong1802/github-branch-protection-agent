"""AgentCore Platform v1.0 — DowngradePreventionNode (CMN-C1-660).

Gate 2 (S-5): compare the effective rule set against the branch's CURRENT
protection and refuse any change that weakens an active protection dimension.
A branch with no existing protection cannot be downgraded, so the write is
allowed. Reads current protection via the injected GitHubClient.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.services.github_client import GitHubClient, GitHubClientError


def _weakened_dimensions(effective: dict[str, Any], current: dict[str, Any]) -> list[str]:
    """Return the dimensions where `effective` is weaker than `current`."""
    weak: list[str] = []
    cur_appr = current.get("require_approvals", 0)
    eff_appr = effective.get("require_approvals", 0)
    if eff_appr < cur_appr:
        weak.append(f"require_approvals {cur_appr} -> {eff_appr}")
    for flag in ("prevent_force_push", "require_status_checks", "enforce_admins"):
        if current.get(flag) is True and effective.get(flag) is not True:
            weak.append(f"{flag} enabled -> disabled")
    return weak


class DowngradePreventionNode(FunctionNode):
    """S-5 gate — refuse writes that weaken the branch's current protection."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def __init__(self, client: GitHubClient | None = None) -> None:
        super().__init__()
        self._client = client or GitHubClient()

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        # Skip if upstream invalid or the baseline gate already refused.
        if (
            state.get("validation_error")
            or state.get("status") == AgentStatus.ERROR.value
            or state.get("baseline_verdict") == "REFUSED"
        ):
            emit_trace_event("downgrade_skipped", {"reason": "upstream_refused"}, state)
            return {"status": state.get("status", AgentStatus.SUCCESS.value)}

        target = json.loads(state.get("target_context") or "{}")
        effective = json.loads(state.get("effective_rules") or "{}")

        # FAIL-CLOSED: reading current protection needs GITHUB_TOKEN. When none is
        # provisioned (e.g. the STG smoke) never attempt a live GitHub call.
        #   - A dry_run is a pure projection that never writes, so we skip the read
        #     and let the writer render the preview (no credential required).
        #   - A real write with no credential cannot proceed — return a graceful
        #     validation_error at SUCCESS so the pipeline completes and post_process
        #     renders a "cannot execute (no credential)" notice, instead of
        #     MissingSecret propagating out of require() as status=error.
        if not self._client.credential_available():
            if bool(target.get("dry_run")):
                emit_trace_event("downgrade_skipped", {"reason": "dry_run_no_credential"}, state)
                return {
                    "current_protection": "null",
                    "downgrade_verdict": "PASS",
                    "downgrade_diff": "",
                    "status": AgentStatus.SUCCESS.value,
                }
            emit_trace_event("downgrade_no_credential", {}, state)
            return {
                "validation_error": "Cannot execute: no GitHub credential is configured.",
                "status": AgentStatus.SUCCESS.value,
            }

        try:
            current = self._client.get_branch_protection(target["owner"], target["repo"], target["branch"])
        except GitHubClientError as exc:
            emit_trace_event("downgrade_check_error", {"reason": str(exc)}, state)
            return {
                "validation_error": f"Could not read current branch protection: {exc}",
                "status": AgentStatus.SUCCESS.value,
            }

        if current is None:
            emit_trace_event("downgrade_checked", {"verdict": "PASS", "current": "none"}, state)
            return {
                # JSON null (not "") — always valid JSON for an unambiguous downstream parse.
                "current_protection": "null",
                "downgrade_verdict": "PASS",
                "downgrade_diff": "",
                "status": AgentStatus.SUCCESS.value,
            }

        weakened = _weakened_dimensions(effective, current)
        verdict = "REFUSED" if weakened else "PASS"
        emit_trace_event("downgrade_checked", {"verdict": verdict, "weakened": len(weakened)}, state)
        return {
            "current_protection": json.dumps(current, ensure_ascii=False),
            "downgrade_verdict": verdict,
            "downgrade_diff": json.dumps(weakened, ensure_ascii=False) if weakened else "",
            "status": AgentStatus.SUCCESS.value,
        }
