"""AgentCore Platform v1.0 — BaselineCheckNode (CMN-C1-660).

Gate 1: compare the requested rules against the organization security baseline.
Refuse (verdict REFUSED) if any requested dimension is weaker than the baseline.
On PASS, emit the effective rule set (request merged over baseline) that the
writer will apply. Runs between pre_process and the main writer slot.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.services.security_baseline_service import SecurityBaselineService


class BaselineCheckNode(FunctionNode):
    """Refuse requested rules that fall below the org security baseline."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def __init__(self, baseline: SecurityBaselineService | None = None) -> None:
        super().__init__()
        self._baseline = baseline or SecurityBaselineService()

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        # Upstream problem — skip the gate; post_process renders the reason.
        if state.get("validation_error") or state.get("status") == AgentStatus.ERROR.value:
            emit_trace_event("baseline_skipped", {"reason": "upstream_invalid"}, state)
            return {"status": state.get("status", AgentStatus.SUCCESS.value)}

        requested = json.loads(state.get("parsed_rules") or "{}")
        ok, reason = self._baseline.check(requested)
        emit_trace_event("baseline_checked", {"verdict": "PASS" if ok else "REFUSED"}, state)

        if not ok:
            return {
                "baseline_verdict": "REFUSED",
                "baseline_reason": reason,
                "status": AgentStatus.SUCCESS.value,
            }
        return {
            "baseline_verdict": "PASS",
            "baseline_reason": reason,
            "effective_rules": json.dumps(self._baseline.effective_rules(requested), ensure_ascii=False),
            "status": AgentStatus.SUCCESS.value,
        }
