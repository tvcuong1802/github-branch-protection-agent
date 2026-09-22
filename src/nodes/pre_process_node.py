"""AgentCore Platform v1.0 — PreProcessNode (CMN-C1-660).

Parse the NL branch-protection instruction into a structured request and run
the S-2 input boundary. Business-invalid input (unparseable, no repo/rules)
becomes a graceful ``validation_error`` (SUCCESS + refusal report downstream);
a genuinely unsafe input (path traversal / control chars / oversized) is a hard
S-2 rejection (status = ERROR) via the _extra_security_gate_input hook.
"""

from __future__ import annotations

import json
import re
from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.services.input_parser_service import InputParseError, InputParserService

# S-2: reject traversal, doubled separators, and control characters that could
# escape the API path when interpolated into /repos/{owner}/{repo}/branches/...
_UNSAFE_INPUT = re.compile(r"(\.\./|[\x00-\x1f\x7f]|[<>|`$])")
_MAX_INPUT_CHARS = 4000
# Presence of any CJK character selects Japanese rendering.
_CJK = re.compile(r"[぀-ヿ㐀-鿿＀-￯]")


class PreProcessNode(FunctionNode):
    """Parse instruction → parsed_rules + target_context; set validation_error on bad input."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def __init__(self, parser: InputParserService | None = None, github_org: str = "") -> None:
        super().__init__()
        self._parser = parser or InputParserService()
        self._github_org = github_org

    def _extra_security_gate_input(self, state: dict[str, Any]) -> dict[str, Any]:
        # S-2 hard gate: never raise — set ERROR status per FunctionNode contract.
        text = state.get("user_input", "") or ""
        if len(text) > _MAX_INPUT_CHARS:
            state["status"] = AgentStatus.ERROR.value
            state.setdefault("error_log", []).append("S-2: instruction exceeds size limit.")
        elif _UNSAFE_INPUT.search(text):
            state["status"] = AgentStatus.ERROR.value
            state.setdefault("error_log", []).append("S-2: instruction contains unsafe path/control characters.")
        return state

    def _answer_language(self, state: Any) -> str:
        """Which language to answer in, decided once per request by the model.

        Called from execute(), so it runs AFTER the S-2 input gate -- anything earlier
        would send raw input, PII included, to the provider. The model READS; this agent
        DECIDES: the return value is narrowed to the two languages the scope wording
        exists in, and any other answer falls back to the script of the message.
        """
        from src.services.agent_scope import resolve_answer_language  # noqa: PLC0415

        try:
            from src.services.app_config import llm_settings  # noqa: PLC0415
            from src.services.llm_provider import build_llm_client  # noqa: PLC0415

            client = build_llm_client(dict(state or {}), llm_settings())
        except Exception:  # noqa: BLE001 -- no client: the script fallback still answers
            client = None
        return resolve_answer_language(state, client)

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        # The model reads the request and decides the language of the answer; every

        # other decision in this pipeline stays deterministic. Here rather than earlier

        # because the S-2 gate runs before execute().

        answer_language = self._answer_language(state)
        # S-2 hard rejection already set ERROR — do not process further.
        if state.get("status") == AgentStatus.ERROR.value:
            emit_trace_event("input_rejected", {"reason": "s2_unsafe_input"}, state)
            return {
                # The model's language decision, carried so the trailer can use it.
                "answer_language": answer_language,
                "validation_error": "Input rejected by the S-2 security gate.",
                "status": AgentStatus.ERROR.value,
            }

        text = state.get("user_input", "") or ""
        language = "ja" if _CJK.search(text) else "en"

        try:
            parsed = self._parser.parse(text, default_org=self._github_org)
        except InputParseError as exc:
            emit_trace_event("scope_parse_failed", {"reason": str(exc)}, state)
            return {
                # The model's language decision, carried so the trailer can use it.
                "answer_language": answer_language,
                "validation_error": f"Could not parse the instruction: {exc}",
                "output_language": language,
                "status": AgentStatus.SUCCESS.value,
            }

        emit_trace_event(
            "scope_parsed",
            {
                "repo": f"{parsed['target']['owner']}/{parsed['target']['repo']}",
                "branch": parsed["target"]["branch"],
                "dry_run": parsed["target"]["dry_run"],
            },
            state,
        )
        return {
            # The model's language decision, carried so the trailer can use it.
            "answer_language": answer_language,
            "parsed_rules": json.dumps(parsed["rules"], ensure_ascii=False),
            "target_context": json.dumps(parsed["target"], ensure_ascii=False),
            "validation_error": "",
            "output_language": language,
            "status": AgentStatus.SUCCESS.value,
        }
