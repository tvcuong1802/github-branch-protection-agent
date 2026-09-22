"""AgentCore Platform v1.0 — PostProcessNode (CMN-C1-660).

Render a bilingual (EN / JA) confirmation, dry-run preview, or refusal report
from the gate verdicts and write result, and enforce the S-3 output boundary
(no GitHub token value may cross into the report). Japanese output uses
controlled DevOps terminology (用語統制) and keigo, with a machine-translation
disclaimer (認証された翻訳ではありません).
"""

from __future__ import annotations

import json
import re
from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import TrustLevel
from src.services.write_scope import caller_may_write
from shared.utils.audit_logger import emit_trace_event

# S-3: GitHub token shapes must never appear in the rendered report.
_TOKEN_PATTERNS = [
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._-]{20,}"),
]
_JA_DISCLAIMER = "※ 本要約は機械生成であり、認証された翻訳ではありません。"


class PostProcessNode(FunctionNode):
    """Build the bilingual confirmation/refusal report; S-3 output gate."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        language = state.get("output_language", "en") or "en"

        if not state.get("write_result") and not caller_may_write(state):
            # BOTH halves are required. "no result" alone is not "the gate refused" --
            # a disambiguation, a dry run, or a blocked precondition also leave the key
            # empty, and those must still render their own report. Only a caller who
            # cannot write on this channel gets the refusal notice. Name the action that did not happen rather than reporting a generic
            # failure -- a reader told "failed" cannot tell a refusal from a bug, and will
            # retry against a change they believe was never made.
            from src.services.write_scope import write_unavailable_notice  # noqa: PLC0415

            notice = write_unavailable_notice(
                language,
                action_en="The branch-protection change",
                action_ja="ブランチ保護設定の変更",
                channel_en="an authorised company repository system",
                channel_ja="社内の権限あるリポジトリ システム",
            )
            emit_trace_event("protection_report_refused", {"language": language}, state)
            return {
                "formatted_output": notice,
                "status": AgentStatus.SUCCESS.value,
            }
        report_en = self._render_en(state)
        report_ja = self._render_ja(state)

        if language == "ja":
            report = report_ja
        elif language == "bilingual":
            report = f"{report_en}\n\n---\n\n{report_ja}"
        else:
            report = report_en

        emit_trace_event("report_compiled", {"language": language}, state)
        # get_output() surfaces `formatted_output` (or `result`) — write that so
        # invoke() returns the report; the outer graph does NOT override get_output.
        return {
            "confirmation_report": report,
            "formatted_output": report,
            "status": AgentStatus.SUCCESS.value,
        }

    def _extra_security_gate_output(self, result: dict[str, Any]) -> dict[str, Any]:
        # S-3: redact any residual GitHub token value from all string outputs.
        for key in ("confirmation_report", "formatted_output"):
            val = result.get(key)
            if isinstance(val, str):
                for pat in _TOKEN_PATTERNS:
                    val = pat.sub("[REDACTED-CREDENTIAL]", val)
                result[key] = val
        return result

    # ── Renderers ────────────────────────────────────────────────────────────
    @staticmethod
    def _outcome(state: dict[str, Any]) -> tuple[str, dict[str, Any], dict[str, Any], dict[str, Any]]:
        target = json.loads(state.get("target_context") or "{}")
        write = json.loads(state.get("write_result") or "{}")
        rules = write.get("rules") or {}
        if state.get("validation_error"):
            kind = "error"
        elif state.get("baseline_verdict") == "REFUSED" or state.get("downgrade_verdict") == "REFUSED":
            kind = "refused"
        elif write.get("dry_run"):
            kind = "dry_run"
        elif write.get("applied"):
            kind = "applied"
        else:
            kind = "error"
        return kind, target, write, rules

    def _render_en(self, state: dict[str, Any]) -> str:
        kind, target, write, rules = self._outcome(state)
        loc = f"{target.get('owner', '?')}/{target.get('repo', '?')}@{target.get('branch', '?')}"
        if kind == "error":
            return f"# Branch Protection — Not Applied\n\n**Target:** {loc}\n\n{state.get('validation_error', 'Request could not be processed.')}"
        if kind == "refused":
            reason = (
                state.get("baseline_reason")
                if state.get("baseline_verdict") == "REFUSED"
                else f"would weaken current protection: {state.get('downgrade_diff', '')}"
            )
            return f"# Branch Protection — Refused\n\n**Target:** {loc}\n\nThe request was refused: {reason}"
        header = "Dry Run (no changes written)" if kind == "dry_run" else "Applied"
        lines = "\n".join(f"- {k}: {v}" for k, v in rules.items())
        return f"# Branch Protection — {header}\n\n**Target:** {loc}\n\n**Effective rules:**\n{lines}"

    def _render_ja(self, state: dict[str, Any]) -> str:
        kind, target, write, rules = self._outcome(state)
        loc = f"{target.get('owner', '?')}/{target.get('repo', '?')}@{target.get('branch', '?')}"
        if kind == "error":
            return (
                f"# ブランチ保護 — 未適用\n\n**対象:** {loc}\n\nリクエストを処理できませんでした。\n\n{_JA_DISCLAIMER}"
            )
        if kind == "refused":
            return f"# ブランチ保護 — 拒否\n\n**対象:** {loc}\n\nセキュリティベースラインまたは現行の保護を下回るため、リクエストを拒否いたしました。\n\n{_JA_DISCLAIMER}"
        header = "ドライラン（変更は書き込まれていません）" if kind == "dry_run" else "適用完了"
        lines = "\n".join(f"- {k}: {v}" for k, v in rules.items())
        return f"# ブランチ保護 — {header}\n\n**対象:** {loc}\n\n**適用ルール:**\n{lines}\n\n{_JA_DISCLAIMER}"
