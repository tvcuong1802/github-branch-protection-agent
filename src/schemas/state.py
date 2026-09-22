"""AgentCore Platform v1.0"""

# ADR-005: State must be a flat TypedDict — never Pydantic BaseModel.
# LangGraph checkpoints use msgpack serialization; Pydantic objects
# cause silent corruption. Extend AgentState with agent-specific
# fields only. Do NOT add credentials, secrets, or Pydantic models.
#
# SAFETY CONTRACT (CMN-C1-660):
# - All complex objects MUST be stored as JSON-serialized str (not raw dict/list)
# - No GitHub token / credential in state (checkpoint DB leakage) — the token is
#   fetched at call time via current_secrets().require() and never persisted.
# - InvocationContext is accessed via config["configurable"] only, never state.

from __future__ import annotations

from typing import NotRequired

from framework.schemas.agent_state import AgentState


class State(AgentState):
    """Branch-protection configuration state for CMN-C1-660.

    All shared fields (user_input, status, session_id, node_history,
    error_log, hitl_*, etc.) are inherited from AgentState.

    Field ownership:
        PreProcessNode            -> parsed_rules, target_context, validation_error, output_language
        BaselineCheckNode         -> baseline_verdict, baseline_reason
        DowngradePreventionNode   -> current_protection, downgrade_verdict, downgrade_diff
        BranchProtectionWriteNode -> write_result
        PostProcessNode           -> confirmation_report, formatted_output (surfaced by get_output)
    """

    # The language the model decided this reader wants, carried to the trailer.
    # Declared because LangGraph merges only declared fields -- an undeclared key is
    # dropped between nodes and the decision would be computed and lost.
    answer_language: str

    # ── PreProcessNode outputs ─────────────────────────────────────────────
    # JSON-serialized structured protection rules:
    # {require_approvals:int, require_status_checks:bool, prevent_force_push:bool,
    #  enforce_admins:bool, ...}
    parsed_rules: NotRequired[str]  # default ""

    # JSON-serialized target: {owner:str, repo:str, branch:str, dry_run:bool}
    target_context: NotRequired[str]  # default ""

    # Non-empty string signals an input problem; downstream nodes short-circuit
    # and post_process renders a refusal/error report.
    validation_error: NotRequired[str]  # default ""

    # Output rendering language: "en" | "ja" | "bilingual" (default "en").
    output_language: NotRequired[str]  # default "en"

    # ── BaselineCheckNode outputs ──────────────────────────────────────────
    # "PASS" | "REFUSED" — requested rules vs org security baseline.
    baseline_verdict: NotRequired[str]  # default ""
    baseline_reason: NotRequired[str]  # default ""
    # JSON of the rule set that would actually be written (request merged over
    # baseline). Produced only when baseline_verdict == "PASS".
    effective_rules: NotRequired[str]  # default ""

    # ── DowngradePreventionNode outputs (S-5) ──────────────────────────────
    # JSON of the branch's current protection, or the JSON literal "null" if the
    # branch has none (always valid JSON — parse with json.loads unconditionally).
    current_protection: NotRequired[str]  # default ""
    # "PASS" | "REFUSED" — requested rules vs current protection.
    downgrade_verdict: NotRequired[str]  # default ""
    # JSON list of weakened dimensions, "" if none.
    downgrade_diff: NotRequired[str]  # default ""

    # ── BranchProtectionWriteNode (main slot) output ───────────────────────
    # JSON: {applied:bool, dry_run:bool, rules:{...}}
    write_result: NotRequired[str]  # default ""

    # ── PostProcessNode outputs ────────────────────────────────────────────
    # Final Markdown confirmation/refusal report. S-3 gate verifies no token
    # value crosses this boundary. `formatted_output` (inherited from AgentState)
    # carries the same report and is what get_output() surfaces to invoke().
    confirmation_report: NotRequired[str]  # default ""
