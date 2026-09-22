"""AgentCore Platform v1.0"""

# SecurityBaselineService — CMN-C1-660 impl-04
# Holds the organization branch-protection baseline (loaded once from
# config/agent.yaml at Graph construction, never per-request) and evaluates
# whether a requested rule set falls below it.
# Stateless w.r.t. requests; constructor-injected into BaselineCheckNode.
# MUST NOT be instantiated inside execute().

from __future__ import annotations

from typing import Any

# Secure-by-default minimum baseline. config.security_baseline overrides these.
_DEFAULT_BASELINE: dict[str, Any] = {
    "require_approvals": 1,
    "prevent_force_push": True,
    "require_status_checks": True,
    "enforce_admins": False,
}


class SecurityBaselineService:
    """Evaluate a requested protection rule set against the org baseline.

    A request is REFUSED if, for any dimension the baseline mandates, the
    request explicitly sets a *weaker* value. A dimension the request leaves
    unset (``None``) is not a downgrade — the baseline value applies on write.
    """

    def __init__(self, baseline: dict[str, Any] | None = None) -> None:
        merged = dict(_DEFAULT_BASELINE)
        if baseline:
            merged.update({k: v for k, v in baseline.items() if v is not None})
        self._baseline = merged

    @property
    def baseline(self: Any) -> dict[str, Any]:
        return dict(self._baseline)

    def check(self, requested: dict[str, Any]) -> tuple[bool, str]:
        """Return (ok, reason). ok=False means the request is below baseline."""
        violations: list[str] = []

        min_approvals = self._baseline.get("require_approvals")
        req_approvals = requested.get("require_approvals")
        if min_approvals is not None and req_approvals is not None and req_approvals < min_approvals:
            violations.append(f"require_approvals={req_approvals} is below baseline minimum {min_approvals}")

        for flag in ("prevent_force_push", "require_status_checks", "enforce_admins"):
            required = self._baseline.get(flag)
            requested_val = requested.get(flag)
            if required is True and requested_val is False:
                violations.append(f"{flag} must remain enabled per baseline (requested disable)")

        if violations:
            return False, "; ".join(violations)
        return True, "Request meets or exceeds the organization security baseline."

    def effective_rules(self, requested: dict[str, Any]) -> dict[str, Any]:
        """Merge the request over the baseline — the rule set that would be written.

        Baseline values fill any dimension the request left unset; a request
        that meets baseline may also *strengthen* it (e.g. more approvals).
        """
        effective = dict(self._baseline)
        for k, v in requested.items():
            if v is not None:
                effective[k] = v
        return effective
