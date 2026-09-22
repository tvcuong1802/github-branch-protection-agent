"""AgentCore Platform v1.0"""

# InputParserService — CMN-C1-660 impl-03
# Deterministic natural-language → structured branch-protection rule parsing.
# Stateless; unit-testable in isolation. Constructor-injected into PreProcessNode.
# MUST NOT be instantiated inside execute().

from __future__ import annotations

from typing import Any

import re


class InputParseError(ValueError):
    """Raised when the instruction cannot be resolved to a target + rule set."""


# Canonical protection dimensions this template understands. Anything not
# mentioned in the instruction is left unset (None) so downstream nodes do not
# assume a value the user did not request.
_DEFAULT_RULES: dict[str, Any] = {
    "require_approvals": None,  # int
    "require_status_checks": None,  # bool
    "prevent_force_push": None,  # bool
    "enforce_admins": None,  # bool
}

# A GitHub URL, e.g. https://github.com/acme/payments-api(.git) — checked first so
# the host ("github.com") is not mistaken for the owner.
_GH_URL_RE = re.compile(r"github\.com/([A-Za-z0-9][\w.-]*)/([A-Za-z0-9][\w.-]*)", re.I)
# "owner/repo" token, e.g. acme/payments-api
_REPO_RE = re.compile(r"\b([A-Za-z0-9][\w.-]*)/([A-Za-z0-9][\w.-]*)\b")
# bare "<name> repo(sitory)" when no owner is given (org comes from config)
_BARE_REPO_RE = re.compile(r"\b([A-Za-z0-9][\w.-]*)\s+repo(?:sitory)?\b", re.I)
# "<n> review(s)" / "<n> approvals"
_APPROVALS_RE = re.compile(r"(\d+)\s*(?:reviews?|approvals?|approving reviews?)", re.I)
# "the <branch> branch" / "branch <branch>" / "protect <branch>"
_BRANCH_RE = re.compile(
    r"(?:branch\s+(?:named\s+)?['\"]?([\w./-]+)['\"]?" r"|(?:the\s+)?['\"]?([\w./-]+)['\"]?\s+branch)",
    re.I,
)


class InputParserService:
    """Parse an NL branch-protection instruction into a structured request.

    Returns ``{"target": {owner, repo, branch, dry_run}, "rules": {...}}``.
    Rule fields left unmentioned are ``None`` (not defaulted) so that the
    baseline/downgrade gates only reason about what was explicitly requested.
    """

    def parse(self, text: str, default_branch: str = "main", default_org: str = "") -> dict[str, Any]:
        if not text or not text.strip():
            raise InputParseError("Empty instruction.")

        lowered = text.lower()
        owner, repo = self._parse_repo(text, default_org)
        branch = self._parse_branch(text) or default_branch
        rules = dict(_DEFAULT_RULES)

        m = _APPROVALS_RE.search(text)
        if m:
            rules["require_approvals"] = int(m.group(1))

        if (
            re.search(r"\b(ci|status check|checks?|build)\b.*\b(green|pass|require)", lowered)
            or "require ci" in lowered
            or "required status" in lowered
        ):
            rules["require_status_checks"] = True

        if re.search(r"(prevent|no|block|disallow)\s+force[- ]?push", lowered):
            rules["prevent_force_push"] = True
        elif re.search(r"allow\s+force[- ]?push", lowered):
            rules["prevent_force_push"] = False

        if (
            re.search(r"(no|prevent|disallow)\s+admin\s+bypass", lowered)
            or "enforce admins" in lowered
            or "include administrators" in lowered
        ):
            rules["enforce_admins"] = True
        elif re.search(r"allow\s+admin\s+bypass", lowered):
            rules["enforce_admins"] = False

        # Dry-run must be an explicit directive. A bare "preview" is too common a
        # verb ("preview it to the team") to treat as a no-write intent — using it
        # would silently skip a real apply. Require an unambiguous phrase.
        dry_run = bool(
            re.search(
                r"\b(dry[- ]?run|dryrun|what[- ]?if|no[- ]?apply|do ?n'?t apply|"
                r"without applying|preview only|preview the change|simulate the change)\b",
                lowered,
            )
        )

        if not any(v is not None for v in rules.values()):
            raise InputParseError(
                "No recognizable protection rules in the instruction "
                "(reviews, status checks, force-push, admin bypass)."
            )

        return {
            "target": {"owner": owner, "repo": repo, "branch": branch, "dry_run": dry_run},
            "rules": rules,
        }

    @staticmethod
    def _parse_repo(text: str, default_org: str = "") -> tuple[str, str]:
        # A GitHub URL takes precedence so the host is not read as the owner.
        gh = _GH_URL_RE.search(text)
        if gh:
            return gh.group(1), gh.group(2).removesuffix(".git")
        m = _REPO_RE.search(text)
        if m:
            return m.group(1), m.group(2)
        # No "owner/repo" — try a bare repo name and fall back to the configured org.
        bare = _BARE_REPO_RE.search(text)
        if bare and default_org:
            return default_org, bare.group(1)
        if bare and not default_org:
            raise InputParseError(
                f"Repository '{bare.group(1)}' has no owner and no default org is configured "
                "(set config.github_org or use 'owner/repo')."
            )
        raise InputParseError("No target repository found — expected 'owner/repo' in the instruction.")

    @staticmethod
    def _parse_branch(text: str) -> str | None:
        m = _BRANCH_RE.search(text)
        if not m:
            return None
        return (m.group(1) or m.group(2) or "").strip() or None
