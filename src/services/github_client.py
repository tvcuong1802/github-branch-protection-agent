"""AgentCore Platform v1.0"""

# GitHubClient — CMN-C1-660 impl-05
# Read/write GitHub branch-protection rules over the REST API.
# - Credentials come from the bound secret provider ONLY
#   (current_secrets().require("GITHUB_TOKEN")) — never from state or os.environ.
# - S-3 egress guard: only the api.github.com host is permitted.
# Constructor-injected into DowngradePreventionNode (read) and
# BranchProtectionWriteNode (read/write). MUST NOT be instantiated in execute().

from __future__ import annotations

from typing import Any

from urllib.parse import urlsplit

import requests

from framework.secrets.context import current_secrets

_ALLOWED_HOST = "api.github.com"
_BASE_URL = "https://api.github.com"
_TIMEOUT = 15  # seconds


class GitHubClientError(RuntimeError):
    """Raised on a non-recoverable GitHub API error."""


class GitHubClient:
    """Thin GitHub REST client for branch protection.

    ``base_url`` is fixed to api.github.com; the S-3 egress guard rejects any
    other host so a misconfiguration cannot exfiltrate the token off-platform.
    """

    def __init__(self, base_url: str = _BASE_URL, timeout: int = _TIMEOUT) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._guard_egress(self._base_url)

    @staticmethod
    def _guard_egress(url: str) -> None:
        host = urlsplit(url).hostname or ""
        if host != _ALLOWED_HOST:
            raise GitHubClientError(f"S-3 egress guard: host '{host}' is not permitted (only {_ALLOWED_HOST}).")

    @staticmethod
    def credential_available() -> bool:
        """True when GITHUB_TOKEN is provisioned in the bound secret provider.

        Non-raising probe (``get`` returns ``None`` on a miss) used by the caller
        nodes to FAIL-CLOSED before any live GitHub HTTP call when no credential is
        present — e.g. the STG smoke, which has no ``GITHUB_TOKEN`` and must never
        attempt a real GitHub read/write. The token is never cached on the instance;
        this only checks presence, so ``require()`` cannot raise ``MissingSecret``
        out of ``execute()`` as ``status=error``.
        """
        return bool(current_secrets().get("GITHUB_TOKEN"))

    def _headers(self: Any) -> dict[str, Any]:
        # Token fetched per call from the bound provider; never cached on self.
        token = current_secrets().require("GITHUB_TOKEN")
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _url(self, path: str) -> str:
        url = f"{self._base_url}{path}"
        self._guard_egress(url)
        return url

    # Transport wrappers: a network-layer failure (timeout, DNS, reset) raises a
    # raw requests.RequestException, which the caller nodes' `except
    # GitHubClientError` would NOT catch — the exception would escape execute()
    # and skip the mandatory graceful compliance report. Convert it to
    # GitHubClientError so every API failure travels the same graceful path.
    def _http_get(self, url: str) -> requests.Response:
        try:
            return requests.get(url, headers=self._headers(), timeout=self._timeout)
        except requests.RequestException as exc:
            raise GitHubClientError(f"GET {url} failed: {exc}") from exc

    def _http_put(self, url: str, payload: dict[str, Any]) -> requests.Response:
        try:
            return requests.put(url, headers=self._headers(), json=payload, timeout=self._timeout)
        except requests.RequestException as exc:
            raise GitHubClientError(f"PUT {url} failed: {exc}") from exc

    # ── Read ────────────────────────────────────────────────────────────────
    def get_branch_protection(self, owner: str, repo: str, branch: str) -> dict[str, Any] | None:
        """Return the branch's current protection normalized to our dimensions,
        or ``None`` when the branch has no protection (HTTP 404)."""
        url = self._url(f"/repos/{owner}/{repo}/branches/{branch}/protection")
        resp = self._http_get(url)
        if resp.status_code == 404:
            return None
        if not resp.ok:
            raise GitHubClientError(f"GET protection failed ({resp.status_code}) for {owner}/{repo}@{branch}")
        return self.normalize_protection(resp.json())

    def _get_raw_protection(self, owner: str, repo: str, branch: str) -> dict[str, Any] | None:
        """Return the branch's RAW current protection object (un-normalized), or
        ``None`` on HTTP 404. Needed for read-modify-write so PUT preserves the
        dimensions this agent does not model."""
        url = self._url(f"/repos/{owner}/{repo}/branches/{branch}/protection")
        resp = self._http_get(url)
        if resp.status_code == 404:
            return None
        if not resp.ok:
            raise GitHubClientError(f"GET protection failed ({resp.status_code}) for {owner}/{repo}@{branch}")
        pinned: dict[str, Any] | None = resp.json()
        return pinned

    # ── Write ────────────────────────────────────────────────────────────────
    def set_branch_protection(self, owner: str, repo: str, branch: str, rules: dict[str, Any]) -> dict[str, Any]:
        """Apply ``rules`` (our four managed dimensions) via PUT; return applied rules.

        GitHub's ``PUT .../protection`` is a FULL REPLACEMENT: any field omitted
        from the body is removed. This agent models only four dimensions, so a
        from-scratch payload would silently strip push ``restrictions``, linear
        history, conversation-resolution, and existing status-check contexts.
        We therefore read the branch's current RAW protection first and MERGE the
        managed dimensions on top of it (read-modify-write), preserving everything
        we do not manage. (``required_signatures`` is a separate GitHub sub-resource
        that ``PUT .../protection`` does not touch, so it is preserved automatically.)
        """
        url = self._url(f"/repos/{owner}/{repo}/branches/{branch}/protection")
        current_raw = self._get_raw_protection(owner, repo, branch)
        payload = self.build_payload(rules, current_raw=current_raw)
        resp = self._http_put(url, payload)
        if not resp.ok:
            raise GitHubClientError(f"PUT protection failed ({resp.status_code}) for {owner}/{repo}@{branch}")
        return self.normalize_protection(resp.json())

    # ── Mapping helpers (pure — unit-testable without HTTP) ──────────────────
    @staticmethod
    def normalize_protection(raw: dict[str, Any]) -> dict[str, Any]:
        """Map a GitHub protection object to our four canonical dimensions."""
        reviews = raw.get("required_pull_request_reviews") or {}
        status = raw.get("required_status_checks")
        force = raw.get("allow_force_pushes") or {}
        admins = raw.get("enforce_admins") or {}
        return {
            "require_approvals": int(reviews.get("required_approving_review_count", 0)),
            "require_status_checks": bool(status),
            "prevent_force_push": not bool(force.get("enabled", False)),
            "enforce_admins": bool(admins.get("enabled", False)),
        }

    @staticmethod
    def _restrictions_get_to_put(restrictions: dict[str, Any] | None) -> dict[str, Any] | None:
        """Translate a GET-shaped ``restrictions`` object (lists of user/team/app
        objects) into the PUT-body shape (lists of login/slug strings). Returns
        ``None`` when there are no restrictions."""
        if not restrictions:
            return None
        users = [u.get("login") for u in restrictions.get("users", []) if u.get("login")]
        teams = [t.get("slug") for t in restrictions.get("teams", []) if t.get("slug")]
        apps = [a.get("slug") for a in restrictions.get("apps", []) if a.get("slug")]
        return {"users": users, "teams": teams, "apps": apps}

    @staticmethod
    def build_payload(rules: dict[str, Any], current_raw: dict[str, Any] | None = None) -> dict[str, Any]:
        """Map our four managed dimensions to a valid GitHub PUT body.

        ``PUT .../protection`` is a full replacement, so when ``current_raw`` (the
        branch's existing RAW protection) is supplied we MERGE the managed
        dimensions on top of it and carry through every dimension this agent does
        not model, so a change that only touches approvals cannot silently strip
        push restrictions, linear history, conversation resolution, or the
        existing status-check contexts.
        """
        current_raw = current_raw or {}
        approvals = rules.get("require_approvals")
        # required_pull_request_reviews is itself a sub-object carrying
        # dimensions this agent does not model (require_code_owner_reviews,
        # dismiss_stale_reviews, bypass_pull_request_allowances, ...). Since PUT
        # is a full replacement, MERGE the managed approval count onto the
        # branch's existing review block instead of rebuilding it from scratch —
        # otherwise a change that only touches approvals silently strips
        # (weakens) code-owner / dismiss-stale enforcement.
        cur_reviews = current_raw.get("required_pull_request_reviews") or {}
        reviews = None
        if approvals is not None and approvals > 0:
            reviews = {**cur_reviews, "required_approving_review_count": int(approvals)}
        elif cur_reviews:
            # Not managing approvals here, but the branch has a review block with
            # unmodeled protections — preserve it rather than removing it.
            reviews = dict(cur_reviews)

        status_checks = None
        if rules.get("require_status_checks"):
            # Preserve the contexts already configured on the branch instead of
            # wiping them to []. A GET protection object exposes them under
            # required_status_checks.contexts (and/or .checks[].context).
            cur_status = current_raw.get("required_status_checks") or {}
            contexts = list(cur_status.get("contexts") or [])
            if not contexts:
                contexts = [c.get("context") for c in cur_status.get("checks", []) if c.get("context")]
            strict = bool(cur_status.get("strict", True)) if cur_status else True
            status_checks = {"strict": strict, "contexts": contexts}

        payload: dict[str, Any] = {
            "required_status_checks": status_checks,
            "enforce_admins": bool(rules.get("enforce_admins", False)),
            "required_pull_request_reviews": reviews,
            # Preserve push restrictions (translated to PUT shape) rather than
            # hard-coding None, which would remove them.
            "restrictions": GitHubClient._restrictions_get_to_put(current_raw.get("restrictions")),
            "allow_force_pushes": not bool(rules.get("prevent_force_push", True)),
        }

        # Carry through the remaining unmanaged, PUT-body-supported dimensions
        # exactly as GitHub currently has them, so the full-replacement PUT does
        # not drop them.
        for dim in (
            "required_linear_history",
            "required_conversation_resolution",
            "allow_deletions",
            "block_creations",
            "lock_branch",
            "allow_fork_syncing",
        ):
            cur = current_raw.get(dim)
            if isinstance(cur, dict) and "enabled" in cur:
                payload[dim] = bool(cur["enabled"])
            elif isinstance(cur, bool):
                payload[dim] = cur
        return payload
