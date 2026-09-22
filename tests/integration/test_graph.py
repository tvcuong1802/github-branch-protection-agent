# CMN-C1-660 — Integration tests: full graph invoke with a mocked GitHub client.


from framework.schemas.invocation_context import InvocationContext, TrustLevel
from framework.secrets.context import NullProvider, bound_secrets

from src.graph.graph import Graph


class FakeClient:
    """No HTTP / no secrets — injected after compile()."""

    def __init__(self, current=None, raise_on_set=False, has_credential=True):
        self._current = current
        self._raise_on_set = raise_on_set
        self._has_credential = has_credential
        self.set_calls = []

    def credential_available(self):
        return self._has_credential

    def get_branch_protection(self, owner, repo, branch):
        return self._current

    def set_branch_protection(self, owner, repo, branch, rules):
        if self._raise_on_set:
            from src.services.github_client import GitHubClientError

            raise GitHubClientError("write boom")
        self.set_calls.append((owner, repo, branch, rules))
        return rules


def _build(current=None, raise_on_set=False):
    g = Graph()
    g.compile()
    client = FakeClient(current=current, raise_on_set=raise_on_set)
    g._nodes["downgrade_prevention"]._client = client
    g._nodes["main"]._client = client
    return g, client


#: A caller who is actually permitted to write. The Marketplace runner grants
#: VERIFIED_EXTERNAL to every user and the write node requires INTERNAL, so a write-path
#: test run at the old default no longer exercises the write -- it exercises the refusal,
#: which has its own test at the bottom of this file.
_WRITER = TrustLevel.INTERNAL


def _run(g, text, language_ctx=None, trust=_WRITER):
    ctx = InvocationContext(session_id="it", caller_trust_level=trust, caller_id="it")
    with bound_secrets(NullProvider()):
        return g.invoke(text, ctx=ctx)


def test_valid_write_applied():
    g, client = _build(current=None)
    out = _run(
        g, "protect acme/api main branch: require 2 reviews, require CI green, prevent force push, no admin bypass"
    )
    assert out["status"] == "success"
    assert "Applied" in out["output"]
    assert len(client.set_calls) == 1
    _, _, _, rules = client.set_calls[0]
    assert rules["require_approvals"] == 2


def test_baseline_refusal_no_write():
    g, client = _build(current=None)
    out = _run(g, "set acme/api main branch: require 0 reviews, allow force push")
    assert out["status"] == "success"
    assert "Refused" in out["output"]
    assert client.set_calls == []


def test_dry_run_previews_without_writing():
    g, client = _build(current=None)
    out = _run(g, "dry run: protect acme/api main branch: require 2 reviews, prevent force push")
    assert "Dry Run" in out["output"]
    assert client.set_calls == []


def test_downgrade_refused_no_write():
    current = {
        "require_approvals": 3,
        "prevent_force_push": True,
        "require_status_checks": True,
        "enforce_admins": True,
    }
    g, client = _build(current=current)
    out = _run(g, "protect acme/api main branch: require 1 review, prevent force push")
    assert "Refused" in out["output"]
    assert client.set_calls == []


def test_unparseable_input_graceful():
    g, client = _build(current=None)
    out = _run(g, "hello, nothing actionable here")
    assert out["status"] == "success"  # graceful, not error
    assert "Not Applied" in out["output"]
    assert client.set_calls == []


def test_japanese_output_language():
    g, _ = _build(current=None)
    out = _run(g, "acme/api の main ブランチを保護：レビュー2件必須、force push禁止")
    assert "認証された翻訳ではありません" in out["output"]


def test_write_error_surfaced_not_crash():
    g, client = _build(current=None, raise_on_set=True)
    out = _run(g, "protect acme/api main branch: require 2 reviews, prevent force push")
    # Write failure is surfaced as a not-applied report, not an unhandled crash.
    assert out["status"] == "success"
    assert "Not Applied" in out["output"]


def test_a_marketplace_caller_cannot_change_branch_protection():
    """The ruling, end to end.

    VERIFIED_EXTERNAL is exactly what `run_agent_marketplace()` stamps on every caller. If
    this run performed the change, any Marketplace user could make it. SUCCESS, not error:
    the runner raises on anything else and the caller would be shown "agent failed" for a
    request that was merely not permitted.
    """
    g, client = _build()
    out = _run(g, "protect acme/api main branch: require 2 reviews, require CI green, prevent force push, no admin bypass", trust=TrustLevel.VERIFIED_EXTERNAL)

    assert out["status"] == "success"
    assert not out.get("write_result"), "the write happened"
    report = str(out.get("output") or out.get("formatted_output") or "")
    assert "was not performed" in report or "実行していません" in report, report[:300]
    for leak in ("TrustLevel", "VERIFIED_EXTERNAL", "INTERNAL", "token"):
        assert leak not in report, f"the refusal names {leak}"

