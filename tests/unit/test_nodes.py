# CMN-C1-660 — Unit tests: nodes (mocked services/client)

import json

from framework.schemas.agent_status import AgentStatus

from src.nodes.baseline_check_node import BaselineCheckNode
from src.nodes.branch_protection_node import BranchProtectionWriteNode
from src.nodes.downgrade_prevention_node import DowngradePreventionNode
from src.nodes.post_process_node import PostProcessNode
from src.nodes.pre_process_node import PreProcessNode
from src.services.security_baseline_service import SecurityBaselineService

SUCCESS = AgentStatus.SUCCESS.value
ERROR = AgentStatus.ERROR.value


class FakeClient:
    """Injectable stand-in for GitHubClient — no HTTP, no secrets."""

    def __init__(self, current=None, raise_on_get=False, raise_on_set=False, has_credential=True):
        self._current = current
        self._raise_on_get = raise_on_get
        self._raise_on_set = raise_on_set
        self._has_credential = has_credential
        self.set_calls = []

    def credential_available(self):
        return self._has_credential

    def get_branch_protection(self, owner, repo, branch):
        if self._raise_on_get:
            from src.services.github_client import GitHubClientError

            raise GitHubClientError("boom")
        return self._current

    def set_branch_protection(self, owner, repo, branch, rules):
        if self._raise_on_set:
            from src.services.github_client import GitHubClientError

            raise GitHubClientError("write boom")
        self.set_calls.append((owner, repo, branch, rules))
        return rules


def _base_state(**kw):
    st = {"user_input": "", "node_history": [], "error_log": [], "status": ""}
    st.update(kw)
    return st


class TestPreProcessNode:
    def setup_method(self):
        self.node = PreProcessNode(github_org="acme")

    def test_valid_parse(self):
        st = _base_state(user_input="protect acme/api main branch: require 2 reviews, prevent force push")
        out = self.node.execute(st)
        assert out["validation_error"] == ""
        rules = json.loads(out["parsed_rules"])
        assert rules["require_approvals"] == 2
        assert json.loads(out["target_context"])["repo"] == "api"
        assert out["status"] == SUCCESS

    def test_unparseable_sets_validation_error(self):
        st = _base_state(user_input="hello there, nothing actionable")
        out = self.node.execute(st)
        assert out["validation_error"]
        assert out["status"] == SUCCESS  # graceful, not ERROR

    def test_s2_gate_rejects_path_traversal(self):
        st = _base_state(user_input="protect acme/api ../../etc branch: require 2 reviews")
        gated = self.node._extra_security_gate_input(st)
        assert gated["status"] == ERROR
        # execute then short-circuits to a hard refusal
        out = self.node.execute(gated)
        assert out["status"] == ERROR
        assert "security gate" in out["validation_error"].lower()

    def test_japanese_input_sets_language(self):
        st = _base_state(user_input="acme/api の main ブランチを保護：レビュー2件必須")
        out = self.node.execute(st)
        assert out["output_language"] == "ja"


class TestBaselineCheckNode:
    def setup_method(self):
        self.node = BaselineCheckNode(baseline=SecurityBaselineService({"require_approvals": 2}))

    def test_pass_emits_effective_rules(self):
        st = _base_state(parsed_rules=json.dumps({"require_approvals": 3, "prevent_force_push": True}))
        out = self.node.execute(st)
        assert out["baseline_verdict"] == "PASS"
        assert json.loads(out["effective_rules"])["require_approvals"] == 3

    def test_refuse_below_baseline(self):
        st = _base_state(parsed_rules=json.dumps({"require_approvals": 1}))
        out = self.node.execute(st)
        assert out["baseline_verdict"] == "REFUSED"
        assert "below baseline" in out["baseline_reason"]

    def test_skip_on_validation_error(self):
        st = _base_state(validation_error="bad input")
        out = self.node.execute(st)
        assert "baseline_verdict" not in out


class TestDowngradePreventionNode:
    def test_allow_when_no_current_protection(self):
        node = DowngradePreventionNode(client=FakeClient(current=None))
        st = _base_state(
            baseline_verdict="PASS",
            target_context=json.dumps({"owner": "a", "repo": "b", "branch": "main"}),
            effective_rules=json.dumps({"require_approvals": 1, "prevent_force_push": True}),
        )
        out = node.execute(st)
        assert out["downgrade_verdict"] == "PASS"
        assert out["current_protection"] == "null"
        assert json.loads(out["current_protection"]) is None  # always valid JSON

    def test_refuse_when_weakening(self):
        current = {
            "require_approvals": 3,
            "prevent_force_push": True,
            "require_status_checks": True,
            "enforce_admins": True,
        }
        node = DowngradePreventionNode(client=FakeClient(current=current))
        st = _base_state(
            baseline_verdict="PASS",
            target_context=json.dumps({"owner": "a", "repo": "b", "branch": "main"}),
            effective_rules=json.dumps(
                {
                    "require_approvals": 1,
                    "prevent_force_push": True,
                    "require_status_checks": True,
                    "enforce_admins": True,
                }
            ),
        )
        out = node.execute(st)
        assert out["downgrade_verdict"] == "REFUSED"
        assert "require_approvals 3 -> 1" in out["downgrade_diff"]

    def test_skip_when_baseline_refused(self):
        node = DowngradePreventionNode(client=FakeClient(current=None))
        out = node.execute(_base_state(baseline_verdict="REFUSED"))
        assert "downgrade_verdict" not in out

    def test_read_error_becomes_validation_error(self):
        node = DowngradePreventionNode(client=FakeClient(raise_on_get=True))
        st = _base_state(
            baseline_verdict="PASS",
            target_context=json.dumps({"owner": "a", "repo": "b", "branch": "main"}),
            effective_rules=json.dumps({"require_approvals": 1}),
        )
        out = node.execute(st)
        assert out["validation_error"]

    def test_no_credential_real_write_fails_closed(self):
        # STG smoke: no GITHUB_TOKEN provisioned → never a live read; graceful SUCCESS.
        node = DowngradePreventionNode(client=FakeClient(current=None, has_credential=False))
        st = _base_state(
            baseline_verdict="PASS",
            target_context=json.dumps({"owner": "a", "repo": "b", "branch": "main", "dry_run": False}),
            effective_rules=json.dumps({"require_approvals": 1}),
        )
        out = node.execute(st)
        assert out["status"] == SUCCESS
        assert out["validation_error"]
        assert "downgrade_verdict" not in out

    def test_no_credential_dry_run_still_previews(self):
        # A dry_run needs no credential — skip the read and let the writer preview.
        node = DowngradePreventionNode(client=FakeClient(current=None, has_credential=False))
        st = _base_state(
            baseline_verdict="PASS",
            target_context=json.dumps({"owner": "a", "repo": "b", "branch": "main", "dry_run": True}),
            effective_rules=json.dumps({"require_approvals": 1}),
        )
        out = node.execute(st)
        assert out["status"] == SUCCESS
        assert out["downgrade_verdict"] == "PASS"
        assert "validation_error" not in out


class TestBranchProtectionWriteNode:
    def _ready_state(self, dry_run=False):
        return _base_state(
            baseline_verdict="PASS",
            downgrade_verdict="PASS",
            target_context=json.dumps({"owner": "a", "repo": "b", "branch": "main", "dry_run": dry_run}),
            effective_rules=json.dumps({"require_approvals": 2, "prevent_force_push": True}),
        )

    def test_applies_when_gates_pass(self):
        client = FakeClient()
        node = BranchProtectionWriteNode(client=client)
        out = node.execute(self._ready_state())
        wr = json.loads(out["write_result"])
        assert wr["applied"] is True and wr["dry_run"] is False
        assert len(client.set_calls) == 1

    def test_dry_run_does_not_write(self):
        client = FakeClient()
        node = BranchProtectionWriteNode(client=client)
        out = node.execute(self._ready_state(dry_run=True))
        wr = json.loads(out["write_result"])
        assert wr["applied"] is False and wr["dry_run"] is True
        assert client.set_calls == []

    def test_blocked_by_baseline_refusal_no_write(self):
        client = FakeClient()
        node = BranchProtectionWriteNode(client=client)
        st = _base_state(baseline_verdict="REFUSED", baseline_reason="too weak")
        out = node.execute(st)
        wr = json.loads(out["write_result"])
        assert wr["applied"] is False
        assert client.set_calls == []

    def test_write_error_becomes_validation_error(self):
        node = BranchProtectionWriteNode(client=FakeClient(raise_on_set=True))
        out = node.execute(self._ready_state())
        assert out["validation_error"]
        assert json.loads(out["write_result"])["applied"] is False

    def test_no_credential_real_write_fails_closed(self):
        # Defense-in-depth: even if reached directly, a real write with no
        # GITHUB_TOKEN never attempts a live call — safe SUCCESS, no write.
        client = FakeClient(has_credential=False)
        node = BranchProtectionWriteNode(client=client)
        out = node.execute(self._ready_state())
        assert out["status"] == SUCCESS
        wr = json.loads(out["write_result"])
        assert wr["applied"] is False and wr.get("no_credential") is True
        assert client.set_calls == []


class TestPostProcessNode:
    def setup_method(self):
        self.node = PostProcessNode()

    def test_applied_report_en(self):
        st = _base_state(
            output_language="en",
            target_context=json.dumps({"owner": "a", "repo": "b", "branch": "main"}),
            write_result=json.dumps({"applied": True, "dry_run": False, "rules": {"require_approvals": 2}}),
        )
        out = self.node.execute(st)
        assert "Applied" in out["confirmation_report"]
        assert "a/b@main" in out["formatted_output"]

    def test_refused_report(self):
        st = _base_state(
            output_language="en",
            baseline_verdict="REFUSED",
            baseline_reason="require_approvals below baseline",
            target_context=json.dumps({"owner": "a", "repo": "b", "branch": "main"}),
            write_result=json.dumps({"applied": False, "dry_run": False, "reason": "x"}),
        )
        out = self.node.execute(st)
        assert "Refused" in out["confirmation_report"]

    def test_japanese_disclaimer(self):
        st = _base_state(
            output_language="ja",
            target_context=json.dumps({"owner": "a", "repo": "b", "branch": "main"}),
            write_result=json.dumps({"applied": True, "dry_run": False, "rules": {"require_approvals": 2}}),
        )
        out = self.node.execute(st)
        assert "認証された翻訳ではありません" in out["formatted_output"]

    def test_s3_redacts_token(self):
        leaked = {
            "confirmation_report": "token ghp_EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
            "formatted_output": "Bearer ghp_EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
        }
        cleaned = self.node._extra_security_gate_output(leaked)
        assert "ghp_EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE" not in cleaned["confirmation_report"]
        assert "[REDACTED-CREDENTIAL]" in cleaned["confirmation_report"]
        assert "ghp_" not in cleaned["formatted_output"]


class TestTheRefusalNoticeNeedsBOTHHalves:
    """"No result" alone is not "the gate refused".

    A permitted caller whose run legitimately produced no write_result -- a dry run, a
    blocked precondition, a disambiguation -- must still get that path's own report. Keying
    the write-unavailable notice on the empty key alone would replace it, and the
    substitution would only show on paths that are already unusual.
    """

    def test_a_permitted_caller_with_no_result_does_not_get_the_refusal(self):
        from src.nodes.post_process_node import PostProcessNode

        out = PostProcessNode().execute({
            "caller_trust_level": "internal",
            "output_language": "en",
            "node_history": [],
            "error_log": [],
        })
        assert "The branch-protection change was not performed" not in str(out.get("formatted_output") or "")

    def test_an_unpermitted_caller_with_no_result_does(self):
        """The other direction, or the guard could be unconditional."""
        from src.nodes.post_process_node import PostProcessNode

        out = PostProcessNode().execute({
            "caller_trust_level": "verified_external",
            "output_language": "en",
            "node_history": [],
            "error_log": [],
        })
        assert "The branch-protection change was not performed" in str(out.get("formatted_output") or "")

