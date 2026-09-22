# CMN-C1-660 — Unit tests: services (parser, baseline, github client mappers)

import pytest

from src.services.input_parser_service import InputParseError, InputParserService
from src.services.github_client import GitHubClient, GitHubClientError
from src.services.security_baseline_service import SecurityBaselineService


class TestInputParser:
    def setup_method(self):
        self.p = InputParserService()

    def test_full_instruction(self):
        r = self.p.parse(
            "Protect the main branch in our payments-api repo: require 2 reviews, "
            "require CI green, prevent force push, no admin bypass",
            default_org="acme",
        )
        assert r["target"] == {"owner": "acme", "repo": "payments-api", "branch": "main", "dry_run": False}
        assert r["rules"]["require_approvals"] == 2
        assert r["rules"]["prevent_force_push"] is True
        assert r["rules"]["require_status_checks"] is True
        assert r["rules"]["enforce_admins"] is True

    def test_owner_repo_and_dry_run(self):
        r = self.p.parse("dry run: set acme/api main branch to require 1 review")
        assert r["target"]["owner"] == "acme" and r["target"]["repo"] == "api"
        assert r["target"]["dry_run"] is True
        assert r["rules"]["require_approvals"] == 1

    def test_empty_raises(self):
        with pytest.raises(InputParseError):
            self.p.parse("")

    def test_no_rules_raises(self):
        with pytest.raises(InputParseError):
            self.p.parse("acme/api main branch please")

    def test_bare_repo_without_org_raises(self):
        with pytest.raises(InputParseError):
            self.p.parse("protect the main branch in payments-api repo: require 2 reviews")

    def test_github_url_not_parsed_as_host_owner(self):
        # ADV-B: a GitHub URL must yield owner=acme/repo=api, not owner=github.com.
        r = self.p.parse("protect https://github.com/acme/api main branch: require 2 reviews")
        assert r["target"]["owner"] == "acme"
        assert r["target"]["repo"] == "api"

    def test_bare_preview_is_not_dry_run(self):
        # ADV-A: "preview" as a common verb must not silently make it a no-write dry-run.
        r = self.p.parse("acme/api main branch: require 2 reviews, then preview it to the team")
        assert r["target"]["dry_run"] is False

    def test_explicit_dry_run_directives(self):
        for phrase in (
            "dry run: acme/api main require 2 reviews",
            "acme/api main require 2 reviews (what-if)",
            "acme/api main require 2 reviews, preview only",
        ):
            assert self.p.parse(phrase)["target"]["dry_run"] is True


class TestSecurityBaseline:
    def test_pass_when_meets_baseline(self):
        b = SecurityBaselineService()
        ok, reason = b.check({"require_approvals": 2, "prevent_force_push": True})
        assert ok is True
        assert "baseline" in reason.lower()

    def test_refuse_below_approvals(self):
        b = SecurityBaselineService({"require_approvals": 2})
        ok, reason = b.check({"require_approvals": 1})
        assert ok is False
        assert "below baseline minimum 2" in reason

    def test_refuse_disabling_force_push_guard(self):
        b = SecurityBaselineService()
        ok, reason = b.check({"prevent_force_push": False})
        assert ok is False
        assert "prevent_force_push" in reason

    def test_unset_dimension_is_not_a_downgrade(self):
        b = SecurityBaselineService()
        ok, _ = b.check({"require_approvals": None, "prevent_force_push": None})
        assert ok is True

    def test_effective_rules_fill_and_strengthen(self):
        b = SecurityBaselineService()
        eff = b.effective_rules({"require_approvals": 3})
        assert eff["require_approvals"] == 3  # strengthened
        assert eff["prevent_force_push"] is True  # filled from baseline


class TestGitHubClientMappers:
    def test_normalize_protection(self):
        raw = {
            "required_pull_request_reviews": {"required_approving_review_count": 2},
            "required_status_checks": {"strict": True},
            "allow_force_pushes": {"enabled": False},
            "enforce_admins": {"enabled": True},
        }
        assert GitHubClient.normalize_protection(raw) == {
            "require_approvals": 2,
            "require_status_checks": True,
            "prevent_force_push": True,
            "enforce_admins": True,
        }

    def test_normalize_minimal_protection_object(self):
        # A protection object with no allow_force_pushes key means force pushes
        # are NOT explicitly enabled -> blocked by the protection (prevent=True).
        assert GitHubClient.normalize_protection({}) == {
            "require_approvals": 0,
            "require_status_checks": False,
            "prevent_force_push": True,
            "enforce_admins": False,
        }

    def test_normalize_force_push_allowed(self):
        raw = {"allow_force_pushes": {"enabled": True}}
        assert GitHubClient.normalize_protection(raw)["prevent_force_push"] is False

    def test_build_payload(self):
        payload = GitHubClient.build_payload(
            {"require_approvals": 2, "prevent_force_push": True, "require_status_checks": True, "enforce_admins": False}
        )
        assert payload["required_pull_request_reviews"] == {"required_approving_review_count": 2}
        assert payload["allow_force_pushes"] is False
        assert payload["enforce_admins"] is False
        assert payload["required_status_checks"] == {"strict": True, "contexts": []}

    def test_build_payload_preserves_unmanaged_dimensions(self):
        # Regression: PUT .../protection is a full replacement. An instruction
        # that only changes approvals must NOT strip dimensions this agent does
        # not model. Given the branch's current RAW protection, build_payload
        # must carry them through.
        current_raw = {
            "required_pull_request_reviews": {"required_approving_review_count": 1},
            "required_status_checks": {"strict": True, "contexts": ["ci/build"]},
            "restrictions": {
                "users": [{"login": "octocat"}],
                "teams": [{"slug": "core"}],
                "apps": [],
            },
            "required_linear_history": {"enabled": True},
            "required_conversation_resolution": {"enabled": True},
        }
        payload = GitHubClient.build_payload(
            {
                "require_approvals": 2,
                "prevent_force_push": True,
                "require_status_checks": True,
                "enforce_admins": False,
            },
            current_raw=current_raw,
        )
        # Managed change still applied.
        assert payload["required_pull_request_reviews"] == {"required_approving_review_count": 2}
        # Unmanaged dimensions preserved (not stripped to None / []).
        assert payload["required_status_checks"]["contexts"] == ["ci/build"]
        assert payload["restrictions"] == {"users": ["octocat"], "teams": ["core"], "apps": []}
        assert payload["required_linear_history"] is True
        assert payload["required_conversation_resolution"] is True

    def test_egress_guard_rejects_non_github_host(self):
        with pytest.raises(GitHubClientError):
            GitHubClient(base_url="https://evil.example.com")

    def test_egress_guard_allows_github(self):
        client = GitHubClient()  # default api.github.com — no error
        assert client is not None


class TestGitHubClientReviewsAndTransport:
    def test_build_payload_preserves_review_subobject_dimensions(self):
        # Regression (residual PASS-2 HIGH): required_pull_request_reviews is a
        # sub-object carrying dimensions this agent does not model
        # (require_code_owner_reviews, dismiss_stale_reviews, ...). Changing only
        # the approval count must NOT silently strip/weaken them.
        current_raw = {
            "required_pull_request_reviews": {
                "required_approving_review_count": 3,
                "require_code_owner_reviews": True,
                "dismiss_stale_reviews": True,
            },
        }
        payload = GitHubClient.build_payload(
            {
                "require_approvals": 1,
                "prevent_force_push": True,
                "require_status_checks": False,
                "enforce_admins": False,
            },
            current_raw=current_raw,
        )
        reviews = payload["required_pull_request_reviews"]
        assert reviews["required_approving_review_count"] == 1  # managed change applied
        assert reviews["require_code_owner_reviews"] is True  # unmodeled dim preserved
        assert reviews["dismiss_stale_reviews"] is True

    def test_transport_error_is_wrapped_as_client_error(self, monkeypatch):
        # Regression (residual PASS-2 MED): a network-layer failure must surface
        # as GitHubClientError so the caller node's `except GitHubClientError`
        # catches it and emits the graceful compliance report, instead of an
        # uncaught requests exception escaping execute().
        import src.services.github_client as gc
        from framework.secrets.context import SecretProvider, bound_secrets

        class _TokenProvider(SecretProvider):
            def get(self, key):
                return "ghp_test_token"

        def _boom(*a, **k):
            raise gc.requests.ConnectionError("connection reset")

        monkeypatch.setattr(gc.requests, "get", _boom)
        monkeypatch.setattr(gc.requests, "put", _boom)
        with bound_secrets(_TokenProvider()):
            client = GitHubClient()
            with pytest.raises(GitHubClientError):
                client.get_branch_protection("acme", "api", "main")
            with pytest.raises(GitHubClientError):
                client.set_branch_protection("acme", "api", "main", {"require_approvals": 2})
