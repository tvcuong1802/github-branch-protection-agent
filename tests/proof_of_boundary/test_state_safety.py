# PB-2 + PB-5: State Safety Verification
# Verifies that State contains only msgpack-safe types (no Pydantic, dataclass, JWT)
# and that the GitHub token used for auth never flows into agent state / output.

import ast
import os
import re
import pytest

from framework.secrets.context import SecretProvider, bound_secrets

_SENTINEL_TOKEN = "ghp_EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"


class _FakeProvider(SecretProvider):
    """Returns a known sentinel token so we can assert it never leaks to state."""

    def get(self, key: str, default=None) -> str:
        return _SENTINEL_TOKEN


CREDENTIAL_FIELD_PATTERNS = re.compile(
    r"(jwt|token|api_key|secret|password|credential|connection_string)", re.IGNORECASE
)

PROHIBITED_TYPE_ANNOTATIONS = [
    "BaseModel",
    "InvocationContext",
]


def _scan_state_file(filepath: str) -> list[str]:
    """Scan a state definition file for safety violations."""
    with open(filepath, "r") as f:
        source = f.read()
        tree = ast.parse(source, filename=filepath)

    violations = []

    for node in ast.walk(tree):
        # Check class definitions that look like State
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                    field_name = item.target.id

                    # Check for credential-like field names
                    if CREDENTIAL_FIELD_PATTERNS.search(field_name):
                        violations.append(f"{filepath}:{item.lineno} — Credential-like field name: {field_name}")

                    # Check for prohibited type annotations
                    if item.annotation:
                        annotation_str = ast.dump(item.annotation)
                        for prohibited in PROHIBITED_TYPE_ANNOTATIONS:
                            if prohibited in annotation_str:
                                violations.append(f"{filepath}:{item.lineno} — Prohibited type in State: {prohibited}")

    return violations


class TestStateSafety:
    """PB-2/PB-5: State must be msgpack-safe with no credentials."""

    def test_state_file_safety(self):
        """State definition must not contain credential fields or prohibited types."""
        state_file = os.path.join(os.path.dirname(__file__), "..", "..", "src", "schemas", "state.py")
        if not os.path.exists(state_file):
            pytest.skip("src/schemas/state.py not found")

        violations = _scan_state_file(state_file)

        assert violations == [], "State safety violations found:\n" + "\n".join(violations)


class TestTokenNeverInState:
    """PB-5 runtime: the GitHub token authenticates the request but must never
    appear in the value returned into agent state / output."""

    def test_token_used_for_auth_but_not_returned(self, monkeypatch):
        import src.services.github_client as gc

        captured = {}

        class _Resp:
            status_code = 200
            ok = True

            def json(self):
                # A realistic protection object — no token echoed back.
                return {
                    "required_pull_request_reviews": {"required_approving_review_count": 2},
                    "required_status_checks": {"strict": True},
                    "allow_force_pushes": {"enabled": False},
                    "enforce_admins": {"enabled": True},
                }

        def _fake_put(url, headers=None, json=None, timeout=None):
            captured["auth"] = (headers or {}).get("Authorization", "")
            return _Resp()

        def _fake_get(url, headers=None, timeout=None):
            # set_branch_protection now performs a read-modify-write, so the
            # write path first GETs the branch's current protection. Mock it too
            # (auth header carries the token here as well).
            captured["get_auth"] = (headers or {}).get("Authorization", "")
            return _Resp()

        monkeypatch.setattr(gc.requests, "put", _fake_put)
        monkeypatch.setattr(gc.requests, "get", _fake_get)

        with bound_secrets(_FakeProvider()):
            client = gc.GitHubClient()
            applied = client.set_branch_protection(
                "acme", "api", "main", {"require_approvals": 2, "prevent_force_push": True}
            )

        # Token WAS used to authenticate...
        assert _SENTINEL_TOKEN in captured["auth"]
        # ...but the value flowing back into state contains no token.
        assert _SENTINEL_TOKEN not in str(applied)
