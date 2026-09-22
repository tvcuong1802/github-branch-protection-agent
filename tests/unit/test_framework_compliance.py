# CMN-C1-660 — Framework compliance tests (TC-01..TC-08)

import pathlib

import pytest

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import TrustLevel

from src.nodes.pre_process_node import PreProcessNode
from src.schemas.state import State

_SRC = pathlib.Path(__file__).resolve().parents[2] / "src"


def test_tc01_state_is_flat_typeddict():
    # State is a TypedDict — instances are plain dicts, no Pydantic/dataclass.
    assert hasattr(State, "__annotations__")
    assert hasattr(State, "__total__")  # TypedDict marker
    assert not hasattr(State, "model_fields")  # not a Pydantic model
    assert not hasattr(State, "__dataclass_fields__")  # not a dataclass
    inst = State(user_input="x")
    assert type(inst) is dict  # noqa: E721 - exact-type check: a TypedDict must construct to a plain dict, not a subclass; isinstance would wrongly pass


def test_tc02_s2_gate_rejects_unsafe_input():
    node = PreProcessNode(github_org="acme")
    state = {
        "caller_trust_level": TrustLevel.VERIFIED_EXTERNAL.value,
        "correlation_id": "tc02",
        "user_input": "protect acme/api ../../etc branch: require 2 reviews",
        "node_history": [],
        "error_log": [],
    }
    out = node(state)
    assert out["status"] == AgentStatus.ERROR.value


def test_tc03_no_hardcoded_credentials_in_src():
    import re

    patterns = [re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"), re.compile(r"github_pat_[A-Za-z0-9_]{20,}")]
    for path in _SRC.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for pat in patterns:
            assert not pat.search(text), f"hardcoded credential-like token in {path}"


def test_tc04_no_invocation_context_field_in_state():
    # This template's own State fields must not be typed as InvocationContext /
    # Pydantic — the context is passed via config["configurable"], not state.
    import ast

    tree = ast.parse((_SRC / "schemas" / "state.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and node.annotation:
            ann = ast.dump(node.annotation)
            assert "InvocationContext" not in ann
            assert "BaseModel" not in ann


def test_tc05_execute_emits_domain_trace_event(monkeypatch):
    import src.nodes.pre_process_node as mod

    events = []
    monkeypatch.setattr(mod, "emit_trace_event", lambda e, p, s: events.append(e))
    node = PreProcessNode(github_org="acme")
    node.execute({"user_input": "protect acme/api main branch: require 2 reviews", "status": ""})
    assert events, "execute() must emit at least one domain trace event"


def test_tc06_security_gate_input_is_final():
    with pytest.raises(TypeError):

        class BadIn(FunctionNode):
            def _security_gate_input(self, state):
                return state


def test_tc07_security_gate_output_is_final():
    with pytest.raises(TypeError):

        class BadOut(FunctionNode):
            def _security_gate_output(self, result):
                return result


def test_tc08_trust_gate_denies_insufficient_caller():
    node = PreProcessNode(github_org="acme")
    state = {
        "caller_trust_level": TrustLevel.ANONYMOUS.value,  # below VERIFIED_EXTERNAL
        "correlation_id": "tc08",
        "user_input": "protect acme/api main branch: require 2 reviews",
        "node_history": [],
        "error_log": [],
    }
    out = node(state)
    assert out["status"] == AgentStatus.ERROR.value
    assert any("trust gate" in e.lower() for e in out.get("error_log", []))


def test_read_nodes_at_verified_external_and_the_writer_at_internal():
    """The writer must NOT sit at VERIFIED_EXTERNAL; the read nodes must.

    This test used to assert VERIFIED_EXTERNAL on every node, which pinned exactly the
    state CoE prohibits: that level is what run_agent_marketplace() grants every
    Marketplace user, so declaring it on the node that changes branch protection on the customer's GitHub repository makes the change reachable
    by all of them (an internal ruling / the framework contract; (internal reference removed) rejects the lowering).

    The declaration stays honest and Graph.add_edges() routes around the node for a caller
    who cannot reach INTERNAL -- see the comment there for why the check cannot live in
    the node itself.
    """
    from src.nodes.baseline_check_node import BaselineCheckNode
    from src.nodes.branch_protection_node import BranchProtectionWriteNode
    from src.nodes.downgrade_prevention_node import DowngradePreventionNode
    from src.nodes.post_process_node import PostProcessNode

    for cls in (PreProcessNode, BaselineCheckNode, DowngradePreventionNode, BranchProtectionWriteNode, PostProcessNode):
        expected = TrustLevel.INTERNAL if cls is BranchProtectionWriteNode else TrustLevel.VERIFIED_EXTERNAL
        assert cls.required_trust_level == expected, cls.__name__
