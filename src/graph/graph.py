"""AgentCore Platform v1.0 — Graph (CMN-C1-660 GitHubBranchProtectionAgent).

Cat 1, L1-direct AgentBaseGraph. Single capability: configure one GitHub
branch's protection from an NL instruction, behind a baseline gate and an
S-5 downgrade-prevention gate.

The framework's compile() requires the slots pre_process / main / post_process.
The two security gates are registered as extra nodes inserted between
pre_process and the main writer slot; add_edges() is overridden to wire them:

    START -> initialize -> pre_process -> baseline_check
          -> downgrade_prevention -> main -> {route} -> post_process -> finalize -> END

Services are constructor-injected here (stateless, shared) — never built inside
execute(). Config (security baseline, github_org) comes from config/agent.yaml;
sensible secure defaults apply when the graph is constructed standalone.
"""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, START

from framework.graph.agent_base_graph import AgentBaseGraph
from shared.utils.audit_logger import emit_trace_event

from src.nodes.baseline_check_node import BaselineCheckNode
from src.nodes.branch_protection_node import BranchProtectionWriteNode
from src.nodes.downgrade_prevention_node import DowngradePreventionNode
from src.nodes.post_process_node import PostProcessNode
from src.nodes.pre_process_node import PreProcessNode
from src.schemas.state import State
from src.services.github_client import GitHubClient
from src.services.input_parser_service import InputParserService
from src.services.security_baseline_service import SecurityBaselineService


class Graph(AgentBaseGraph):
    """Guarded branch-protection pipeline."""

    @property
    def name(self: Any) -> str:
        return "cmn-c1-660"

    @property
    def state_schema(self: Any) -> type:
        return State

    def register_nodes(self: Any) -> None:
        super().register_nodes()  # injects InitializeNode + FinalizeNode

        # Constructor DI — services are stateless + shared; never built in execute().
        parser = InputParserService()
        baseline = SecurityBaselineService(self.config.get("security_baseline"))
        client = GitHubClient()
        github_org = self.config.get("github_org", "")

        self._nodes["pre_process"] = PreProcessNode(parser=parser, github_org=github_org)
        self._nodes["baseline_check"] = BaselineCheckNode(baseline=baseline)
        self._nodes["downgrade_prevention"] = DowngradePreventionNode(client=client)
        self._nodes["main"] = BranchProtectionWriteNode(client=client)
        self._nodes["post_process"] = PostProcessNode()

    def add_edges(self: Any) -> None:
        # Insert the two gate nodes between pre_process and the main writer slot;
        # preserve the standard {route} tail after main.
        self._sg.add_edge(START, "initialize")
        self._sg.add_edge("initialize", "pre_process")
        self._sg.add_edge("pre_process", "baseline_check")
        self._sg.add_edge("baseline_check", "downgrade_prevention")
        # The write gate. `main` changes branch protection on the customer's GitHub repository and declares INTERNAL; a caller who
        # cannot reach that level goes straight to post_process, which reports which
        # action was not performed. Skipping is what keeps the declaration honest without
        # ending the run at status error -- the S-1 gate runs before execute(), so the
        # node cannot refuse for itself.
        self._sg.add_conditional_edges("downgrade_prevention", self._write_route)
        self._sg.add_conditional_edges("main", self.route)
        self._sg.add_edge("post_process", "finalize")
        self._sg.add_edge("finalize", END)

    def _write_route(self: Any, state: Any) -> str:
        """`main` for a caller permitted to write, `post_process` for everyone else."""
        from src.services.write_scope import caller_may_write  # noqa: PLC0415

        if caller_may_write(state):
            return "main"
        emit_trace_event("protection_write_refused", {"reason": "write_not_available_on_this_channel"}, state)
        return "post_process"

    def get_output(self, state: Any) -> dict[str, Any]:
        """The framework envelope, with a reader-facing payload and a trailer.

        The envelope shape is kept: BaseGraph.invoke() hands this straight to the
        Marketplace runner and to the Stage-5 evidence script, and both read it as a
        dict. Only `output` changes -- from the framework value to the Markdown a chat
        reader can actually read. The structured payload stays under its own key,
        because the HTTP adapter and the boundary tests index into it.
        """
        from src.services.agent_scope import SCOPE_EN, SCOPE_JA  # noqa: PLC0415
        from src.services.output_envelope import with_disclaimer  # noqa: PLC0415

        return with_disclaimer(
            dict(super().get_output(state)),
            state,
            scope_en=SCOPE_EN,
            scope_ja=SCOPE_JA,
            rendered=_render_payload(state),
            preserve_as="formatted_output",
        )


def _render_payload(state: Any) -> str:
    """This agent's Markdown for the reader, or "" when there is nothing to render.

    The structured result stays in State: the HTTP adapter and anything downstream read
    it as data, and rendering it in the node would break them. Only the PAYLOAD changes.
    """
    from src.services.output_envelope import render_markdown  # noqa: PLC0415

    if not isinstance(state, dict):
        return ""
    payload = state.get("formatted_output")
    if isinstance(payload, str):
        return payload.strip()
    return render_markdown(payload)
