# CMN-C1-660 — Test Specification

All tests run on the **real** `agenticstar-agentcore==1.0.0` wheel (not stub harness).
Current status: **55 tests pass**, `ruff` clean.

## Framework Compliance (TC) — `tests/unit/test_framework_compliance.py`

| TC | Test | Expectation |
|----|------|-------------|
| TC-01 | State is a flat TypedDict | no Pydantic/dataclass; instance is a plain dict |
| TC-02 | S-2 gate rejects unsafe input | path-traversal instruction → `status = ERROR` |
| TC-03 | No hardcoded credentials in `src/` | no `ghp_`/`github_pat_` token literals |
| TC-04 | No InvocationContext field in State | State own fields carry no `InvocationContext`/`BaseModel` annotation |
| TC-05 | Domain audit event emitted in `execute()` | `emit_trace_event` fires ≥ 1× |
| TC-06 | `_security_gate_input` is `@final` | overriding raises `TypeError` at class definition |
| TC-07 | `_security_gate_output` is `@final` | overriding raises `TypeError` at class definition |
| TC-08 | S-1 trust gate enforced | ANONYMOUS caller on a VERIFIED_EXTERNAL node → `status = ERROR` |
| — | All 5 domain nodes declare `required_trust_level = VERIFIED_EXTERNAL` | assertion over the node set |

## Unit — services & nodes

- `tests/unit/test_services.py` — InputParserService (full/owner-repo/dry-run/empty/no-rules/bare-repo), SecurityBaselineService (pass/refuse-approvals/refuse-force-push/unset-not-downgrade/effective), GitHubClient mappers (normalize, force-push, build_payload, egress guard).
- `tests/unit/test_nodes.py` — each node with mocked services / an injected fake client, concrete asserts on verdicts, effective rules, dry-run no-write, downgrade diff, S-3 token redaction.

## Integration — `tests/integration/test_graph.py`

Full `Graph().compile().invoke()` with a fake GitHub client injected after compile:
valid write applied, baseline refusal (no write), dry-run (no write), downgrade refusal
(no write), unparseable input (graceful), Japanese output, write-error surfaced (no crash).

## Proof-of-Boundary — `tests/proof_of_boundary/`

| PB | File | Boundary |
|----|------|----------|
| PB-2/PB-5 (static) | `test_state_safety.py::TestStateSafety` | no credential-named/prohibited-typed State fields |
| PB-5 (runtime) | `test_state_safety.py::TestTokenNeverInState` | token authenticates the request but never appears in the returned state value |
| PB-4 | `test_import_isolation.py` | no Level-0 (`agenticstar`) imports |
| PB-6 | `test_pb_invoke_order.py` | every node: S-1 → node_start → S-2 → execute → S-3 → node_complete |

## Refused input — what the sender receives (shared contract, 2026-09-15)

Measured across the fleet with a real model: a message the framework's S-2 gate declined
came back as `status: error` carrying the generic line "No answer could be produced for
this request." `normalize_terminal_output()` raises on any status but SUCCESS, so the
runner discarded the whole envelope and the sender read **"agent failed"** — with nothing
to act on, and no reason to send anything different next time.

| Situation | What is returned | Why |
|---|---|---|
| S-2 declined the MESSAGE | `status: success`, `refusal_kind: "input"`, a sentence naming what to change, plus the trailer | The sender is legitimate and holds something they can fix; they only learn that if the reply reaches them |
| The agent has its own refusal wording | That wording, not the shared sentence | "The shipment could not be classified" says which step stopped; the generic line does not |
| S-1 denied the CALLER | `status: error`, `refusal_kind: "trust"`, the refusal and nothing else | A caller not permitted to invoke the agent must not be told what it is for |
| S-3 blocked the agent's OWN output | unchanged — `status: error` | The agent produced something its output gate would not pass. The sender can do nothing with that, and must not be invited to retry |
| The agent genuinely broke | unchanged — `status: error` | The one signal that says this is an operations problem |

Nothing downstream reads `status` to detect a refusal any more: the envelope names the
refusal in `refusal_kind`. A contract that could only be read by the symptom it was fixing
was not a contract.

Enforced by `tests/unit/test_disclaimer_always_present.py` —
`test_a_refused_MESSAGE_is_delivered_and_says_what_to_change`,
`test_a_REAL_failure_is_still_an_error` (its control), and
`test_the_gate_token_is_matched_as_a_whole_token`.
