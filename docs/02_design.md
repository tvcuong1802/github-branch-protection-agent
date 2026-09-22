# CMN-C1-660 — Technical Design Specification

## Position in AgentCore Architecture

- **Agent Class**: `Graph`
- **L1 Base**: `AgentBaseGraph` (L1-direct). ToolCallingAgent is a conceptual reference only — not an inheritance target (2026-05-18 L2-abolition policy).
- **Category**: Cat 1 — single generic capability (configure one branch's protection).
- **Three-Layer Separation**:
  - **State**: flat `TypedDict` (`State(AgentState)`) — primitives + JSON-serialized `str` only (msgpack-safe). No Pydantic/dataclass, no credentials.
  - **Node**: L1 inheritance (`FunctionNode`, Template Method — override `execute(self, state) -> dict` only).
  - **Graph**: composition — `register_nodes()` (constructor-DI services) + `add_edges()` override to insert the two gate nodes.

## Node Backbone & Slot Mapping

The framework's `AgentBaseGraph.compile()` hard-requires the three slots
`pre_process` / `main` / `post_process` (verified on wheel 1.0.0 — `MissingNodeError`
otherwise). The proposal's five conceptual steps map onto the backbone as follows —
the two security gates are registered as **extra nodes** inserted before the `main`
slot, and the branch-protection write (the core capability) occupies `main`:

| Slot / node key | Node class | Responsibility | Writes |
|---|---|---|---|
| initialize | InitializeNode (framework) | schema_version, session_id, trust_level | — |
| pre_process | PreProcessNode | S-2 input boundary (repo/branch sanitization, size); NL parse → structured rules; resolve target | `parsed_rules`, `target_context`, `validation_error` |
| baseline_check *(extra)* | BaselineCheckNode | compare requested rules vs org baseline; refuse if weaker | `baseline_verdict`, `baseline_reason` |
| downgrade_prevention *(extra, S-5)* | DowngradePreventionNode | read current protection via client; refuse if request weakens it (allow if no current protection). **Fail-closed:** if no `GITHUB_TOKEN` is provisioned (`client.credential_available()` is false), never attempt a live read — a real write yields a graceful `validation_error` at SUCCESS; a `dry_run` skips the read and previews. | `downgrade_verdict`, `downgrade_diff`, `current_protection` |
| **main** | BranchProtectionWriteNode | apply protection via GitHub API **only if both gates PASS and no validation_error**; `dry_run` returns projected rules without writing. **Fail-closed:** a real write with no credential returns a safe plan-only `no_credential` result at SUCCESS (zero HTTP). | `write_result`, `status` |
| post_process | PostProcessNode | bilingual (EN/JA) confirmation, dry-run indicator, rejection reason; S-3 output gate | `confirmation_report`, `formatted_output` |
| finalize | FinalizeNode (framework) | response_metadata, total_time_ms | — |

### Data Flow

```
START → initialize → pre_process → baseline_check → downgrade_prevention → main → {route} → post_process → finalize → END
                                                                                    ↓ (RETRY, max 3)
                                                                                 pre_process
```

`add_edges()` is overridden to insert `baseline_check` and `downgrade_prevention`
between `pre_process` and `main`; the standard `add_conditional_edges("main", self.route)`
and `post_process → finalize → END` tail is preserved.

### Gate short-circuit (no conditional-edge sprawl)

Each gate writes a verdict field; downstream nodes check it and no-op — the pattern
proven in the sibling (internal reference removed). If `pre_process` sets a non-empty `validation_error`,
or `baseline_check` / `downgrade_prevention` sets a `REFUSED` verdict, the `main`
writer performs **no** API call and `post_process` renders the refusal. Every path
ends `status = success` (a refusal is a valid business outcome, not an execution error).

## State Schema (`src/schemas/state.py`)

Flat `State(AgentState)`; all complex objects are JSON-serialized `str` (msgpack-safe):

| Field | Type | Owner | Notes |
|---|---|---|---|
| `parsed_rules` | `str` | pre_process | JSON: `{require_approvals, require_status_checks, prevent_force_push, enforce_admins, ...}` |
| `target_context` | `str` | pre_process | JSON: `{owner, repo, branch, dry_run}` |
| `validation_error` | `str` | pre_process | non-empty → downstream short-circuits |
| `baseline_verdict` | `str` | baseline_check | `PASS` / `REFUSED` |
| `baseline_reason` | `str` | baseline_check | human-readable refusal reason |
| `current_protection` | `str` | downgrade_prevention | JSON of current branch protection (or the JSON literal `"null"` if none) |
| `downgrade_verdict` | `str` | downgrade_prevention | `PASS` / `REFUSED` |
| `downgrade_diff` | `str` | downgrade_prevention | JSON of weakened dimensions |
| `write_result` | `str` | main | JSON: `{applied, dry_run, rules}` |
| `confirmation_report` | `str` | post_process | final Markdown report |
| `formatted_output` | `str` | post_process | inherited from `AgentState`; carries the final report; surfaced by `get_output()` to `invoke()` (the outer graph does not override `get_output`) |
| `output_language` | `str` | pre_process | `en` / `ja` / `bilingual` (default `en`) |

**No credential, token, or raw request payload is ever stored in State.** The GitHub
token is retrieved at call time from the bound secret provider and never persisted.

## Services (`src/services/`)

- **`input_parser_service.py` — `InputParserService`** (stateless): `parse(text, default_branch="main") -> dict` → structured rules + `{owner, repo, branch}`; raises `InputParseError` on unrecognizable input.
- **`security_baseline_service.py` — `SecurityBaselineService`**: constructed from `config.security_baseline` (default: `require_approvals >= 1`, `prevent_force_push = true`); `check(requested_rules) -> (ok: bool, reason: str)`.
- **`github_client.py` — `GitHubClient`**: `get_branch_protection(owner, repo, branch) -> dict | None`, `set_branch_protection(owner, repo, branch, payload) -> dict`. Token via `current_secrets().require("GITHUB_TOKEN")` (never state/env). **S-3 egress guard: only `api.github.com` host permitted.**

Services are constructor-injected at `Graph.__init__` / `register_nodes()` time — never instantiated inside `execute()`.

## 5-Layer Security Mapping

| Layer | Placement |
|---|---|
| **S-1** Trust | `required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL` on every node (branch-protection write is security-sensitive). |
| **S-2** Input | Framework `@final _security_gate_input` (PII scan) runs automatically; `PreProcessNode._extra_security_gate_input()` adds repo/branch-name sanitization (no path traversal, size cap). Bad input → `status=SUCCESS` + non-empty `validation_error` (never raises), backbone short-circuits to a refusal report. |
| **S-3** Output | `PostProcessNode._extra_security_gate_output()` scrubs any residual token/credential from the report. **Egress isolation is enforced at the `GitHubClient` (only `api.github.com`), NOT at the Graph class** — verified on wheel: `AgentBaseGraph._extra_security_gate_output` does not exist, so a graph-level gate would be dead code. Impl issue #11's "graph-level S-3 egress scan" is therefore realized as node/client-level guards. |
| **S-4** Audit | `emit_trace_event(event, payload, state)` from `shared.utils.audit_logger`; ≥1 domain event per node (`scope_parsed`, `baseline_checked`, `downgrade_checked`, `protection_applied`/`protection_skipped`, `report_compiled`). FISC audit fields (repo, branch, rules applied, verdicts) are in the report. Never `node_start`/`node_complete`/`node_error`. |
| **S-5** Downgrade prevention | `DowngradePreventionNode` — refuses any write that weakens the branch's current protection; **novel gate flagged for CoE pre-review** (architect note 2026-07-06). `dry_run` provides a lockout-safe preview. |

## Config surface (`config/agent.yaml`)

```yaml
config:
  max_retry: 3
  timeout_seconds: 30
  github_org: ""                 # optional default org for repo resolution
  security_baseline:
    require_approvals: 1
    prevent_force_push: true
    require_status_checks: true
    enforce_admins: false
requires:
  secrets: ["GITHUB_TOKEN"]      # retrieved via current_secrets().require()
```

## Testing (summary — full spec in docs/03)

- Unit: each node (mocked services/client) + each service. Baseline refusal, downgrade refusal, dry-run, no-current-protection allow-path all covered with concrete asserts.
- Integration: full `invoke()` with a mocked `GitHubClient` (valid write, baseline refusal, downgrade refusal).
- Proof-of-Boundary: import isolation, state safety (no token in checkpoint), invoke order.
