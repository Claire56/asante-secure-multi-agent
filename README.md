# Asante Secure Multi-Agent Application

A production-style learning application for secure AI-agent operations at Asante Stays.

The project is deliberately split into layers:

- **Operator API:** FastAPI.
- **Human authentication:** OAuth-style Bearer JWT access tokens.
- **Agent runtime:** OpenAI Agents SDK.
- **Agent tool protocol:** MCP over Streamable HTTP.
- **Workload identity:** trusted SPIFFE IDs for Supervisor and Guest Support.
- **Authorization boundary:** Ruhusa 0.8.0 for delegated authority, policy, trusted invocation provenance, tool identity, revocation semantics, and execution fencing.
- **Observability:** OpenTelemetry traces and security/execution metrics, plus an OpenAI Agents tracing bridge.
- **Reliability:** bounded known-safe retries, server-derived idempotency, and fail-closed unknown outcomes.
- **Authorization-aware caching:** reservation reads are cached only after live Ruhusa authorization and execution-time revalidation.
- **Release gate:** deterministic authorization, attack, reliability, cache-disclosure, and agent-contract evals in GitHub Actions.

## Phase 7 vertical slice: authorization-aware caching

Phase 7 adds a protected read capability, `get_reservation`, and an in-memory TTL
cache that is deliberately placed **after** Ruhusa authorization and execution-time
revalidation.

```text
Guest Support
  -> MCP get_reservation
  -> trusted task lookup
  -> Ruhusa authorization
  -> Ruhusa revalidation
  -> authorization-aware cache
       -> HIT: return cached reservation
       -> MISS: reservation provider -> cache -> return
```

The central invariant is:

> A cache hit may save an external read, but it may never save the authorization check.

The cache stores reservation data, not Ruhusa `ALLOW` decisions. A revoked grant is
therefore denied before `cache.get()` is reached, even if the requested reservation
is still physically present in cache.

### Capability-specific delegation

Credit and reservation-read authority use separate delegation chains. The credit
chain keeps its `$100 -> $25` numeric attenuation, while the reservation-read chain
contains only `reservation.read`. This avoids applying credit-specific argument
constraints to unrelated read actions.

### Cache-key design

The Phase 7 key is derived from stable resource semantics and a schema version:

```text
reservation-read-v1
reservation.read
reservation:<id>
```

The resulting key is hashed, so raw reservation IDs do not appear in the key. Task
IDs and grant IDs are intentionally excluded because authorization is checked on
every read; including ephemeral IDs would prevent useful cross-request cache hits.
If the representation later becomes tenant-, role-, or user-specific, that security
context must become part of the cache partition/key.

### Cache security evals

The deterministic gate now includes cache cases for:

1. first authorized read -> cache miss;
2. repeated authorized read -> cache hit;
3. different resource -> cache miss;
4. revoked grant after cache population -> deny with no disclosure;
5. cross-task replay -> deny with no disclosure;
6. cache schema-version change -> stale key not reused; and
7. MCP reservation schema -> no task/grant/principal/cache authority exposed to the model.

The release thresholds now include **zero unauthorized disclosures** in addition to
zero unauthorized side effects.

### Local cache test

After authorizing in Swagger, call:

```text
GET /demo/reservations/R-3001
```

The first response should report `"cache": "miss"`; the next authorized call should
report `"cache": "hit"` while still creating a fresh Ruhusa task/delegation and
revalidating authority.

## Phase 6 vertical slice: reliability + eval-gated CI

Phase 6 turns the security/reliability properties from documentation into a
release gate. CI does not need an OpenAI API key: it evaluates deterministic
invariants that must never depend on model behavior.

```text
PR / push
  -> locked dependency sync
  -> ruff format/lint
  -> pytest
  -> deterministic release evals
       -> normal authorization cases
       -> delegation attack cases
       -> MCP authority-boundary checks
       -> idempotency/retry checks
       -> agent safety instruction contracts
  -> PASS only when every gate is green
```

The release thresholds are intentionally strict:

- deterministic pass rate: **100%**;
- critical eval failures: **0**;
- unauthorized side effects: **0**.

Run the same gate locally:

```bash
uv run python -m asante_secure_multi_agent.evals --output eval-report.json
```

The command exits non-zero when the release gate fails, so the same behavior can
block a pull request in GitHub Actions.

### Reliability policy

The protected credit path now distinguishes retry safety:

- `TransientCreditProviderError`: the adapter knows no side effect happened, so
  a small bounded retry budget may be used;
- `UnknownOutcomeCreditProviderError`: execution may have happened, so the
  application does **not** blindly retry and Ruhusa is marked unknown;
- repeated identical logical credits in the same trusted task use a
  server-derived idempotency key and are deduplicated.

The model never supplies the idempotency key. It is derived from trusted task ID,
reservation, action, and amount.

### Deterministic attack/eval catalog

The Phase 6 gate includes cases for:

1. small allowed credit;
2. approval-required action produces no side effect;
3. policy-denied action produces no side effect;
4. delegated-limit bypass attempt;
5. widened child-grant attack;
6. cross-task grant replay;
7. MCP schema authority injection;
8. duplicate logical execution/idempotency;
9. known-safe transient retry;
10. unknown-outcome no-retry behavior; and
11. Supervisor/Guest Support safety-instruction contracts.

A future live-model eval suite can measure model behavior separately. The CI
release gate remains deterministic so a security invariant never becomes a
probabilistic test.

## Phase 5 vertical slice: end-to-end agent observability

Phase 5 adds OpenTelemetry without changing who is trusted or what Ruhusa allows.

```text
HTTP /agent/run
  -> Bearer token verification
  -> human -> Supervisor -> Guest Support delegation
  -> OpenAI Agents workflow / handoff / generation structure
  -> Streamable HTTP MCP
  -> trusted task lookup
  -> Ruhusa admission
  -> Ruhusa execution-time revalidation
  -> protected credit side effect
```

The API returns a `trace_id` on `POST /agent/run`, `POST /demo/credits`, and
`GET /auth/whoami` so an application result can be correlated with its trace.

### What is traced

Phase 5 records structural and security metadata such as:

- authenticated vs rejected identity attempts;
- delegation depth and bounded credit limits;
- Supervisor / Guest Support agent runtime structure;
- MCP tool name and outcome;
- Ruhusa admission and revalidation effects;
- policy ID when one matched;
- protected side-effect outcome; and
- FastAPI request latency/status.

The application intentionally does **not** copy prompts, completions, tool
arguments/results, reservation IDs, Bearer tokens, or human subject IDs into
custom OpenTelemetry span attributes. OpenAI Agents native tracing remains
enabled separately unless you disable it using the Agents SDK configuration.

### OpenAI Agents -> OpenTelemetry bridge

The Agents SDK already traces agent runs, model generations, handoffs and tool
calls. Phase 5 registers an additional tracing processor that mirrors the SDK's
**structure** into the current OpenTelemetry trace. This preserves the native
OpenAI trace destination while giving the application a vendor-neutral SRE
trace that also contains HTTP, MCP, Ruhusa and execution spans.

### MCP trace propagation

The MCP client injects W3C trace context into the Streamable HTTP headers. It
also injects current trace context into hidden MCP `_meta` alongside the trusted
task reference. That metadata is not part of the model-visible tool schema. The
MCP server extracts it before creating the `asante.mcp.issue_guest_credit` span.

### Metrics

Phase 5 emits low-cardinality metrics:

```text
asante.authorization.decisions
asante.authorization.duration
asante.mcp.tool.calls
asante.credit.executions
```

Authorization metrics distinguish admission from execution-time revalidation.
They do not carry operator, reservation or prompt data.

## Exporters

Local development defaults to console output:

```bash
export ASANTE_OTEL_EXPORTER=console
```

To keep instrumentation active without exporting:

```bash
export ASANTE_OTEL_EXPORTER=none
```

To send OTLP/HTTP to an OpenTelemetry Collector or compatible backend:

```bash
export ASANTE_OTEL_EXPORTER=otlp
export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
```

The OpenTelemetry SDK/exporters use the standard `OTEL_EXPORTER_OTLP_*`
environment variables for further OTLP configuration.

## Security chain preserved from Phases 1-4

```text
Authentication
  Who is this human/workload?

Delegation
  What authority was passed to this workload?

MCP
  How does the agent reach the capability?

Authorization
  May this workload perform this exact action now?

Observability
  What happened, where did time go, and which security boundary stopped it?
```

Ruhusa remains the authorization boundary. OpenTelemetry observes decisions; it
does not influence them.

## Run locally

Requires Python 3.12+ and `uv`.

```bash
uv sync
export OPENAI_API_KEY="..."
export ASANTE_AUTH_MODE=dev
export ASANTE_DEV_JWT_SECRET="asante-local-development-only-change-me"
export ASANTE_OTEL_EXPORTER=console
uv run pytest
uv run uvicorn asante_secure_multi_agent.main:app --reload
```

Create a development access token:

```bash
TOKEN=$(uv run python -m asante_secure_multi_agent.identity.dev_token claire)
```

Open Swagger at `http://127.0.0.1:8000/docs`, click **Authorize**, paste the
token, and call `POST /agent/run`. A successful response now includes both the
Ruhusa task ID and an OpenTelemetry trace ID.

The normal learning cases remain:

- `$20` credit -> allowed and executed;
- `$40` credit -> blocked by the `$25` Guest Support delegation;
- `/demo/credits` -> direct authenticated Ruhusa diagnostic path.

## Phase 5 tests

Phase 5 preserves all identity, delegation, MCP and execution regressions and
adds tests for:

1. W3C `traceparent` injection and trace-ID correlation;
2. OpenAI Agents span mirroring into OpenTelemetry;
3. parent/child trace structure between the application and agent runtime; and
4. preventing prompt/tool content from entering custom OTel attributes.

## Roadmap

1. ~~Prove secure tool execution with Ruhusa.~~
2. ~~Add real supervisor -> specialist delegation grants.~~
3. ~~Move the guest-credit tool surface to MCP.~~
4. ~~Add authenticated human identity and trusted workload identity.~~
5. ~~Add OpenTelemetry traces and security metrics.~~
6. ~~Add agent evals and authorization attack tests to CI.~~
7. ~~Add authorization-aware caching with revocation-safe reads.~~
8. Add durable human approval workflow.
9. Replace in-memory stores with production backends/shared task state.
10. Replace the in-memory cache with Redis while preserving the same authorization-before-cache invariant.
11. Split MCP/agent workloads and replace static SPIFFE assignment with SPIRE/SVID verification.
