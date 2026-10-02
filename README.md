# Asante Secure Multi-Agent Application

A production-style reference application for **secure agentic operations** at Asante Stays.
It demonstrates how an LLM can propose actions without becoming the source of identity,
authority, or execution trust.

> **Core principle:** the model proposes; trusted runtime identity and delegation establish
> authority; Ruhusa independently authorizes; execution is revalidated; telemetry and evals
> prove what happened.

## What this project demonstrates

- **Human authentication:** OAuth-style Bearer JWT access tokens.
- **Workload identity:** trusted SPIFFE IDs for Supervisor and Guest Support.
- **Delegated authorization:** task-bound, scope-attenuated authority through Ruhusa 0.8.0.
- **Agent orchestration:** OpenAI Agents SDK Supervisor -> Guest Support handoff.
- **Agent tool protocol:** MCP over Streamable HTTP with authority hidden from model-visible schemas.
- **Execution security:** trusted invocation provenance, execution fencing, revocation, and revalidation.
- **Observability:** OpenTelemetry traces/metrics plus an OpenAI Agents tracing bridge.
- **Reliability:** bounded known-safe retries, server-derived idempotency, and fail-closed unknown outcomes.
- **Authorization-aware caching:** cached reservation reads never bypass live authorization.
- **Release safety:** deterministic authorization, attack, reliability, disclosure, and agent-contract evals.
- **Property operations:** maintenance work orders, guest messaging, and durable human approval for larger service-recovery credits.

## Architecture

```text
                         Authenticated Human
                                |
                         OAuth Access Token
                                |
                                v
                      Operations Supervisor
                                |
                       delegated authority
                                v
                       Guest Support Agent
                                |
                                v
                       MCP Tool Boundary
                         /             \
                        /               \
             get_reservation       issue_guest_credit
                    |                     |
                    v                     v
                 Ruhusa                Ruhusa
              authorization         authorization
                    |                     |
              revalidation            revalidation
                    |                     |
                    v                     v
          Authorization-Aware       Idempotency +
                 Cache              Bounded Retry
                    |                     |
                    v                     v
            Reservation Provider    Credit Provider
                         \             /
                          \           /
                           OpenTelemetry
                                |
                       deterministic evals
                                |
                           CI release gate
```

## Security invariants

The project treats these as release properties rather than informal expectations:

1. **Agent handoff is not authority delegation.** A specialist receives only authority explicitly delegated through the trusted chain.
2. **Model-visible MCP arguments cannot assert identity or grants.** Task, principal, grant, and cache authority stay server-side.
3. **Ruhusa is checked immediately before protected execution or disclosure.** A stale plan cannot bypass revocation.
4. **Denied or approval-required credit actions produce zero side effects.**
5. **Unknown execution outcomes are never blindly retried.**
6. **A cache hit may save an external read, but it may never save the authorization check.**
7. **Unauthorized cached-data disclosure is a release-blocking failure.**

## API documentation

When running locally, the application publishes three complementary interfaces:

| Interface | URL | Purpose |
| --- | --- | --- |
| Swagger UI | `http://127.0.0.1:8000/docs` | Interactive authenticated testing |
| ReDoc | `http://127.0.0.1:8000/redoc` | Readable API contract/reference |
| OpenAPI | `http://127.0.0.1:8000/openapi.json` | Machine-readable API specification |

The operator-facing API is intentionally small:

| Endpoint | Auth | Purpose |
| --- | --- | --- |
| `GET /` | No | Service discovery and architecture metadata |
| `GET /health` | No | Liveness probe |
| `GET /auth/whoami` | Bearer | Show the canonical authenticated human principal |
| `POST /agent/run` | Bearer | Run Supervisor -> Guest Support -> MCP -> Ruhusa |
| `GET /demo/credits` | Bearer | Inspect credits that actually reached the demo side effect |
| `POST /demo/credits` | Bearer | Exercise the secured credit path without the LLM/MCP layer |
| `GET /demo/reservations/{reservation_id}` | Bearer | Exercise Ruhusa + authorization-aware cache directly |
| `GET /operations/work-orders` | Bearer | Maintenance work orders created by the agent |
| `GET /operations/messages` | Bearer | Outbound guest messages sent by the agent |
| `GET /operations/approvals` | Bearer | Durable human approval inbox |
| `POST /operations/approvals/{approval_id}/approve` | Bearer + `asante:approve` | Approve and execute a pending credit |
| `POST /operations/approvals/{approval_id}/deny` | Bearer + `asante:approve` | Deny a pending credit; nothing executes |
| `/mcp/` | Protocol endpoint | Streamable HTTP MCP transport; not a normal REST resource |

Ruhusa authorization denials are represented as domain outcomes such as `status=blocked`.
HTTP `401` is reserved for missing, invalid, or expired Bearer credentials. The approval
endpoints additionally return `403` without `asante:approve`, `404` for an unknown approval,
and `409` for an invalid state transition.

## Release gate

CI is designed to fail closed. The deterministic gate requires:

```text
minimum pass rate                = 100%
maximum critical failures       = 0
maximum unauthorized side effects = 0
maximum unauthorized disclosures  = 0
```

Run the same checks locally:

```bash
uv run ruff format .
uv run ruff check .
uv run pytest
uv run python -m asante_secure_multi_agent.evals --output eval-report.json
```

## Development journey

The sections below preserve the implementation history and the security property introduced
at each phase. The architecture above describes the system as it exists today.

## Phase 8 product slice: property operations + human approval

Phase 8 moves the project from a secure-agent reference flow toward the real
Asante Stays operating backend. Guest Support can now verify a reservation, create
a maintenance work order, send an operational guest update, issue a small service
credit, or request durable human approval for a larger credit.

```text
Guest / operator issue
  -> Operations Supervisor
  -> Guest Support
  -> get_reservation
  -> create_maintenance_request
  -> send_guest_message
  -> service recovery
       -> <= $25: issue_guest_credit
       -> $25-$100: request_guest_credit -> human approval inbox
       -> > $100: deny / escalate
```

The approval path deliberately separates **authority to request** a credit from
**authority to execute** it. The model can create a pending approval request but
cannot mark it approved or invoke the approved-credit executor.

Approval and denial endpoints additionally require the validated human token to
contain the `asante:approve` scope, so the operator who requests work does not
automatically gain manager approval authority.

```text
Agent
  -> MCP request_guest_credit
  -> Ruhusa guest.credit.request
  -> SQLite approval record (pending)

Authenticated human
  -> POST /operations/approvals/{id}/approve
  -> durable approval decision
  -> trusted approval-executor workload
  -> Ruhusa guest.credit.issue.approved
  -> idempotent credit provider write
```

A denial never executes the credit. Repeating an approved execution is
idempotent, and the approval record survives process restarts when the configured
SQLite path is persistent.

### Operations dashboard endpoints

```text
GET  /operations/work-orders
GET  /operations/messages
GET  /operations/approvals
POST /operations/approvals/{approval_id}/approve
POST /operations/approvals/{approval_id}/deny
```

For local development, approval state defaults to `.asante/approvals.db` and can
be moved with `ASANTE_APPROVAL_DB_PATH`. Maintenance and message providers remain
in memory until the production-backend roadmap item.

### New MCP tools

```text
create_maintenance_request(reservation_id, category, urgency, description)
send_guest_message(reservation_id, message)
request_guest_credit(reservation_id, amount, reason)
```

As with the earlier MCP boundary, task IDs, principals, delegation chains, grant
IDs, and approval-verification flags are never model-visible tool arguments.

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

Create a local environment file, replace `OPENAI_API_KEY=replace-me`, and load
the file into the shell that starts the API:

```bash
cp .env.example .env
set -a
source .env
set +a
uv sync
export ASANTE_OTEL_EXPORTER=console
uv run pytest
uv run uvicorn asante_secure_multi_agent.main:app --reload
```

In a second terminal, load the same environment file before creating a
development access token:

```bash
set -a
source .env
set +a
TOKEN=$(uv run python -m asante_secure_multi_agent.identity.dev_token claire)
printf '%s\n' "$TOKEN"
```

For the human approval endpoints, create a manager token with explicit approval
authority (in the same terminal, after loading `.env`):

```bash
MANAGER_TOKEN=$(uv run python -m asante_secure_multi_agent.identity.dev_token manager \
  --scope "asante:operate asante:approve")
printf '%s\n' "$MANAGER_TOKEN"
```

The API and token generator must use the same `ASANTE_DEV_JWT_SECRET`, issuer,
and audience. The token command does not load `.env` automatically. Development
tokens expire after 30 minutes, so generate a new one after expiration.

## Test with FastAPI Swagger

Open `http://127.0.0.1:8000/docs`, click **Authorize**, and paste only the token
value without the `Bearer` prefix. Start with `GET /auth/whoami`; a `200`
response confirms that authentication is configured correctly. A `401` with
`Invalid or expired access token` usually means the token expired or it was
generated with different JWT settings than the running API.

The `POST /agent/run` schema intentionally contains only a natural-language
`message`. Use this reservation lookup example:

```json
{
  "message": "Look up reservation R-3001 and summarize its status."
}
```

Use this example for an allowed credit:

```json
{
  "message": "Issue a $20 credit to reservation R-3001 because of a Wi-Fi outage."
}
```

Use this example to confirm that delegated authority is enforced:

```json
{
  "message": "Issue a $40 credit to reservation R-3001 because of an extended Wi-Fi outage."
}
```

The `$20` credit should be issued. The `$40` credit is above the Guest Support
agent's `$25` direct limit, so the agent should request human approval instead:
`GET /operations/approvals` shows a `pending` request and no credit is issued.
A successful agent response also includes the Ruhusa task ID and an
OpenTelemetry trace ID.

To test the full Phase 8 workflow, send:

```json
{
  "message": "Guest R-3001 says there has been no hot water for two hours. Verify the reservation, create an urgent maintenance request, send the guest an update, and request a $75 service-recovery credit."
}
```

Then check `GET /operations/work-orders`, `GET /operations/messages`, and
`GET /operations/approvals`: you should see an open work order, a sent message,
and a pending `$75` approval, but no `$75` entry in `GET /demo/credits`.
Re-authorize with `MANAGER_TOKEN` and call
`POST /operations/approvals/{approval_id}/approve` with
`{"note": "Approved after reviewing the outage duration."}`. Only then does the
credit appear in `GET /demo/credits`.

To test authorization without making an OpenAI request, use
`POST /demo/credits` with:

```json
{
  "reservation_id": "R-3001",
  "amount": 20,
  "reason": "Wi-Fi outage"
}
```

To test authorization-aware caching, call
`GET /demo/reservations/R-3001` twice. The first response should contain
`"cache": "miss"` and the second should contain `"cache": "hit"`.

The normal learning cases remain:

- `$20` credit -> allowed and executed;
- `$40` credit -> above the `$25` direct limit, so it becomes a pending approval request;
- `$150` credit -> above the `$100` approval ceiling, so it is denied outright;
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
8. ~~Add durable human approval workflow plus maintenance and guest messaging.~~
9. Replace in-memory stores with production backends/shared task state.
10. Replace the in-memory cache with Redis while preserving the same authorization-before-cache invariant.
11. Split MCP/agent workloads and replace static SPIFFE assignment with SPIRE/SVID verification.
