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
6. Add agent evals and authorization attack tests to CI.
7. Add durable human approval workflow.
8. Replace in-memory stores with production backends/shared task state.
9. Split MCP/agent workloads and replace static SPIFFE assignment with SPIRE/SVID verification.
