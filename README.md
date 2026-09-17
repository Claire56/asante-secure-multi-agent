# Asante Secure Multi-Agent Application

A production-style learning application for secure AI-agent operations at Asante Stays.

The project is deliberately split into two layers:

- **Application/runtime:** OpenAI Agents SDK, Asante workflows, tools, API, telemetry, evals.
- **Authorization boundary:** Ruhusa 0.8.0 for deterministic policy, trusted invocation provenance, tool identity, and execution fencing.

## Phase 1 vertical slice

The first workflow is guest service recovery:

```text
Operator
  -> Asante Operations Supervisor
  -> Guest Support Agent
  -> guest credit tool
  -> trusted invocation record
  -> Ruhusa authorization
  -> execution claim
  -> execution-time revalidation
  -> mock credit ledger
  -> execution completion
```

Current credit policy:

- $0 < credit <= $25: **ALLOW**
- $25 < credit <= $100: **REQUIRE_APPROVAL**
- credit > $100: **DENY** by default

Phase 1 intentionally uses an in-memory fake external ledger. It lets us prove the authorization and execution lifecycle before connecting a real property-management or payment system.

## Run locally

Requires Python 3.12+ and `uv`.

```bash
uv sync
cp .env.example .env
export OPENAI_API_KEY="..."
uv run pytest
uv run uvicorn asante_secure_multi_agent.main:app --reload
```

Then try:

```bash
curl -X POST http://127.0.0.1:8000/agent/run \
  -H 'content-type: application/json' \
  -d '{"message":"Guest R-1001 had a Wi-Fi outage. Issue a $20 service-recovery credit."}'
```

## Roadmap

1. Prove secure tool execution with Ruhusa.
2. Add real supervisor -> specialist delegation grants.
3. Move tool surface to MCP.
4. Add authenticated operator/workload identity.
5. Add OpenTelemetry traces and security metrics.
6. Add agent evals and authorization attack tests to CI.
7. Add durable human approval workflow.
8. Replace in-memory stores with production backends.
