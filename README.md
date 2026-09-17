# Asante Secure Multi-Agent Application

A production-style learning application for secure AI-agent operations at Asante Stays.

The project is deliberately split into two layers:

- **Application/runtime:** OpenAI Agents SDK, Asante workflows, tools, API, telemetry, evals.
- **Authorization boundary:** Ruhusa 0.8.0 for deterministic policy, delegated authority, trusted invocation provenance, tool identity, and execution fencing.

## Phase 2 vertical slice: delegated authority

The guest service-recovery workflow now separates **agent orchestration** from **authorization delegation**:

```text
Operator / Human
  -> task-bound authority
  -> Asante Operations Supervisor
  -> narrower Ruhusa DelegationGrant
  -> Guest Support Agent
  -> guest credit tool
  -> trusted invocation record
  -> Ruhusa delegation + policy authorization
  -> execution claim
  -> execution-time revalidation
  -> mock credit ledger
  -> execution completion
```

The OpenAI Agents SDK handoff answers: **which agent should handle the work?**

Ruhusa answers: **what authority did that agent actually receive?**

A handoff does not automatically transfer permission.

### Default delegated credit authority

```text
Operator
  -> Supervisor: guest.credit.issue <= $100
  -> Guest Support: guest.credit.issue <= $25
```

The child grant must be a subset of the parent grant. Ruhusa validates chain origin, identity continuity, task binding, temporal validity, and scope attenuation before policy evaluation.

### Defense-in-depth policy

The policy layer remains independent of delegation:

- $0 < credit <= $25: **ALLOW**
- $25 < credit <= $100: **REQUIRE_APPROVAL**
- credit > $100: **DENY** by default

The ordinary autonomous Guest Support path only receives $25 of authority. A trusted infrastructure path can issue a broader delegation, but policy still requires human approval above $25.

## Phase 2 security tests

The test suite covers:

1. canonical human -> supervisor -> Guest Support grants are task-bound and registered;
2. a $20 credit succeeds under the default delegation chain;
3. a $40 credit is denied because Guest Support only received $25 of authority;
4. a broader trusted grant still cannot bypass the human-approval policy;
5. a grant above the policy ceiling still receives default deny; and
6. a malicious widened child grant is denied even when the proposed action itself is small.

The sixth case is important: it proves that authorization is about the **validity of the authority chain**, not merely whether the final action looks harmless.

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
  -d '{"message":"Guest R-1001 had a Wi-Fi outage. Issue a $20 service-recovery credit.","operator_id":"user:claire"}'
```

And compare it with a request outside Guest Support's delegated authority:

```bash
curl -X POST http://127.0.0.1:8000/agent/run \
  -H 'content-type: application/json' \
  -d '{"message":"Guest R-1001 had a Wi-Fi outage. Issue a $40 service-recovery credit.","operator_id":"user:claire"}'
```

The model may propose the $40 action, but Ruhusa should deny execution because the default Guest Support grant is capped at $25.

## Roadmap

1. ~~Prove secure tool execution with Ruhusa.~~
2. ~~Add real supervisor -> specialist delegation grants.~~
3. Move tool surface to MCP.
4. Add authenticated operator/workload identity.
5. Add OpenTelemetry traces and security metrics.
6. Add agent evals and authorization attack tests to CI.
7. Add durable human approval workflow.
8. Replace in-memory stores with production backends.
