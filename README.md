# Asante Secure Multi-Agent Application

A production-style learning application for secure AI-agent operations at Asante Stays.

The project is deliberately split into layers:

- **Application/runtime:** FastAPI, OpenAI Agents SDK, Asante workflows.
- **Agent tool protocol:** MCP over Streamable HTTP.
- **Authorization boundary:** Ruhusa 0.8.0 for deterministic policy, delegated authority, trusted invocation provenance, tool identity, and execution fencing.

## Phase 3 vertical slice: MCP behind the agent, Ruhusa behind MCP

Phase 3 moves the guest-credit action from an in-process Agents SDK `function_tool` to a real MCP tool:

```text
Operator / Human
  -> POST /agent/run
  -> Asante Operations Supervisor
  -> Guest Support Agent
  -> Streamable HTTP MCP
  -> issue_guest_credit
  -> trusted server-side task lookup
  -> Ruhusa delegated authorization
  -> execution claim + revalidation
  -> mock credit ledger
```

The key security separation is:

```text
Model-visible MCP arguments:
  reservation_id
  amount
  reason

Hidden MCP _meta:
  task reference

Trusted server-side state:
  TaskContext
  DelegationGrant chain
  principal/tool identity
```

The model never supplies `task_id`, grant objects, principal identity, or the delegation chain as tool arguments. OpenAI's MCP client injects the current task reference in per-call `_meta`; the MCP server resolves the canonical authority objects from `TrustedTaskRegistry` and then calls the existing Ruhusa-secured service.

### Why this matters

MCP answers **how the agent reaches a business capability**.

Ruhusa answers **whether this agent, under this task and delegated authority, may execute this exact side effect**.

Moving a tool behind MCP must not widen authority.

## MCP transport

The application uses Streamable HTTP and mounts the MCP server at:

```text
http://127.0.0.1:8000/mcp
```

`ASANTE_MCP_URL` can override the client URL.

The MCP server currently runs inside the same FastAPI process so Phase 3 can isolate the protocol/trust-boundary learning goal. The task registry is therefore in-memory. A later deployment with a separately scaled MCP service will require shared trusted task state.

## Delegated credit authority

```text
Operator
  -> Supervisor: guest.credit.issue <= $100
  -> Guest Support: guest.credit.issue <= $25
```

The independent policy layer remains:

- $0 < credit <= $25: **ALLOW**
- $25 < credit <= $100: **REQUIRE_APPROVAL**
- credit > $100: **DENY** by default

The ordinary Guest Support path therefore cannot use the policy's approval headroom unless trusted infrastructure explicitly delegates broader authority.

## Development control path

The direct development endpoints remain intentionally useful:

```text
POST /demo/credits
GET  /demo/credits
```

`POST /demo/credits` bypasses the LLM and MCP but **does not bypass Ruhusa**. It lets you distinguish MCP/agent failures from authorization/business-layer failures.

## Phase 3 tests

Phase 2 authorization/delegation tests remain in place. Phase 3 adds checks that:

1. unknown or removed task references fail closed;
2. MCP metadata carries the task reference outside model-visible tool arguments;
3. the MCP tool schema exposes only business arguments;
4. a $20 MCP-routed credit reaches the existing Ruhusa-secured execution path; and
5. a $40 MCP-routed credit is still denied by the $25 delegated authority limit.

## Run locally

Requires Python 3.12+ and `uv`.

```bash
uv sync
cp .env.example .env
export OPENAI_API_KEY="..."
uv run pytest
uv run uvicorn asante_secure_multi_agent.main:app --reload
```

Open:

```text
http://127.0.0.1:8000/docs
```

The MCP endpoint is mounted at:

```text
http://127.0.0.1:8000/mcp
```

Test the full agent -> MCP -> Ruhusa path:

```bash
curl -X POST http://127.0.0.1:8000/agent/run \
  -H 'content-type: application/json' \
  -d '{"message":"Guest R-1001 had a Wi-Fi outage. Issue a $20 service-recovery credit.","operator_id":"user:claire"}'
```

Then try the same flow with `$40`. The model may propose it, but the MCP migration does not change the Ruhusa grant: Guest Support still has only $25 of delegated credit authority.

## Roadmap

1. ~~Prove secure tool execution with Ruhusa.~~
2. ~~Add real supervisor -> specialist delegation grants.~~
3. ~~Move the guest-credit tool surface to MCP.~~
4. Add authenticated operator/workload identity.
5. Add OpenTelemetry traces and security metrics.
6. Add agent evals and authorization attack tests to CI.
7. Add durable human approval workflow.
8. Replace in-memory stores with production backends/shared task state.
