# Asante Secure Multi-Agent Application

A production-style learning application for secure AI-agent operations at Asante Stays.

The project is deliberately split into layers:

- **Operator API:** FastAPI.
- **Human authentication:** OAuth-style Bearer JWT access tokens.
- **Agent runtime:** OpenAI Agents SDK.
- **Agent tool protocol:** MCP over Streamable HTTP.
- **Workload identity:** trusted SPIFFE IDs for Supervisor and Guest Support.
- **Authorization boundary:** Ruhusa 0.8.0 for delegated authority, policy, trusted invocation provenance, tool identity, revocation semantics, and execution fencing.

## Phase 4 vertical slice: authenticated identity before delegated authority

Phase 4 removes caller-supplied operator identity from request bodies.

```text
Human
  -> Bearer access token
  -> FastAPI validates token
  -> canonical human principal from iss + sub
  -> Ruhusa task root
  -> Supervisor SPIFFE identity
  -> delegated grant
  -> Guest Support SPIFFE identity
  -> MCP issue_guest_credit
  -> trusted task lookup
  -> Ruhusa authorization + execution revalidation
  -> credit ledger
```

The security distinction is now explicit:

```text
Authentication
  Who is this human/workload?

Delegation
  What authority was passed to this workload?

Authorization
  May this workload perform this exact action now?
```

Ruhusa does not become an identity provider. It consumes canonical identities established by trusted application/runtime infrastructure.

## Human identity

Operator-facing protected endpoints use `Authorization: Bearer <access-token>`.

The request body no longer accepts `operator_id`.

The local development verifier validates:

- JWT signature
- access-token type (`at+jwt`)
- issuer (`iss`)
- subject (`sub`)
- audience (`aud`)
- expiry (`exp`)
- issued-at time (`iat`)
- JWT ID (`jti`)
- OAuth client ID (`client_id`)

The canonical Ruhusa root principal is derived from the verified issuer/subject pair:

```text
oauth:https://dev.asante.local#claire
```

This prevents a caller from choosing another user's identity by changing JSON in the request body.

### Local development token

Phase 4 includes a local token generator so the authentication boundary can be exercised without first configuring an external identity provider.

```bash
TOKEN=$(uv run python -m asante_secure_multi_agent.identity.dev_token claire)
echo "$TOKEN"
```

The development token is HS256 and is only for local learning/testing.

### External JWKS mode

The application also supports asymmetric JWT access-token verification against an external JWKS endpoint.

```bash
export ASANTE_AUTH_MODE=jwks
export ASANTE_AUTH_ISSUER="https://your-issuer.example/"
export ASANTE_AUTH_AUDIENCE="asante-secure-multi-agent"
export ASANTE_AUTH_JWKS_URL="https://your-issuer.example/.well-known/jwks.json"
export ASANTE_AUTH_ALGORITHMS="RS256"
```

This mode expects access tokens compatible with the claims enforced by the Phase 4 verifier. Provider-specific claim mappings can be added later if an IdP uses a different token profile.

## Workload identity

The trusted runtime currently assigns these canonical SPIFFE IDs:

```text
spiffe://asante.jamiiz.io/agents/supervisor
spiffe://asante.jamiiz.io/agents/guest-support
```

These IDs replace application labels such as `agent:asante:supervisor` as Ruhusa principals.

The agents and MCP server still run in one process in Phase 4, so this is **trusted SPIFFE-ID assignment, not yet cryptographic SPIFFE attestation**. When those components are deployed as separate workloads, the `WorkloadIdentityProvider` boundary is where SPIRE/SVID retrieval and verification can be introduced without changing the Ruhusa policy model.

## Delegated credit authority

```text
Authenticated Human
  -> Supervisor: guest.credit.issue <= $100
  -> Guest Support: guest.credit.issue <= $25
```

Independent Ruhusa policy remains:

- $0 < credit <= $25: **ALLOW**
- $25 < credit <= $100: **REQUIRE_APPROVAL**
- credit > $100: **DENY** by default

A handoff does not grant authority. MCP access does not grant authority. A valid identity also does not grant authority. Ruhusa still validates the task-bound delegation chain and the exact proposed action.

## MCP boundary

The Guest Support agent reaches business actions through Streamable HTTP MCP:

```text
Model-visible MCP arguments:
  reservation_id
  amount
  reason

Hidden MCP metadata:
  task reference

Trusted server-side state:
  TaskContext
  DelegationGrant chain
  authenticated human root
  workload principal identities
```

The model cannot provide `task_id`, grant objects, human identity, or workload principal IDs as tool arguments.

The canonical MCP URL is:

```text
http://127.0.0.1:8000/mcp/
```

The trailing slash avoids the redirect discovered by the Phase 3 live integration test.

## Development control path

The direct endpoints remain useful for isolating failures:

```text
POST /agent/run
  -> LLM -> MCP -> Ruhusa -> execution

POST /demo/credits
  -> Ruhusa -> execution

GET /demo/credits
  -> inspect executed credits
```

All three now require authenticated human identity.

Use `GET /auth/whoami` to inspect the canonical identity derived from your Bearer token.

## Run locally

Requires Python 3.12+ and `uv`.

```bash
uv sync
export OPENAI_API_KEY="..."
export ASANTE_AUTH_MODE=dev
export ASANTE_DEV_JWT_SECRET="asante-local-development-only-change-me"
uv run pytest
uv run uvicorn asante_secure_multi_agent.main:app --reload
```

Create a development access token:

```bash
TOKEN=$(uv run python -m asante_secure_multi_agent.identity.dev_token claire)
```

Open Swagger:

```text
http://127.0.0.1:8000/docs
```

Click **Authorize** and paste the token.

First verify identity with:

```text
GET /auth/whoami
```

Expected shape:

```json
{
  "principal_id": "oauth:https://dev.asante.local#claire",
  "subject": "claire",
  "issuer": "https://dev.asante.local",
  "audiences": ["asante-secure-multi-agent"],
  "client_id": "asante-local-cli",
  "scopes": ["asante:operate"]
}
```

Then test the full path:

```bash
curl -X POST http://127.0.0.1:8000/agent/run \
  -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"message":"Guest R-1001 had a Wi-Fi outage. Issue a $20 service-recovery credit."}'
```

A $20 credit should execute. A $40 credit should still be blocked because Guest Support has only $25 of delegated authority.

## Phase 4 tests

Phase 4 retains all Phase 1-3 authorization, delegation, MCP, and execution tests and adds identity regressions for:

1. valid access-token identity derivation;
2. wrong-audience rejection;
3. rejection of non-access-token JWT types;
4. removal of `operator_id` from request schemas;
5. canonical SPIFFE workload IDs;
6. authenticated human identity as the delegation root;
7. missing Bearer credential rejection;
8. Bearer credential -> canonical human resolution; and
9. canonical `/mcp/` URL enforcement.

## Roadmap

1. ~~Prove secure tool execution with Ruhusa.~~
2. ~~Add real supervisor -> specialist delegation grants.~~
3. ~~Move the guest-credit tool surface to MCP.~~
4. ~~Add authenticated human identity and trusted workload identity.~~
5. Add OpenTelemetry traces and security metrics.
6. Add agent evals and authorization attack tests to CI.
7. Add durable human approval workflow.
8. Replace in-memory stores with production backends/shared task state.
9. Split MCP/agent workloads and replace static SPIFFE assignment with SPIRE/SVID verification.
