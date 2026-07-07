# aauth-go

A Go implementation of the **AAuth protocol** —
[draft-hardt-oauth-aauth-protocol](https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/)
(tracking **-09**, 2026-07-04) — giving AI agents their own cryptographic
identity and a clean authorization model across trust domains: no shared
secrets, no per-server pre-registration.

To our knowledge, **the first Go implementation** of the protocol (the
draft's §17 Implementation Status lists TypeScript, .NET, Python, Java).

Companion specs implemented against:
[draft-hardt-httpbis-signature-key-04](https://datatracker.ietf.org/doc/draft-hardt-httpbis-signature-key/)
· [draft-hardt-aauth-bootstrap-01](https://datatracker.ietf.org/doc/draft-hardt-aauth-bootstrap/)
· protocol explorer: [explorer.aauth.dev](https://explorer.aauth.dev/)

## Quick start

```go
id, _ := aauth.ParseAgentIdentifier("aauth:claude-code@devbox.local")
agent, _ := aauth.NewAgent(id, aauth.WithPersonServer("http://127.0.0.1:7421"))

ps := aauth.NewPSClient("http://127.0.0.1:7421", agent)
res, err := ps.RequestPermission(ctx, aauth.PermissionRequest{
    Action:      "WriteFile",
    Description: "write the deploy config",
    Parameters:  map[string]any{"path": "/tmp/deploy.yaml"},
})
// res.Granted() — or res.Reason explains the denial.
// A 202 deferred response (a human deciding) is followed automatically.
```

Server side — a Person Server or resource authenticating an agent:

```go
claims, err := aauth.VerifyAndExtractAgent(ctx, req, aauth.VerifyAgentTokenOptions{
    Resolver: aauth.SelfSignedResolver{}, // or JWKSResolver / StaticResolver
})
```

## Coverage

AAuth involves four participants — an **Agent** making signed requests, a
**Resource** (the protected API), a **Person Server** representing the user,
and an **Access Server** enforcing access policy — and stacks three layers:
proving *who the agent is*, deciding *what it may access*, and optionally
governing *what it is doing and why* (missions). The tables below track how
much of each this library implements. For an interactive walkthrough of the
protocol itself, see [explorer.aauth.dev](https://explorer.aauth.dev/).

✅ implemented (tested) · 🟡 partial · ⬜ planned · ⛔ not planned yet

### The four participants

What role can aauth-go play for you today?

| Role | Status | What exists |
|---|---|---|
| **Agent** — makes signed requests, holds keys, proposes missions | 🟡 | identity, token minting, signed requests, permission client, challenge verification + token exchange with deferred flow; auto-retrying transport and token cache pending |
| **Resource** — protected API; issues resource tokens, verifies auth | 🟡 | agent authentication, resource-token issuing + 401 challenge (`ChallengeAuthToken`), auth-token verification (`VerifyAndExtractAuth`); `AAuth-Access` two-party flow pending |
| **Person Server** — represents the user; manages missions, federates to AS | 🟡 | permission-endpoint shapes, agent + resource-token verification for the token endpoint; interaction endpoint, missions pending |
| **Access Server** — issues auth tokens; enforces resource access policy | ⬜ | |

### Layer 1 — Identity

How an agent cryptographically proves who it is on every request.

| Capability | Status |
|---|---|
| Agent identifiers (`aauth:name@domain`; sub-agents `name+worker@domain`, single-level rule) | ✅ |
| Agent tokens — `sig=jwt` (-09 claim set: `iss dwk sub jti cnf iat exp ps parent_agent`, `kid` header) | ✅ |
| Self-hosted agents (agent as its own AP, bootstrap §4.3) | ✅ |
| Agent token verification (§5.2.4) — pluggable trust: JWKS discovery / pinned keys / self-signed | ✅ |
| HTTP Message Signatures profile (`@method @authority @path signature-key`, + `content-digest`) | ✅ |
| Signature-Key scheme `jwt` | ✅ |
| Pseudonymous signing (`hwk`) · key delegation (`jkt-jwt`) · `jwks_uri` scheme | ⬜ |
| Signature-Key scheme `x509` | ⛔ |
| AP-issued tokens — two-key model (root signs, ephemeral `cnf.jwk`) | ⬜ |
| Error model (`Signature-Error` header, error codes) | ⬜ |

### Layer 2 — Resource access

How a protected API decides what the agent may do.

| Access mode | Status |
|---|---|
| Identity-Based (agent token + resource's own policy) | 🟡 |
| Resource-Managed (two-party; `AAuth-Access` opaque tokens) | ⬜ |
| PS-Asserted (three-party; challenge → PS token exchange → auth token) | ✅ |
| Federated (four-party; Access Server) | ⬜ |
| Resource tokens (`aa-resource+jwt`): issue, recipient verification (§6.7.2), agent-side challenge verification (§6.7.3) | ✅ |
| Auth tokens (`aa-auth+jwt`): -09 claim set, verification incl. cnf request binding (§9.4) | ✅ |
| `AAuth-Requirement` header: build/parse (`auth-token`, `interaction`, …) | ✅ |
| Rich Resource Requests (R3) — vocabulary access, conditional ops, content addressing | ⛔ |

### Layer 3 — Mission (optional governance)

The agent proposes; the Person Server approves, scopes, and threads context.

| Capability | Status |
|---|---|
| Permission Endpoint (§7.4) — works with or without a mission | ✅ |
| Deferred responses (202 / `Location` / `Retry-After` / `Prefer: wait`, 429 backoff) | ✅ |
| Mission reference (`approver` + `s256`) in requests | ✅ |
| Proposal & approval · mission-scoped access · out-of-bounds · completion · lifecycle | ⬜ |
| Audit endpoint (§7.5) | ⬜ |
| Call chaining (delegation across resources) | ⬜ |
| Clarification chat · interaction chaining | ⬜ |
| User delegation (deferred auth semantics beyond the 202 machinery) | ⬜ |
| Interaction codes (Crockford base32, canonicalization) — `interactioncode/` | ✅ |
| Metadata documents + JWKS discovery (`{iss}/.well-known/{dwk}`) | ✅ |

## Details on the partials and choices

- **Identity-Based access 🟡** — the server side is complete
  (`VerifyAndExtractAgent`: Signature-Key parse → token verify → HTTP
  signature verify against `cnf.jwk`). The client side today is the signed
  permission call; a protocol-aware `http.RoundTripper` that handles 401
  `AAuth-Requirement` challenges and token caching is the next major piece.
- **Permission Endpoint ✅ (usable without missions)** — request/response
  shapes per §7.4 (`action`/`description`/`parameters`/optional `mission`),
  denial as `{"permission":"denied","reason":…}`, deferred (202) flow
  followed automatically by `PSClient.RequestPermission`. `MissionRef`
  (`approver` + `s256`) is in place; the mission lifecycle itself is not.
- **Deferred responses ✅ vs user-delegation semantics ⬜** — the 202 state
  machine (`DoDeferred`) is fully implemented and tested (429 linear
  backoff, same-origin pending-URL enforcement); the longer-window consent
  bookkeeping built on top of it is not yet.
- **Verification trust is pluggable** — `KeyResolver` implementations:
  `JWKSResolver` (public discovery chain), `StaticResolver` (pinned keys for
  offline/air-gapped deployments), `SelfSignedResolver` (local agents,
  trust-on-`cnf.jwk`). Strict `RequireProviderClaims` mode enforces §5.2.4
  (`iss` HTTPS URL, `dwk`, `jti`) for cross-domain interop.
- **Sub-agents** — `aauth:name+worker@domain` identifiers, `parent_agent`
  claim, single-level rule, and minting are implemented; PS-side enforcement
  of "the parent requests on behalf" is exposed as a policy hook
  (`IsSubAgent()`, `ErrSubAgentDirect`) rather than hard-coded.
- **The 9421 + Signature-Key layer is isolated in `httpsig.go`** — the
  reference implementations externalize this layer; keeping it contained
  means a signature-key draft bump stays contained too.
- **R3 ⛔** — experimental in-spec; revisit when it stabilizes.
- Planned package evolution mirrors the reference TS monorepo: `agent/`
  (protocol-aware client transport), `server/` (challenge builders,
  interaction manager), `keys/` (two-key minting, hardware backends), with
  the root package staying the stable protocol vocabulary.

## Testing

```bash
go test ./...
```

Unit + end-to-end tests cover: token round-trips (incl. wrong-`typ` and
missing-claim rejection), tampered-`@path` and swapped-`Signature-Key`
rejection, sub-agent rules, JWKS discovery against a live test server, and
the full deferred (202) permission flow. Golden wire vectors as a
cross-implementation conformance suite: planned.

## License

[MIT](LICENSE) — matching the reference AAuth implementations.
