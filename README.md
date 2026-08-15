# `dev.mcpg.identity.aauth` — AAuth agent identity

Resolves cryptographic AI-agent identity from AAuth-signed inbound requests and
maps the stable agent principal `aauth:local@domain` into the MCPG gateway
identity context. It replaces API keys / OAuth Dynamic Client Registration with
**per-request, self-sovereign, proof-of-possession** agent identity.

- **Protocol:** AAuth (`draft-hardt-oauth-aauth-protocol-10`) + HTTP Signature
  Keys (`draft-hardt-httpbis-signature-key-08`), RFC 9421 HTTP Message
  Signatures.
- **Class:** `identity_provider` · **Runtime:** `native-cdylib-v1` · **License:** Apache-2.0
- **Scope:** AAuth **Pattern A** (rung 1, identity-based) — the gateway acts as a
  *Resource* and verifies inbound agent identity. Southbound signing (the gateway
  as an *Agent*), sub-agents, AAuth Events, and the Person/Access-Server flows
  (rungs 2–4) are out of scope for an identity resolver.

## What it verifies (per request)

1. Parses `Signature-Input` / `Signature` / `Signature-Key` and enforces the
   covered components `@method @authority @path signature-key` and the `created`
   window (default ±60s).
2. Extracts the `aa-agent+jwt` agent token from the `Signature-Key` `jwt` scheme.
3. Checks `typ`/`alg`/`dwk`; verifies the token against the issuing Agent
   Provider's **published JWKS** — fetched from
   `{iss}/.well-known/aauth-agent.json` → `jwks_uri`, with the document's
   `issuer` asserted to equal `iss` (host-poisoning defense), cached, and
   SSRF-egress-admitted. The `alg` gate runs *before* the fetch, so a token
   signed with an algorithm we can never accept never drives outbound traffic.
4. Enforces the **proof-of-possession binding**: the request's RFC 9421
   signature must verify under the token's `cnf.jwk`.
5. On success, resolves identity: `subject_id = sub` (e.g.
   `aauth:k7q3p9n2@ap.example`), `issuer = iss`, `trust_level = verified`, with
   `ps` / `parent_agent` / `jti` recorded as attributes.

An unauthenticated caller (no signature headers) resolves to *no identity* so
other resolvers / anonymous handling apply. A presented-but-invalid credential
resolves to *invalid* (the gateway does not grant identity).

## Security posture

- **Fail-closed trust policy.** `trusted_issuers` is an allow-list of Agent
  Providers; an empty list without `allow_any_issuer` refuses to load.
- **SSRF egress admission** on every metadata/JWKS fetch: HTTPS only, no
  redirects, private/loopback/link-local/CGNAT/reserved IPs blocked, the resolved
  address pinned (anti-rebinding), body (64 KiB) and time (10 s) capped.
- **JWKS cache**: ≥1 fetch/min floor, ≤24h ceiling, refresh-on-unknown-kid with a
  single retry, keyed by `(iss, dwk)`.
- **Cross-origin JWKS** rejected unless the host is in `jwks.cross_origin_hosts`.
- **Fully-specified algorithms only** — see below. `dwk` is pinned to
  `aauth-agent.json` before any fetch (no path injection).

## Algorithms

`draft-hardt-oauth-aauth-protocol-10` §5.2.2 requires a *fully-specified*
algorithm identifier on the agent token and states that implementations **MUST
NOT** accept `none`, the polymorphic `EdDSA` identifier, or any symmetric
algorithm; `draft-hardt-httpbis-signature-key-08` §3.3 repeats the `EdDSA` ban.
This plugin implements that literally:

| Where | Rule |
| --- | --- |
| `aa-agent+jwt` header `alg` | `Ed25519` accepted. `EdDSA`, `none`, `HS*`, `RS*`, `ES*`, `PS*` rejected as `unsupported_algorithm`. `Ed448` is spec-valid but has no backend here — rejected with a message that says exactly that. |
| Token `cnf.jwk` | MUST carry `alg` (§5.2.2). Absent, polymorphic `EdDSA`, or any non-`Ed25519` value is rejected. |
| `Signature-Key` `hwk` member | `alg` is **REQUIRED** and must be fully specified (signature-key-08 §3.4). Members without it — the shape earlier drafts mandated — are now rejected. |
| `Signature-Input` `alg` | Optional per RFC 9421; when present it must be `ed25519` (the HTTP Signature Algorithms registry name, distinct from the JOSE `Ed25519`). |
| AP's published JWKS keys | `alg` is *not* required, so key discovery keeps working against APs whose documents omit it. `kty`/`crv` already pin the curve, and the token's own header `alg` is gated. |

There is deliberately **no configuration flag to re-admit `EdDSA`**: the drafts
say MUST NOT, and a toggle would just be a switch that makes the gateway
non-compliant. An Agent Provider still emitting the polymorphic identifier will
be refused with `unsupported_algorithm` until it is updated — that rejection is
intended, not a regression.

Southbound, everything this crate signs or serialises is fully specified too:
JWTs carry `alg: Ed25519`, minted JWKs (including the embedded `cnf.jwk`) carry
`alg`, and the `hwk` serialiser emits an `alg` parameter.

## Configuration

```yaml
plugins:
  - id: dev.mcpg.identity.aauth
    source: { oci: "…/identity-aauth" }
    config:
      # Agent-Provider issuers this gateway trusts (exact `iss` match).
      trusted_issuers:
        - https://ap.example
      # signature_window_secs: 60          # ±created window (needs NTP sync)
      # expected_authority: mcpg.example   # pin @authority if a proxy rewrites Host
      # additional_covered_components:     # require beyond @method/@authority/@path/signature-key
      #   - "@query"
      #   - content-digest
      # jwks:
      #   cross_origin_hosts: []           # allow-list JWKS hosts != issuer host
      #   refresh_floor_secs: 60
      #   max_ttl_secs: 86400
      #   fetch_timeout_secs: 10
      #   max_response_bytes: 65536
      # resolution:
      #   trust_level: verified            # verified | header_asserted
      #   auth_provider_label: aauth
      # insecure_dev_mode: false           # DEV ONLY: allow http + private IPs
```

There is no algorithm knob: the accepted set is fixed by the drafts (see
[Algorithms](#algorithms)), and `insecure_dev_mode` relaxes only URL
admission (`http://`, private IPs) — never the `alg` rules.

The plugin requires the `network_outbound` capability (metadata + JWKS
discovery). Preserve `Host` and the request path at every proxy hop — the
signature covers `@authority` and `@path`; rewriting either (or stripping
`Signature-*`) breaks verification. Use `expected_authority` when a
TLS-terminating proxy rewrites `Host`.

## Scope & limitations

- **Binds the request envelope, not the body.** Rung-1 identity binds
  `@method`/`@authority`/`@path` (and, if the agent covers them,
  `@query`/`content-digest`) plus the agent identity. It does **not** bind the
  MCP request *body* — an identity resolver has no body access. For full
  operation integrity on state-changing calls, require `content-digest` via
  `additional_covered_components` **and** verify that covered digest against the
  received body at the gateway/backend (outside this plugin). Within the
  `signature_window_secs` window an unbound body can otherwise be substituted on
  a trusted internal hop / by replay.
- **No per-request replay cache.** Replay is bounded only by the `created`
  window (keep it tight; keep clocks NTP-synced).
- **`allow_any_issuer` trusts any self-asserted identity** — see the config
  note; downstream authz must be `(issuer, subject_id)`-scoped.
- **No `Signature-Error` / `Accept-Signature-Alg` response headers.**
  signature-key-08 §5.4.1 says a rejection SHOULD carry the machine-readable
  error code and, for `unsupported_algorithm`, an `Accept-Signature-Alg` header
  naming what the verifier does accept. The gateway's identity-resolver ABI
  (`IdentityResolution::Invalid { reason }`) has no response-header channel — a
  rejected credential becomes a fixed 401 — so the code and the reason reach the
  log and the audit event, not the client. Meeting that SHOULD requires an ABI
  change, not a change here.
- **Rung 1 only.** The `account` parameter added in -10 belongs to the resource
  authorization endpoint (rung 2+) and is intentionally not implemented.

## Deploying the Agent Provider

This plugin is the **Resource** side. Agents get their identities from an Agent
Provider (e.g. [`apd`](https://github.com/agentprovider/source-code)), which
publishes `/.well-known/aauth-agent.json` + JWKS. See that project's
`docs/guide-mcp-server-auth.md` for the end-to-end picture.

## Attribution

The RFC 8037/7638/8941/9421 primitives under `src/aauth/` are vendored from
`aauth-core` (MIT OR Apache-2.0); see `third_party/aauth-core/`.

## Building and testing

```sh
cargo build --release   # builds the plugin cdylib into target/release/
cargo test
```
