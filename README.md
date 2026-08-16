# `dev.mcpg.identity.aauth` — AAuth agent, person & auth-token identity

Resolves cryptographic identity from AAuth-signed inbound requests and maps it
into the MCPG gateway identity context: the stable agent principal
`aauth:local@domain`; opt-in, the PS-asserted **person** an agent acts for;
and, opt-in, the PS- or AS-issued **auth token** whose `scope` becomes the
gateway's scopes. It replaces API keys / OAuth Dynamic Client Registration
with **per-request, self-sovereign, proof-of-possession** identity.

- **Protocol:** AAuth (`draft-hardt-oauth-aauth-protocol-11`) + HTTP Signature
  Keys (`draft-hardt-httpbis-signature-key-08`), RFC 9421 HTTP Message
  Signatures. Interoperates with the reference person server
  ([personserver.dev](https://personserver.dev), `psd`) — proved end to end
  by `e2e/inspector/aauth-person-server-e2e.sh`.
- **Class:** `identity_provider` · **Runtime:** `native-cdylib-v1` · **License:** Apache-2.0
- **Scope:** the verifying half of the gateway's *Resource* role, in three
  access modes — **agent identity** (always), **person identity**
  (`person_tokens`), and **PS-authorization / federated** (`auth_tokens`).
  The issuing half — the signing key, `authorization_endpoint`
  (resource tokens) and `revocation_endpoint` — is the gateway's
  `server.aauth_resource_metadata` block, described below. Southbound
  signing (the gateway as an *Agent*), sub-agents, and AAuth Events are out
  of scope.

## What it verifies (per request)

1. Parses `Signature-Input` / `Signature` / `Signature-Key` and enforces the
   covered components `@method @authority @path signature-key` and the `created`
   window (default ±60s). `expires` is honored when present; the RFC 9421
   `alg`/`keyid`/`nonce`/`tag` signature parameters are **ignored**, as the
   drafts require — the algorithm comes from the key alone.
2. Extracts the JWT from the `Signature-Key` `jwt` scheme (any other scheme is
   refused with the draft's `unsupported_scheme`).
3. Branches on `typ`: `aa-agent+jwt` always; `aa-person+jwt` when
   `person_tokens.enabled`; `aa-auth+jwt` when `auth_tokens.enabled`.
   Everything else — subscribe tokens, resource tokens — is rejected by type
   (the drafts call out that this case otherwise fails open).
4. Verifies the token against the issuer's **published JWKS** — fetched from
   `{iss}/.well-known/aauth-agent.json` (or `aauth-person.json`) → `jwks_uri`,
   with the document's `issuer` asserted to equal `iss` (host-poisoning
   defense; `issuer_missing` / `issuer_mismatch` on failure), cached with
   `Cache-Control` respected inside the floor/ceiling, and
   SSRF-egress-admitted. The `alg` gate runs *before* the fetch, so a token
   signed with an algorithm we can never accept never drives outbound traffic.
5. Validates the claims (identifier grammar, `dwk` pinning, expiry, the 24 h
   agent / 1 h person and auth lifetime ceilings, `aud` = this gateway on
   person and auth tokens, `ps == iss` on a PS-issued auth token, the person
   token's forbidden `scope`/`account` members), checks the `(iss, jti)`
   revocation list, and — when `replay_protection` is on — rejects a
   duplicate signature tuple inside the window.
6. Enforces the **proof-of-possession binding**: the request's RFC 9421
   signature must verify under the token's `cnf.jwk`.
7. On success, resolves identity: for agents `subject_id = sub` (e.g.
   `aauth:k7q3p9n2@ap.example`, domain-bound to the issuer); for persons and
   auth tokens `subject_id = sub` (a directed opaque identifier — key
   downstream policy on `(issuer, subject_id)`); an auth token's `scope`
   becomes `scopes`. Attributes: `aauth.token_type` (`agent` | `person` |
   `auth`), `aauth.jti`, `aauth.agent_jkt` (RFC 7638 thumbprint of the
   agent key), `aauth.exp`, `aauth.ps`, and per type `aauth.parent_agent`,
   `aauth.mission_s256`, `aauth.tenant`, `aauth.account`.

An unauthenticated caller (no signature headers) resolves to *no identity* so
other resolvers / anonymous handling apply. A presented-but-invalid credential
resolves to *invalid* — a 401 that now carries the machine-readable
`Signature-Error` header (and `Accept-Signature-Scheme` /
`Accept-Signature-Alg` recovery hints where the draft pairs them).

## Security posture

- **Fail-closed trust policy.** `trusted_issuers` is an allow-list of Agent
  Providers; an empty list without `allow_any_issuer` refuses to load.
  `person_tokens.trusted_person_servers` is explicit-only — there is
  deliberately no allow-any escape for the parties that assert who a person is.
- **SSRF egress admission** on every metadata/JWKS fetch: HTTPS only, no
  redirects, private/loopback/link-local/CGNAT/reserved IPs blocked, the resolved
  address pinned (anti-rebinding), body (64 KiB) and time (10 s) capped.
- **JWKS cache**: ≥1 fetch/min floor, ≤24h ceiling, `Cache-Control: max-age`
  respected between those bounds, refresh-on-unknown-kid with a single retry,
  keyed by `(iss, dwk)`.
- **Cross-origin JWKS** rejected unless the host is in `jwks.cross_origin_hosts`.
- **Fully-specified algorithms only** — see below. `dwk` is pinned per token
  type before any fetch (no path injection).

## Algorithms

The drafts require a *fully-specified* algorithm identifier everywhere a key
is conveyed or published, ban `none`, the polymorphic `EdDSA`, and all
symmetric algorithms, and make `Ed25519` support a MUST and `ES256` a SHOULD.
This plugin implements both:

| Where | Rule |
| --- | --- |
| Token header `alg` | `Ed25519` and `ES256` accepted; the header must name the SAME algorithm the issuer key carries. `EdDSA`, `none`, `HS*`, `RS*`, `PS*` rejected as `unsupported_algorithm`. `Ed448` is spec-valid but has no backend here — rejected with a message that says exactly that. |
| Token `cnf.jwk` | MUST carry `alg`, fully specified and consistent with the key's `kty`/`crv` (OKP/Ed25519 → `Ed25519`, EC/P-256 → `ES256`); a disagreement is rejected as `invalid_key` rather than resolved either way. |
| `Signature-Key` `hwk` member | `alg` is **REQUIRED** and must be fully specified (signature-key-08 §3.4). OKP/Ed25519 and EC/P-256 shapes parse. |
| `Signature-Input` `alg` | **Ignored**, whatever its value — signature-key-08 "Algorithm Selection": signers MUST NOT send it and verifiers MUST ignore it; the key signals the algorithm. |
| Published JWKS keys | The key selected by `kid` MUST carry a fully-specified `alg` (the drafts make a published key that omits it unusable, even though RFC 7517 leaves the member optional). Unusable *sibling* keys never break selection, and a `kid` that exists only as an unsupported type reports `unsupported_algorithm`, not `unknown_key`. |

There is deliberately **no configuration flag to re-admit `EdDSA`**: the drafts
say MUST NOT, and a toggle would just be a switch that makes the gateway
non-compliant. An Agent Provider still emitting the polymorphic identifier will
be refused with `unsupported_algorithm` until it is updated — that rejection is
intended, not a regression.

Southbound, everything this crate signs or serialises is fully specified too:
JWTs carry `alg: Ed25519`, minted JWKs (including the embedded `cnf.jwk`) carry
`alg`, and the `hwk` serialiser emits an `alg` parameter. (Signing is
Ed25519-only; ES256 is verify-side, for agents whose hardware-backed keys are
P-256.)

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
      #   - "@query"                       #   (alias: additional_signature_components —
      #   - content-digest                 #    the resource-metadata field name)
      # person_tokens:                     # opt-in person-identity access mode
      #   enabled: true
      #   resource_identifier: https://gw.example   # this gateway's AAuth identifier (`aud`)
      #   trusted_person_servers:
      #     - https://sandbox.personserver.dev
      # auth_tokens:                       # opt-in: PS/AS-issued grants → scopes
      #   enabled: true                    #   (requires person_tokens.enabled)
      #   trusted_access_servers: []       #   four-party ASes (dwk aauth-access.json)
      # replay_protection: false           # reject duplicate signature tuples in-window;
      #                                    #   pair with content-digest coverage (see below)
      # revoked_tokens:                    # out-of-band (iss, jti) deny-list
      #   - { iss: "https://ap.example", jti: "abc123" }
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

## The gateway's resource role (`server.aauth_resource_metadata`)

This plugin verifies. What a person server needs from a *resource* beyond
that — the discovery document, a signing key, resource tokens, revocation —
lives in the gateway's `server.aauth_resource_metadata` block:

```yaml
gateway:
  server:
    aauth_resource_metadata:
      issuer: https://gw.example              # = person_tokens.resource_identifier
      access_mode: auth-token                 # agent-token | person-token | auth-token
      signing_key: { seed: "${env.AAUTH_RESOURCE_SEED}" }   # or seed_file / ephemeral (dev)
      scope_descriptions:
        "tools:read": "Read-only tools"
        "tools:write": "Tools that change things"
      name: "Example gateway"
```

With that the gateway:

- serves `/.well-known/aauth-resource.json` (with `jwks_uri`,
  `authorization_endpoint`, `revocation_endpoint`, `scope_descriptions`,
  `accept_signature_algs`) and its JWKS at `/.well-known/aauth-jwks.json`;
- answers an unauthenticated caller with `401` +
  `AAuth-Requirement: requirement=person-token` (`agent-token` for an
  identity-only resource) so an AAuth agent learns which credential to bring;
- mints resource tokens (`aa-resource+jwt`, ≤ 5 min, `aud` = the person
  server) at `POST /aauth/authorize` for a caller presenting a person token,
  and as the `requirement=auth-token; resource-token="…"` step-up when a
  person or auth-token caller lacks a tool's `required_scopes`;
- accepts revocations at `POST /aauth/revoke` — the person server's
  `jwks_uri`-signed `{iss, jti}` — and refuses that credential from then on.

Tools declare their scope needs on the binding:

```yaml
mcp:
  capabilities:
    tools:
      - name: deploy.rollback
        governance:
          minimum_trust: verified
          required_scopes: ["tools:write"]
```

The loop an agent runs is the one the drafts describe: present a person
token → be challenged with a resource token → take it to the person server →
present the auth token. `mcpg inspector … --aauth-credential auth
--aauth-scopes "tools:write" --aauth-person-server https://…` drives it.

## Scope & limitations

- **Binds the request envelope, not the body.** Identity-mode verification
  binds `@method`/`@authority`/`@path` (and, if the agent covers them,
  `@query`/`content-digest`) plus the identity. It does **not** bind the MCP
  request *body* — an identity resolver has no body access. For full operation
  integrity on state-changing calls, require `content-digest` via
  `additional_covered_components` **and** verify that covered digest against
  the received body at the gateway/backend (outside this plugin).
- **Replay protection is off by default, deliberately.** `created` has
  one-second granularity, so two legitimate identical calls in the same second
  are indistinguishable from a replay unless the signature also covers a
  per-request component. Enable `replay_protection` together with
  `additional_covered_components: ["content-digest"]`; without it, replay is
  bounded by the `created` window (keep it tight; keep clocks NTP-synced).
- **`allow_any_issuer` trusts any self-asserted agent identity**, and person
  `sub` values are opaque per-PS strings — in both cases downstream authz must
  key on `(issuer, subject_id)`, never `subject_id` alone.
- **Revocation reaches one replica.** The gateway's `/aauth/revoke`
  endpoint records `(iss, jti)` in the process that received it; a
  multi-node fleet is told per replica the person server happens to reach.
  Exposure is bounded by the token lifetime ceilings (24 h agents / 1 h
  persons and auth tokens); `revoked_tokens` covers operator-driven cases
  cluster-wide via config.
- **Session tokens (`AAuth-Access`, resource-managed mode) and four-party
  federation on the resource's own behalf are not implemented.** Auth tokens
  an Access Server issued are verified when it is allow-listed in
  `auth_tokens.trusted_access_servers`.

## Deploying the Agent Provider

This plugin is the **Resource** side. Agents get their identities from an Agent
Provider (e.g. [`apd`](https://github.com/agentprovider/source-code)), which
publishes `/.well-known/aauth-agent.json` + JWKS. See that project's
`docs/guide-mcp-server-auth.md` for the end-to-end picture.

## Attribution

The RFC 8037/7638/8941/9421 primitives live in `libs/aauth-core`, vendored
from `aauth-core` (MIT OR Apache-2.0); see that crate's
`third_party/aauth-core/`.

## Building and testing

```sh
cargo build --release   # builds the plugin cdylib into target/release/
cargo test
```
