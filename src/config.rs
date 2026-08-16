//! Operator-supplied configuration for `dev.mcpg.identity.aauth`.
//!
//! All structs reject unknown fields and the resolver fails closed: an empty
//! Agent-Provider allow-list without an explicit `allow_any_issuer` opt-in is a
//! hard error (any AP could otherwise mint an accepted identity).

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AauthConfig {
    /// Agent-Provider issuers (`iss`) the gateway trusts, e.g.
    /// `https://ap.example`. A presented token whose `iss` is not listed is
    /// rejected. Exact-match against the server identifier (no trailing slash).
    #[serde(default)]
    pub trusted_issuers: Vec<String>,

    /// Accept a token from any `iss` (subject only to egress admission). Off by
    /// default. **Dangerous:** this trusts ANY self-asserted agent identity —
    /// an attacker who stands up their own Agent Provider can assert an
    /// arbitrary `subject_id` at `trust_level: verified`. Only the recorded
    /// `issuer` disambiguates, so downstream authorization MUST key on
    /// `(issuer, subject_id)`, never `subject_id` alone. It also removes the
    /// bound on which hosts the gateway will fetch JWKS from (still IP-egress-
    /// admitted). Use only on trusted networks; prefer an explicit
    /// `trusted_issuers` allow-list.
    #[serde(default)]
    pub allow_any_issuer: bool,

    /// Symmetric `created`-timestamp window, seconds (AAuth default 60). A
    /// request signature whose `created` is outside `[now-window, now+window]`
    /// is rejected. Depends on NTP-synced clocks across agents and the gateway.
    #[serde(default = "default_signature_window_secs")]
    pub signature_window_secs: u64,

    /// Override the `@authority` the signature is verified against. Set to the
    /// public hostname agents sign toward when a TLS-terminating proxy in front
    /// of the gateway rewrites `Host`. When unset, the request's `Host` header
    /// is used as received.
    ///
    /// Taken verbatim (lowercased), NOT canonicalized: include the port if and
    /// only if the agent signs one. An agent dialling `http://host:443` signs
    /// `host:443`, because 443 is not the default port for `http` — the
    /// as-received path elides `:443` and cannot express this.
    #[serde(default)]
    pub expected_authority: Option<String>,

    /// Covered components to require IN ADDITION to the mandatory
    /// `@method @authority @path signature-key`. Set e.g. `["@query"]` or
    /// `["content-digest"]` to require the agent's signature to also cover the
    /// query string / a request-body digest header.
    ///
    /// `additional_signature_components` is the resource-metadata field name
    /// the AAuth protocol uses for the same declaration and is accepted as an
    /// alias, so the plugin config can mirror a published
    /// `/.well-known/aauth-resource.json` verbatim.
    ///
    /// NOTE: an identity resolver has no access to the request body, so this
    /// enforces only that the agent *committed* to the named component — it
    /// does NOT verify a `content-digest` value against the actual body. Full
    /// body integrity additionally requires the gateway/backend to verify the
    /// covered `content-digest` against the received body (out of scope for an
    /// identity resolver). Rung-1 AAuth identity binds the request envelope
    /// (method/authority/path[/query][/committed digest]) + the agent identity,
    /// not the body content.
    #[serde(default, alias = "additional_signature_components")]
    pub additional_covered_components: Vec<String>,

    /// Accept PS-issued person tokens (`aa-person+jwt`) alongside agent
    /// tokens — the protocol's person-identity access mode. Off by default.
    #[serde(default)]
    pub person_tokens: PersonTokenConfig,

    /// Accept PS/AS-issued auth tokens (`aa-auth+jwt`) — the grants that
    /// carry `scope`. Requires `person_tokens.enabled` (the resource MUST
    /// have verified a person token before any auth token can exist for it,
    /// and `resource_identifier` is shared).
    #[serde(default)]
    pub auth_tokens: AuthTokenConfig,

    /// Reject a signature whose `(key thumbprint, created, method, authority,
    /// path)` tuple was already accepted inside the `created` window — the
    /// spec's optional replay cache for state-changing requests. Off by
    /// default: with per-second `created` granularity, two legitimate
    /// identical calls in the same second are indistinguishable from a replay
    /// unless the signature also covers a per-request component such as
    /// `content-digest`. Enable together with
    /// `additional_covered_components: ["content-digest"]`.
    #[serde(default)]
    pub replay_protection: bool,

    /// Tokens revoked out of band, matched by `(iss, jti)` — the pair the
    /// protocol keys revocation state by. A verified token naming a listed
    /// pair is rejected even though its signature and claims are valid.
    #[serde(default)]
    pub revoked_tokens: Vec<RevokedToken>,

    /// JWKS / metadata fetch + cache tuning.
    #[serde(default)]
    pub jwks: JwksConfig,

    /// Development escape hatch: admit `http://` and private/loopback/link-local
    /// issuer + JWKS hosts (SSRF egress admission is otherwise fail-closed).
    /// NEVER set in production — a token's `iss`/`jwks_uri` are attacker-chosen.
    #[serde(default)]
    pub insecure_dev_mode: bool,

    /// How the resolved identity is labelled in the gateway identity context.
    #[serde(default)]
    pub resolution: ResolutionConfig,
}

impl AauthConfig {
    pub fn parse(s: &str) -> Result<Self> {
        let cfg: Self = serde_json::from_str(s).context("invalid identity.aauth config JSON")?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.trusted_issuers.is_empty() && !self.allow_any_issuer {
            return Err(anyhow::anyhow!(
                "identity.aauth: `trusted_issuers` is empty — refusing to accept tokens from any \
                 Agent Provider (any AP could vouch for an accepted identity). List the AP \
                 issuers you trust, or opt in with `allow_any_issuer: true`."
            ));
        }
        for (i, iss) in self.trusted_issuers.iter().enumerate() {
            if iss.trim().is_empty() {
                return Err(anyhow::anyhow!(
                    "identity.aauth: trusted_issuers[{i}] is empty"
                ));
            }
            // Same server-identifier shape the token's `iss` is held to, so a
            // typo (trailing slash, scheme omission) fails at boot, not silently
            // at request time.
            super::aauth::ident::validate_server_identifier(iss, self.insecure_dev_mode)
                .map_err(|e| {
                    anyhow::anyhow!("identity.aauth: trusted_issuers[{i}] `{iss}` is not a valid AAuth issuer: {e:?}")
                })?;
        }
        if self.signature_window_secs == 0 {
            return Err(anyhow::anyhow!(
                "identity.aauth: signature_window_secs must be greater than 0"
            ));
        }
        self.person_tokens.validate(self.insecure_dev_mode)?;
        self.auth_tokens
            .validate(self.person_tokens.enabled, self.insecure_dev_mode)?;
        for (i, r) in self.revoked_tokens.iter().enumerate() {
            if r.iss.trim().is_empty() || r.jti.trim().is_empty() {
                return Err(anyhow::anyhow!(
                    "identity.aauth: revoked_tokens[{i}] needs both `iss` and `jti`"
                ));
            }
        }
        self.jwks.validate()?;
        self.resolution.validate()?;
        Ok(())
    }

    /// True when `(iss, jti)` names a revoked token.
    pub fn is_revoked(&self, iss: &str, jti: &str) -> bool {
        self.revoked_tokens
            .iter()
            .any(|r| r.iss == iss && r.jti == jti)
    }

    /// True when `iss` is admitted by the trust policy.
    pub fn issuer_trusted(&self, iss: &str) -> bool {
        self.allow_any_issuer || self.trusted_issuers.iter().any(|t| t == iss)
    }
}

fn default_signature_window_secs() -> u64 {
    60
}

/// A token revoked by `(iss, jti)` — the pair AAuth keys revocation by
/// (`jti` alone collides across issuers).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokedToken {
    pub iss: String,
    pub jti: String,
}

// --- person tokens ----------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonTokenConfig {
    /// Master switch. When off (default) an `aa-person+jwt` is rejected by
    /// its `typ` like any other non-agent token.
    #[serde(default)]
    pub enabled: bool,

    /// Person-Server issuers whose person tokens are accepted. Explicit
    /// allow-list only — a PS asserts WHO the person is, so trusting "any PS"
    /// would let an attacker-operated PS mint arbitrary person principals.
    #[serde(default)]
    pub trusted_person_servers: Vec<String>,

    /// This gateway's own AAuth server identifier (e.g. `https://gw.example`).
    /// A person token's `aud` must equal it exactly — it is what the PS
    /// issued the token FOR. Required when `enabled`.
    #[serde(default)]
    pub resource_identifier: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthTokenConfig {
    /// Master switch. When off (default) an `aa-auth+jwt` is rejected by
    /// its `typ` like any other unexpected token.
    #[serde(default)]
    pub enabled: bool,

    /// Access Servers whose auth tokens are accepted (four-party — this
    /// resource delegated policy to them; `dwk: aauth-access.json`).
    /// PS-issued auth tokens (three-party, `dwk: aauth-person.json`) are
    /// accepted from `person_tokens.trusted_person_servers`.
    #[serde(default)]
    pub trusted_access_servers: Vec<String>,
}

impl AuthTokenConfig {
    fn validate(&self, person_tokens_enabled: bool, insecure_dev: bool) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if !person_tokens_enabled {
            return Err(anyhow::anyhow!(
                "identity.aauth: auth_tokens.enabled requires person_tokens.enabled — an auth \
                 token for this resource can only exist after it verified a person token, and \
                 the two share `resource_identifier` and the trusted person-server list"
            ));
        }
        for (i, a) in self.trusted_access_servers.iter().enumerate() {
            super::aauth::ident::validate_server_identifier(a, insecure_dev).map_err(|e| {
                anyhow::anyhow!(
                    "identity.aauth: auth_tokens.trusted_access_servers[{i}] `{a}` is not a \
                     valid AAuth server identifier: {e:?}"
                )
            })?;
        }
        Ok(())
    }

    /// True when `iss` is an allow-listed Access Server.
    pub fn as_trusted(&self, iss: &str) -> bool {
        self.enabled && self.trusted_access_servers.iter().any(|t| t == iss)
    }
}

impl PersonTokenConfig {
    fn validate(&self, insecure_dev: bool) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let rid = self.resource_identifier.as_deref().unwrap_or_default();
        if rid.is_empty() {
            return Err(anyhow::anyhow!(
                "identity.aauth: person_tokens.enabled requires `resource_identifier` — the \
                 gateway's own AAuth server identifier the PS issues tokens for (`aud`)"
            ));
        }
        super::aauth::ident::validate_server_identifier(rid, insecure_dev).map_err(|e| {
            anyhow::anyhow!(
                "identity.aauth: person_tokens.resource_identifier `{rid}` is not a valid AAuth \
                 server identifier: {e:?}"
            )
        })?;
        if self.trusted_person_servers.is_empty() {
            return Err(anyhow::anyhow!(
                "identity.aauth: person_tokens.enabled requires a non-empty \
                 `trusted_person_servers` allow-list (a PS asserts who the person is; there is \
                 deliberately no allow-any escape hatch)"
            ));
        }
        for (i, ps) in self.trusted_person_servers.iter().enumerate() {
            super::aauth::ident::validate_server_identifier(ps, insecure_dev).map_err(|e| {
                anyhow::anyhow!(
                    "identity.aauth: person_tokens.trusted_person_servers[{i}] `{ps}` is not a \
                     valid AAuth server identifier: {e:?}"
                )
            })?;
        }
        Ok(())
    }

    /// True when `iss` is an allow-listed Person Server.
    pub fn ps_trusted(&self, iss: &str) -> bool {
        self.enabled && self.trusted_person_servers.iter().any(|t| t == iss)
    }
}

// --- JWKS / metadata fetch + cache -----------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwksConfig {
    /// JWKS hosts admitted even when they differ from the issuer host. By
    /// default a token's `jwks_uri` MUST share the issuer's host (a CDN on
    /// another host must be explicitly allow-listed here).
    #[serde(default)]
    pub cross_origin_hosts: Vec<String>,

    /// Minimum seconds between fetch *attempts* per issuer (AAuth floor: 60).
    /// Rate-limits refreshes so an unknown-`kid` flood can't hammer an AP.
    #[serde(default = "default_refresh_floor_secs")]
    pub refresh_floor_secs: u64,

    /// Maximum age a cached JWKS is served for regardless of cache headers
    /// (AAuth ceiling: 86400 = 24h).
    #[serde(default = "default_max_ttl_secs")]
    pub max_ttl_secs: u64,

    /// Whole-request timeout for a metadata / JWKS fetch, seconds.
    #[serde(default = "default_fetch_timeout_secs")]
    pub fetch_timeout_secs: u64,

    /// Hard cap on a metadata / JWKS response body, bytes.
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: usize,
}

impl Default for JwksConfig {
    fn default() -> Self {
        Self {
            cross_origin_hosts: Vec::new(),
            refresh_floor_secs: default_refresh_floor_secs(),
            max_ttl_secs: default_max_ttl_secs(),
            fetch_timeout_secs: default_fetch_timeout_secs(),
            max_response_bytes: default_max_response_bytes(),
        }
    }
}

impl JwksConfig {
    fn validate(&self) -> Result<()> {
        if self.refresh_floor_secs == 0 {
            return Err(anyhow::anyhow!(
                "identity.aauth: jwks.refresh_floor_secs must be greater than 0"
            ));
        }
        if self.max_ttl_secs == 0 {
            return Err(anyhow::anyhow!(
                "identity.aauth: jwks.max_ttl_secs must be greater than 0"
            ));
        }
        if self.fetch_timeout_secs == 0 {
            return Err(anyhow::anyhow!(
                "identity.aauth: jwks.fetch_timeout_secs must be greater than 0"
            ));
        }
        if self.max_response_bytes < 1024 {
            return Err(anyhow::anyhow!(
                "identity.aauth: jwks.max_response_bytes must be at least 1024"
            ));
        }
        Ok(())
    }
}

fn default_refresh_floor_secs() -> u64 {
    60
}
fn default_max_ttl_secs() -> u64 {
    24 * 3600
}
fn default_fetch_timeout_secs() -> u64 {
    10
}
fn default_max_response_bytes() -> usize {
    64 * 1024
}

// --- resolution ------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionConfig {
    /// Gateway trust level for a verified AAuth identity. AAuth is a
    /// cryptographic proof-of-possession, so `verified` is the correct value;
    /// `header_asserted` is offered only for parity with other resolvers.
    #[serde(default = "default_trust_level")]
    pub trust_level: String,

    /// `auth_provider` label recorded on the resolved identity.
    #[serde(default = "default_auth_provider_label")]
    pub auth_provider_label: String,
}

impl Default for ResolutionConfig {
    fn default() -> Self {
        Self {
            trust_level: default_trust_level(),
            auth_provider_label: default_auth_provider_label(),
        }
    }
}

impl ResolutionConfig {
    fn validate(&self) -> Result<()> {
        if !matches!(self.trust_level.as_str(), "verified" | "header_asserted") {
            return Err(anyhow::anyhow!(
                "identity.aauth: resolution.trust_level must be `verified` or `header_asserted`, got '{}'",
                self.trust_level
            ));
        }
        Ok(())
    }
}

fn default_trust_level() -> String {
    "verified".to_owned()
}
fn default_auth_provider_label() -> String {
    "aauth".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn minimal_config_parses() {
        let cfg =
            AauthConfig::parse(&json!({ "trusted_issuers": ["https://ap.example"] }).to_string())
                .unwrap();
        assert_eq!(cfg.signature_window_secs, 60);
        assert_eq!(cfg.jwks.refresh_floor_secs, 60);
        assert_eq!(cfg.jwks.max_ttl_secs, 24 * 3600);
        assert_eq!(cfg.resolution.trust_level, "verified");
    }

    #[test]
    fn empty_issuers_needs_opt_in() {
        assert!(AauthConfig::parse(&json!({}).to_string()).is_err());
        AauthConfig::parse(&json!({ "allow_any_issuer": true }).to_string()).unwrap();
    }

    #[test]
    fn deny_unknown_fields() {
        assert!(
            AauthConfig::parse(
                &json!({ "trusted_issuers": ["https://ap.example"], "x": 1 }).to_string()
            )
            .is_err()
        );
    }

    #[test]
    fn bad_issuer_shape_rejected() {
        // trailing slash / path is not a valid AAuth server identifier
        assert!(
            AauthConfig::parse(&json!({ "trusted_issuers": ["https://ap.example/"] }).to_string())
                .is_err()
        );
        assert!(
            AauthConfig::parse(&json!({ "trusted_issuers": ["ap.example"] }).to_string()).is_err()
        );
    }

    #[test]
    fn bad_trust_level_rejected() {
        assert!(
            AauthConfig::parse(
                &json!({ "trusted_issuers": ["https://ap.example"], "resolution": { "trust_level": "root" } })
                    .to_string()
            )
            .is_err()
        );
    }

    /// The AAuth resource-metadata field name is accepted as an alias, so
    /// plugin config can mirror a published `aauth-resource.json` verbatim.
    #[test]
    fn additional_signature_components_alias_accepted() {
        let via_alias = AauthConfig::parse(
            &json!({
                "trusted_issuers": ["https://ap.example"],
                "additional_signature_components": ["content-digest", "@query"],
            })
            .to_string(),
        )
        .unwrap();
        assert_eq!(
            via_alias.additional_covered_components,
            vec!["content-digest".to_owned(), "@query".to_owned()]
        );
    }

    #[test]
    fn person_tokens_config_fails_closed() {
        // enabled without a resource identifier
        assert!(
            AauthConfig::parse(
                &json!({
                    "trusted_issuers": ["https://ap.example"],
                    "person_tokens": { "enabled": true,
                        "trusted_person_servers": ["https://ps.example"] },
                })
                .to_string()
            )
            .is_err()
        );
        // enabled without any trusted PS
        assert!(
            AauthConfig::parse(
                &json!({
                    "trusted_issuers": ["https://ap.example"],
                    "person_tokens": { "enabled": true,
                        "resource_identifier": "https://gw.example" },
                })
                .to_string()
            )
            .is_err()
        );
        // fully specified parses, and the PS list is exact-match
        let cfg = AauthConfig::parse(
            &json!({
                "trusted_issuers": ["https://ap.example"],
                "person_tokens": { "enabled": true,
                    "resource_identifier": "https://gw.example",
                    "trusted_person_servers": ["https://ps.example"] },
            })
            .to_string(),
        )
        .unwrap();
        assert!(cfg.person_tokens.ps_trusted("https://ps.example"));
        assert!(!cfg.person_tokens.ps_trusted("https://other.example"));
    }

    #[test]
    fn revoked_tokens_match_by_pair() {
        let cfg = AauthConfig::parse(
            &json!({
                "trusted_issuers": ["https://ap.example"],
                "revoked_tokens": [ { "iss": "https://ap.example", "jti": "abc" } ],
            })
            .to_string(),
        )
        .unwrap();
        assert!(cfg.is_revoked("https://ap.example", "abc"));
        assert!(!cfg.is_revoked("https://ap.example", "xyz"));
        assert!(!cfg.is_revoked("https://other.example", "abc"));
    }

    #[test]
    fn issuer_trusted_matches_exact() {
        let cfg =
            AauthConfig::parse(&json!({ "trusted_issuers": ["https://ap.example"] }).to_string())
                .unwrap();
        assert!(cfg.issuer_trusted("https://ap.example"));
        assert!(!cfg.issuer_trusted("https://evil.example"));
        assert!(!cfg.issuer_trusted("https://ap.example/"));
    }
}
