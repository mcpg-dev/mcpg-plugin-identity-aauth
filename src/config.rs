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
    /// NOTE: an identity resolver has no access to the request body, so this
    /// enforces only that the agent *committed* to the named component — it
    /// does NOT verify a `content-digest` value against the actual body. Full
    /// body integrity additionally requires the gateway/backend to verify the
    /// covered `content-digest` against the received body (out of scope for an
    /// identity resolver). Rung-1 AAuth identity binds the request envelope
    /// (method/authority/path[/query][/committed digest]) + the agent identity,
    /// not the body content.
    #[serde(default)]
    pub additional_covered_components: Vec<String>,

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
        self.jwks.validate()?;
        self.resolution.validate()?;
        Ok(())
    }

    /// True when `iss` is admitted by the trust policy.
    pub fn issuer_trusted(&self, iss: &str) -> bool {
        self.allow_any_issuer || self.trusted_issuers.iter().any(|t| t == iss)
    }
}

fn default_signature_window_secs() -> u64 {
    60
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
