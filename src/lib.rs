//! `dev.mcpg.identity.aauth` — AAuth agent-identity resolver.
//!
//! Verifies AAuth-signed inbound requests
//! (`draft-hardt-oauth-aauth-protocol` / `draft-hardt-httpbis-signature-key`)
//! and maps the cryptographic agent principal `aauth:local@domain` into the
//! gateway identity context. This is AAuth **Pattern A** (rung 1,
//! identity-based): the gateway acts as a *Resource*, verifying the presented
//! `aa-agent+jwt` agent token against the issuing Agent Provider's published
//! JWKS and the RFC 9421 HTTP Message Signature, then keying identity off the
//! stable `sub`. It replaces API keys / OAuth Dynamic Client Registration with
//! per-request, self-sovereign, proof-of-possession agent identity.
//!
//! Scope: inbound identity resolution only. Southbound request *signing* (the
//! gateway acting as an Agent), sub-agents, AAuth Events, and the Person /
//! Access-Server flows (rungs 2–4) are separate concerns and not part of an
//! identity resolver.
//!
//! The RFC 8037/7638/8941/9421 primitives live in `mcpg-aauth-core`; this
//! crate adds the config surface, the egress-admitted JWKS cache, and the
//! verification orchestration. Fails closed on bad config (a misconfigured
//! identity resolver is a security hole).

// The primitives were vendored into this crate until the inspector needed
// the SIGNING half of the same code. Two copies of security-critical crypto
// is the worse answer, and the module was already I/O-free with no plugin
// dependencies, so it became a leaf crate that both sides share.
use mcpg_aauth_core as aauth;

pub mod config;
pub mod jwks;
pub mod verifier;

use std::sync::Arc;

use mcpg_plugin_protocol::types::RequestMetadata;
use mcpg_plugin_protocol::{
    IdentityResolution, PluginIdentity, PluginManifest, firstparty_manifest,
};
use mcpg_plugin_sdk::ffi::SyncIdentityResolver;
use serde_json::Value;
use std::collections::BTreeMap;
use tracing::{info_span, warn};

pub use config::AauthConfig;

const PLUGIN_ID: &str = "dev.mcpg.identity.aauth";

pub struct AauthIdentityPlugin {
    inner: Arc<Inner>,
}

struct Inner {
    manifest: PluginManifest,
    config: AauthConfig,
    jwks: jwks::JwksResolver,
    /// Present when the operator enabled `replay_protection`.
    replay: Option<verifier::ReplayGuard>,
}

impl AauthIdentityPlugin {
    pub fn from_config_json(config_json: &str) -> Self {
        let config = AauthConfig::parse(config_json).unwrap_or_else(|err| {
            tracing::error!(
                plugin_id = PLUGIN_ID,
                error = %err,
                "identity.aauth: config parse failed; refusing to register"
            );
            panic!(
                "identity.aauth config parse failed: {err}. A misconfigured identity resolver is \
                 a security hole; refusing to load rather than falling back to defaults. Fix \
                 operator config and retry."
            )
        });

        let jwks = jwks::JwksResolver::new(&config.jwks, config.insecure_dev_mode);
        let replay = config
            .replay_protection
            .then(verifier::ReplayGuard::default);

        tracing::info!(
            plugin_id = PLUGIN_ID,
            trusted_issuers = config.trusted_issuers.len(),
            allow_any_issuer = config.allow_any_issuer,
            person_tokens = config.person_tokens.enabled,
            replay_protection = config.replay_protection,
            "identity.aauth: verifier compiled"
        );

        Self {
            inner: Arc::new(Inner {
                manifest: firstparty_manifest! {
                    id: PLUGIN_ID,
                    name: "AAuth Agent Identity Resolver",
                    class: IdentityProvider,
                    capabilities: [mcpg_plugin_protocol::capability::Capability::NetworkOutbound],
                },
                config,
                jwks,
                replay,
            }),
        }
    }
}

fn record_resolve_outcome(result: &IdentityResolution, elapsed: std::time::Duration) {
    let outcome = match result {
        IdentityResolution::Resolved { .. } => "resolved",
        IdentityResolution::None => "none",
        IdentityResolution::Invalid { .. } => "invalid",
    };
    metrics::counter!("mcpg_identity_aauth_resolutions_total", "outcome" => outcome).increment(1);
    metrics::histogram!("mcpg_identity_aauth_resolve_ms").record(elapsed.as_millis() as f64);
    if let IdentityResolution::Invalid { reason, .. } = result {
        warn!(reason = %reason, "identity.aauth: rejected AAuth credential");
    }
}

fn lookup_header<'a>(headers: &'a [(String, String)], target: &str) -> Option<&'a str> {
    headers
        .iter()
        .find_map(|(name, value)| name.eq_ignore_ascii_case(target).then_some(value.as_str()))
}

fn resolve(
    inner: &Inner,
    headers: &[(String, String)],
    metadata: &RequestMetadata,
) -> IdentityResolution {
    // AAuth is HTTP-only (the signature covers @method/@authority/@path).
    if !metadata.transport.eq_ignore_ascii_case("http") {
        return IdentityResolution::None;
    }

    // @authority: the operator override wins (proxied deployments where Host is
    // rewritten); otherwise the as-received Host, canonicalized.
    //
    // The override is taken verbatim, only lowercased. Canonicalizing it would
    // strip `:443`, and there is no other way to express the authority an agent
    // signs when it dials plain HTTP on port 443 — a TLS terminator's backend.
    let authority = match &inner.config.expected_authority {
        Some(a) => a.trim().to_ascii_lowercase(),
        None => lookup_header(headers, "host")
            .map(verifier::canonical_authority)
            .unwrap_or_default(),
    };

    let method = metadata.method.as_deref().unwrap_or_default();
    let path = metadata.path.as_deref().unwrap_or("/");
    // RFC 9421 `@query` includes the leading `?`; empty when there was none.
    let query = match metadata.query.as_deref() {
        Some(q) if !q.is_empty() => format!("?{q}"),
        _ => String::new(),
    };

    match verifier::verify(
        headers,
        method,
        &authority,
        path,
        &query,
        &inner.config,
        &inner.jwks,
        inner.replay.as_ref(),
    ) {
        verifier::Outcome::NoCredential => IdentityResolution::None,
        verifier::Outcome::Rejected(err) => IdentityResolution::Invalid {
            reason: format!("{}: {}", err.code.as_str(), err.detail),
            response_headers: error_response_headers(&err),
        },
        verifier::Outcome::Verified(vid) => IdentityResolution::Resolved {
            identity: build_identity(inner, *vid),
        },
    }
}

/// The response headers a `401` for this failure should carry: the
/// machine-readable `Signature-Error` (the authoritative error channel — the
/// draft says agents MUST NOT depend on the body), plus the
/// `Accept-Signature-*` capability statements naming what WOULD succeed on
/// the two recoverable errors.
fn error_response_headers(err: &aauth::sig::SigError) -> Vec<(String, String)> {
    let mut sig_error = format!("error={}", err.code.as_str());
    if let Some(required) = &err.required_input {
        let refs: Vec<&str> = required.iter().map(|s| s.as_str()).collect();
        sig_error.push_str(&format!(
            ", required_input={}",
            aauth::sfv::serialize_string_list(&refs)
        ));
    }
    let mut headers = vec![("signature-error".to_owned(), sig_error)];
    match err.code {
        aauth::sig::SigErrorCode::UnsupportedScheme => {
            headers.push(("accept-signature-scheme".to_owned(), "jwt".to_owned()));
        }
        aauth::sig::SigErrorCode::UnsupportedAlgorithm => {
            headers.push((
                "accept-signature-alg".to_owned(),
                aauth::jwt::SUPPORTED_ALGS.join(", "),
            ));
        }
        _ => {}
    }
    headers
}

fn build_identity(inner: &Inner, vid: verifier::VerifiedIdentity) -> PluginIdentity {
    let mut attributes: BTreeMap<String, String> = BTreeMap::new();
    let mut scopes: Vec<String> = Vec::new();
    // Every AAuth credential binds the request to one key; its RFC 7638
    // thumbprint is what a resource token names as `agent_jkt`, and the
    // token's expiry bounds how long any state derived from it may live.
    let (subject_id, issuer) = match vid {
        verifier::VerifiedIdentity::Agent(claims) => {
            // `sub` is `aauth:local@domain` — domain-qualified (verified
            // against the issuer's host) and stable across the agent's key
            // rotations. Use it directly as the principal; `issuer` carries
            // the vouching AP for per-issuer trust policy downstream.
            attributes.insert("aauth.token_type".to_owned(), "agent".to_owned());
            insert_common(&mut attributes, &claims.jti, &claims.cnf.jwk, claims.exp);
            if let Some(ps) = claims.ps {
                attributes.insert("aauth.ps".to_owned(), ps);
            }
            if let Some(parent) = claims.parent_agent {
                attributes.insert("aauth.parent_agent".to_owned(), parent);
            }
            (claims.sub, claims.iss)
        }
        verifier::VerifiedIdentity::Person(claims) => {
            // A person `sub` is a directed OPAQUE identifier, unique within
            // its issuing PS only — `(issuer, subject_id)` is the identifier,
            // and downstream authorization MUST key on the pair, exactly as
            // documented for `allow_any_issuer` agent identities.
            attributes.insert("aauth.token_type".to_owned(), "person".to_owned());
            insert_common(&mut attributes, &claims.jti, &claims.cnf.jwk, claims.exp);
            // The person server that asserted this person is the token issuer.
            attributes.insert("aauth.ps".to_owned(), claims.iss.clone());
            if let Some(m) = claims.mission_s256 {
                attributes.insert("aauth.mission_s256".to_owned(), m);
            }
            if let Some(t) = claims.tenant {
                attributes.insert("aauth.tenant".to_owned(), t);
            }
            (claims.sub, claims.iss)
        }
        verifier::VerifiedIdentity::Auth(claims) => {
            // The grant: the person is `(ps, sub)`; what is authorized is
            // `scope`, which becomes the gateway's `scopes` so tool policy
            // (`required_scopes`, CEL `identity.scopes`) applies unchanged.
            attributes.insert("aauth.token_type".to_owned(), "auth".to_owned());
            insert_common(&mut attributes, &claims.jti, &claims.cnf.jwk, claims.exp);
            attributes.insert("aauth.ps".to_owned(), claims.ps.clone());
            scopes = claims.scopes();
            if let Some(a) = claims.account {
                attributes.insert("aauth.account".to_owned(), a);
            }
            if let Some(m) = claims.mission_s256 {
                attributes.insert("aauth.mission_s256".to_owned(), m);
            }
            if let Some(t) = claims.tenant {
                attributes.insert("aauth.tenant".to_owned(), t);
            }
            (claims.sub, claims.iss)
        }
    };

    PluginIdentity {
        kind: inner.config.resolution.trust_level.clone(),
        trust_level: inner.config.resolution.trust_level.clone(),
        subject_id: Some(subject_id),
        auth_provider: Some(inner.config.resolution.auth_provider_label.clone()),
        issuer: Some(issuer),
        // Identity-mode tokens carry no roles/groups; scopes come only from
        // an auth token's grant.
        roles: Vec::new(),
        groups: Vec::new(),
        scopes,
        attributes,
    }
}

/// Attributes every AAuth credential yields: the token id (revocation and
/// audit key, with `issuer`), the agent key's thumbprint, and the expiry.
fn insert_common(
    attributes: &mut BTreeMap<String, String>,
    jti: &str,
    cnf_jwk: &aauth::jwk::Jwk,
    exp: u64,
) {
    attributes.insert("aauth.jti".to_owned(), jti.to_owned());
    if let Ok(t) = cnf_jwk.thumbprint() {
        attributes.insert("aauth.agent_jkt".to_owned(), t);
    }
    attributes.insert("aauth.exp".to_owned(), exp.to_string());
}

impl SyncIdentityResolver for AauthIdentityPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    fn resolve_identity(
        &self,
        headers: &[(String, String)],
        metadata: &RequestMetadata,
        _config: &Value,
    ) -> IdentityResolution {
        let _span = info_span!("identity_aauth_resolve", plugin_id = PLUGIN_ID).entered();
        let started = std::time::Instant::now();
        let result = resolve(&self.inner, headers, metadata);
        record_resolve_outcome(&result, started.elapsed());
        result
    }
}

#[cfg(any(feature = "cdylib-export", feature = "static-firstparty"))]
mcpg_plugin_sdk::declare_plugin! {
    plugin_id: "dev.mcpg.identity.aauth",
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[mcpg_plugin_protocol::capability::Capability::NetworkOutbound],
    entities: [
        identity as id {
            inner_name: "",
            plugin_type: AauthIdentityPlugin,
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| -> AauthIdentityPlugin {
                AauthIdentityPlugin::from_config_json(cfg)
            },
        }
    ],
}

#[cfg(test)]
mod tests;
