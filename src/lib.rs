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

        tracing::info!(
            plugin_id = PLUGIN_ID,
            trusted_issuers = config.trusted_issuers.len(),
            allow_any_issuer = config.allow_any_issuer,
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
    if let IdentityResolution::Invalid { reason } = result {
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
    ) {
        verifier::Outcome::NoCredential => IdentityResolution::None,
        verifier::Outcome::Rejected(err) => IdentityResolution::Invalid {
            reason: format!("{}: {}", err.code.as_str(), err.detail),
        },
        verifier::Outcome::Verified(vid) => IdentityResolution::Resolved {
            identity: build_identity(inner, *vid),
        },
    }
}

fn build_identity(inner: &Inner, vid: verifier::VerifiedIdentity) -> PluginIdentity {
    let claims = vid.claims;
    let mut attributes: BTreeMap<String, String> = BTreeMap::new();
    attributes.insert("aauth.jti".to_owned(), claims.jti);
    if let Some(ps) = claims.ps {
        attributes.insert("aauth.ps".to_owned(), ps);
    }
    if let Some(parent) = claims.parent_agent {
        attributes.insert("aauth.parent_agent".to_owned(), parent);
    }

    PluginIdentity {
        kind: inner.config.resolution.trust_level.clone(),
        trust_level: inner.config.resolution.trust_level.clone(),
        // `sub` is `aauth:local@domain` — domain-qualified and stable across the
        // agent's key rotations. Use it directly as the principal; `issuer`
        // carries the vouching AP for per-issuer trust policy downstream.
        subject_id: Some(claims.sub),
        auth_provider: Some(inner.config.resolution.auth_provider_label.clone()),
        issuer: Some(claims.iss),
        // Rung-1 agent tokens carry no scopes/roles/groups (those come from
        // resource/auth tokens in rungs 2–4).
        roles: Vec::new(),
        groups: Vec::new(),
        scopes: Vec::new(),
        attributes,
    }
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
