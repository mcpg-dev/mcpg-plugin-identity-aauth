//! AAuth inbound verification: agent-identity access (always) and
//! person-identity access (opt-in).
//!
//! Chains the two cryptographic proofs that make an AAuth request trustworthy:
//! the issuer's JWKS key signs the presented JWT (proving the AP vouches for
//! the agent, or the PS for the person), and the token's `cnf.jwk` signs the
//! request (proving possession for *this* request). Because `signature-key` is
//! a required covered component, the whole token travels inside the verified
//! signature base — an attacker can neither swap the token nor forge the
//! request.

use std::collections::HashMap;
use std::sync::Mutex;

use sha2::{Digest, Sha256};

use crate::aauth::ident::validate_server_identifier;
use crate::aauth::jwk::Jwk;
use crate::aauth::sig::{self, RequestParts, SigError, SigErrorCode, VerifyPolicy};
use crate::aauth::sigkey::SigKeyScheme;
use crate::aauth::tokens::{self, AgentTokenClaims, AuthTokenClaims, PersonTokenClaims};
use crate::aauth::{jwt, now_unix};
use crate::config::AauthConfig;

/// Resolves an issuer's verifying key for a `(iss, dwk, kid)`. The production
/// impl is the egress-admitted [`crate::jwks::JwksResolver`]; a seam so the
/// verification orchestration is unit-testable without network I/O.
pub trait KeyResolver {
    fn get_key(&self, iss: &str, dwk: &str, kid: &str) -> Result<Jwk, SigError>;
    fn refresh_and_get(&self, iss: &str, dwk: &str, kid: &str) -> Result<Jwk, SigError>;
}

/// Well-known document names, fixed per token type by the AAuth profile;
/// asserted before the metadata fetch so a hostile `dwk` can never be a
/// path-injection vector in `{iss}/.well-known/{dwk}`.
const AGENT_DWK: &str = "aauth-agent.json";
const PERSON_DWK: &str = "aauth-person.json";
const ACCESS_DWK: &str = "aauth-access.json";

/// Names of the three AAuth signature headers.
const H_SIG_INPUT: &str = "signature-input";
const H_SIG: &str = "signature";
const H_SIG_KEY: &str = "signature-key";

/// What the verifier concluded about a request.
pub enum Outcome {
    /// No AAuth credential presented — let other resolvers/anonymous handle it.
    NoCredential,
    /// A valid, proof-of-possession-bound identity. Boxed because the
    /// verified claims are much larger than the other variants.
    Verified(Box<VerifiedIdentity>),
    /// A credential was presented but failed verification.
    Rejected(SigError),
}

/// The cryptographically verified identity — which of the two credential
/// types the caller presented.
pub enum VerifiedIdentity {
    /// `aa-agent+jwt`: the AP-vouched agent, keyed by `sub`
    /// (`aauth:local@domain`).
    Agent(AgentTokenClaims),
    /// `aa-person+jwt`: the PS-asserted person, keyed by `(iss, sub)` —
    /// `sub` is a directed opaque identifier meaningful only under its
    /// issuing PS.
    Person(PersonTokenClaims),
    /// `aa-auth+jwt`: a PS- or AS-issued grant for this resource — the
    /// person (`ps`, `sub`) plus what is authorized (`scope`).
    Auth(AuthTokenClaims),
}

/// The spec's optional replay cache: a bounded set of
/// `(key thumbprint, created, @method, @authority, @path)` tuples, rejecting a
/// duplicate inside the signature window. Entries expire with the window, so
/// the set never needs to persist.
pub struct ReplayGuard {
    /// tuple-hash → unix second after which the entry is dead.
    seen: Mutex<HashMap<[u8; 32], i64>>,
}

/// Bound on retained replay tuples. At the default 60 s window this admits
/// ~1000 verified requests/second before the opportunistic prune has to work;
/// on overflow expired entries are pruned and, if still full, the set is
/// cleared (a brief protection gap, never a false rejection).
const MAX_REPLAY_ENTRIES: usize = 65_536;

impl ReplayGuard {
    pub fn new() -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Record the tuple; `true` when it was already present (a replay).
    fn check_and_insert(&self, tuple_hash: [u8; 32], created: i64, window_secs: u64) -> bool {
        let now = now_unix() as i64;
        let expiry = created.saturating_add(window_secs as i64);
        let Ok(mut seen) = self.seen.lock() else {
            // A poisoned lock fails open on replay detection rather than
            // rejecting all traffic; the signature itself was already valid.
            return false;
        };
        if let Some(exp) = seen.get(&tuple_hash)
            && *exp >= now
        {
            return true;
        }
        if seen.len() >= MAX_REPLAY_ENTRIES {
            seen.retain(|_, exp| *exp >= now);
            if seen.len() >= MAX_REPLAY_ENTRIES {
                seen.clear();
            }
        }
        seen.insert(tuple_hash, expiry);
        false
    }
}

impl Default for ReplayGuard {
    fn default() -> Self {
        Self::new()
    }
}

/// Run the full inbound verification for one request.
///
/// `authority` is the already-canonicalized `@authority` (see
/// [`canonical_authority`]); `path`/`query` are split from the request target.
/// `replay` is present when the operator enabled replay protection.
#[allow(clippy::too_many_arguments)]
pub fn verify(
    headers: &[(String, String)],
    method: &str,
    authority: &str,
    path: &str,
    query: &str,
    cfg: &AauthConfig,
    keys: &dyn KeyResolver,
    replay: Option<&ReplayGuard>,
) -> Outcome {
    // Fast path: a caller presenting none of the three signature headers is not
    // an AAuth client — fall through rather than reject.
    let has_any_sig = headers.iter().any(|(n, _)| {
        n.eq_ignore_ascii_case(H_SIG_INPUT)
            || n.eq_ignore_ascii_case(H_SIG)
            || n.eq_ignore_ascii_case(H_SIG_KEY)
    });
    if !has_any_sig {
        return Outcome::NoCredential;
    }

    if authority.is_empty() {
        return Outcome::Rejected(SigError::new(
            SigErrorCode::InvalidRequest,
            "missing Host / @authority to verify the signature against",
        ));
    }

    // RFC 9421 header lookup: case-insensitive name, OWS-trimmed values,
    // multiple field lines comma-joined.
    let header = |name: &str| -> Option<String> {
        let mut vals: Vec<&str> = Vec::new();
        for (n, v) in headers {
            if n.eq_ignore_ascii_case(name) {
                vals.push(v.trim());
            }
        }
        if vals.is_empty() {
            None
        } else {
            Some(vals.join(", "))
        }
    };

    let parts = RequestParts {
        method,
        authority,
        path,
        query,
        header: &header,
    };
    let policy = VerifyPolicy {
        now: now_unix(),
        window_secs: cfg.signature_window_secs,
        // Beyond the mandatory @method/@authority/@path/signature-key, operators
        // may require the signature to also cover e.g. `@query` / `content-digest`.
        extra_required: cfg.additional_covered_components.clone(),
    };

    // (1) Parse + structurally validate the three headers, enforce covered
    // components + the `created` window, and build the signature base.
    let parsed = match sig::parse_request_signature(&parts, &policy) {
        Ok(p) => p,
        Err(e) => return Outcome::Rejected(e),
    };

    // (2) AAuth requires the `jwt` Signature-Key scheme; anything else —
    // implemented elsewhere or not — is refused on the draft's defined path:
    // `unsupported_scheme`, with `Accept-Signature-Scheme: jwt` naming what
    // would succeed (the plugin surfaces that header via the gateway).
    let token = match &parsed.scheme {
        SigKeyScheme::Jwt(t) => t.clone(),
        _ => {
            return Outcome::Rejected(SigError::new(
                SigErrorCode::UnsupportedScheme,
                "AAuth requires the `jwt` Signature-Key scheme (an agent or person token)",
            ));
        }
    };

    // (3) Decode (no crypto yet) to learn typ / iss / dwk / kid.
    let decoded = match jwt::decode(&token) {
        Ok(d) => d,
        Err(e) => {
            return Outcome::Rejected(SigError::new(
                SigErrorCode::InvalidJwt,
                format!("malformed AAuth token: {e:?}"),
            ));
        }
    };
    // A fully-specified `alg` is REQUIRED; `none`, the polymorphic `EdDSA`,
    // and symmetric algorithms MUST NOT be accepted. Gated here, ahead of the
    // metadata/JWKS fetch, so a token that can never verify cannot drive
    // outbound requests at the issuer it names, and so the rejection carries
    // the draft's `unsupported_algorithm` rather than being flattened into a
    // signature failure after a wasted refresh.
    if let Err(e) = jwt::check_alg(&decoded.header.alg) {
        return Outcome::Rejected(SigError::new(
            SigErrorCode::UnsupportedAlgorithm,
            format!("token `alg`: {e}"),
        ));
    }

    // (4) Branch on the token type. Only `typ` distinguishes the credential
    // families, and the spec is explicit that a recipient MUST check it —
    // an `aa-person+jwt` where an agent token is expected (or vice versa)
    // fails open at verifiers that skip this.
    let typ = decoded.header.typ.as_deref().unwrap_or_default();
    match typ {
        tokens::TYP_AGENT => verify_agent(
            &decoded, &parsed, method, authority, path, cfg, keys, replay,
        ),
        tokens::TYP_PERSON if cfg.person_tokens.enabled => verify_person(
            &decoded, &parsed, method, authority, path, cfg, keys, replay,
        ),
        tokens::TYP_PERSON => Outcome::Rejected(SigError::new(
            SigErrorCode::InvalidJwt,
            "person tokens are not accepted by this resource (person_tokens.enabled is off)",
        )),
        tokens::TYP_AUTH if cfg.auth_tokens.enabled => verify_auth(
            &decoded, &parsed, method, authority, path, cfg, keys, replay,
        ),
        tokens::TYP_AUTH => Outcome::Rejected(SigError::new(
            SigErrorCode::InvalidJwt,
            "auth tokens are not accepted by this resource (auth_tokens.enabled is off)",
        )),
        other => Outcome::Rejected(SigError::new(
            SigErrorCode::InvalidJwt,
            format!(
                "unsupported Signature-Key JWT typ '{other}' (expected {}, {} or {})",
                tokens::TYP_AGENT,
                tokens::TYP_PERSON,
                tokens::TYP_AUTH
            ),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_auth(
    decoded: &jwt::DecodedJwt,
    parsed: &sig::ParsedSignature,
    method: &str,
    authority: &str,
    path: &str,
    cfg: &AauthConfig,
    keys: &dyn KeyResolver,
    replay: Option<&ReplayGuard>,
) -> Outcome {
    let (iss, kid) = match issuer_and_kid(decoded, "auth token") {
        Ok(v) => v,
        Err(e) => return Outcome::Rejected(e),
    };

    // Who may grant access here: a trusted PS asserting identity and consent
    // (three-party) or an Access Server this resource delegated policy to
    // (four-party). The issuer decides which discovery document verifies it.
    let dwk = if cfg.person_tokens.ps_trusted(&iss) {
        PERSON_DWK
    } else if cfg.auth_tokens.as_trusted(&iss) {
        ACCESS_DWK
    } else {
        return Outcome::Rejected(SigError::new(
            SigErrorCode::InvalidKey,
            format!(
                "auth-token issuer '{iss}' is neither a trusted person server nor a trusted \
                 access server"
            ),
        ));
    };
    if validate_server_identifier(&iss, cfg.insecure_dev_mode).is_err() {
        return Outcome::Rejected(SigError::new(
            SigErrorCode::InvalidKey,
            format!("auth-token issuer '{iss}' is not a valid AAuth server identifier"),
        ));
    }
    if let Err(e) = require_dwk(decoded, dwk, "auth token") {
        return Outcome::Rejected(e);
    }
    if let Err(e) = verify_token_signature(decoded, &iss, dwk, &kid, keys) {
        return Outcome::Rejected(e);
    }

    let resource_id = cfg
        .person_tokens
        .resource_identifier
        .as_deref()
        .unwrap_or_default();
    let claims = match tokens::validate_auth_token(
        decoded,
        now_unix(),
        resource_id,
        dwk,
        cfg.insecure_dev_mode,
    ) {
        Ok(c) => c,
        Err(e) => return Outcome::Rejected(claims_error(&e.0, "auth token")),
    };

    if cfg.is_revoked(&claims.iss, &claims.jti) {
        return Outcome::Rejected(SigError::new(
            SigErrorCode::InvalidJwt,
            "auth token is revoked",
        ));
    }

    if let Err(e) = sig::verify_parsed(parsed, &claims.cnf.jwk) {
        return Outcome::Rejected(e);
    }

    if let Some(guard) = replay
        && let Outcome::Rejected(e) = check_replay(
            guard,
            &claims.cnf.jwk,
            parsed.created,
            method,
            authority,
            path,
            cfg.signature_window_secs,
        )
    {
        return Outcome::Rejected(e);
    }

    Outcome::Verified(Box::new(VerifiedIdentity::Auth(claims)))
}

#[allow(clippy::too_many_arguments)]
fn verify_agent(
    decoded: &jwt::DecodedJwt,
    parsed: &sig::ParsedSignature,
    method: &str,
    authority: &str,
    path: &str,
    cfg: &AauthConfig,
    keys: &dyn KeyResolver,
    replay: Option<&ReplayGuard>,
) -> Outcome {
    let (iss, kid) = match issuer_and_kid(decoded, "agent token") {
        Ok(v) => v,
        Err(e) => return Outcome::Rejected(e),
    };

    // Trust policy over the issuing AP, and a server-identifier shape check
    // before any fetch (the only shape gate when `allow_any_issuer` is set).
    if !cfg.issuer_trusted(&iss) {
        return Outcome::Rejected(SigError::new(
            SigErrorCode::InvalidKey,
            format!("issuer '{iss}' is not in the trusted Agent-Provider allow-list"),
        ));
    }
    if validate_server_identifier(&iss, cfg.insecure_dev_mode).is_err() {
        return Outcome::Rejected(SigError::new(
            SigErrorCode::InvalidKey,
            format!("issuer '{iss}' is not a valid AAuth server identifier"),
        ));
    }
    if let Err(e) = require_dwk(decoded, AGENT_DWK, "agent token") {
        return Outcome::Rejected(e);
    }
    if let Err(e) = verify_token_signature(decoded, &iss, AGENT_DWK, &kid, keys) {
        return Outcome::Rejected(e);
    }

    // Structural + temporal validation (typ / dwk / iss / sub / exp / iat /
    // cnf.jwk). The signature was already checked above.
    let claims = match tokens::validate_agent_token(decoded, now_unix(), cfg.insecure_dev_mode) {
        Ok(c) => c,
        Err(e) => return Outcome::Rejected(claims_error(&e.0, "agent token")),
    };

    // Enforce the AAuth agent-token lifetime ceiling even if a (trusted) AP
    // over-issues: bounds the impersonation window should the agent's `cnf`
    // private key later leak. `validate_agent_token` only checks `exp > now`.
    if claims.exp.saturating_sub(claims.iat) > tokens::AGENT_TOKEN_MAX_TTL_SECS {
        return Outcome::Rejected(SigError::new(
            SigErrorCode::InvalidJwt,
            format!(
                "agent token lifetime exceeds the {}s ceiling",
                tokens::AGENT_TOKEN_MAX_TTL_SECS
            ),
        ));
    }

    if cfg.is_revoked(&claims.iss, &claims.jti) {
        return Outcome::Rejected(SigError::new(
            SigErrorCode::InvalidJwt,
            "agent token is revoked",
        ));
    }

    // Proof of possession: the request's RFC 9421 signature MUST verify
    // under the token's confirmation key.
    if let Err(e) = sig::verify_parsed(parsed, &claims.cnf.jwk) {
        return Outcome::Rejected(e);
    }

    if let Some(guard) = replay
        && let Outcome::Rejected(e) = check_replay(
            guard,
            &claims.cnf.jwk,
            parsed.created,
            method,
            authority,
            path,
            cfg.signature_window_secs,
        )
    {
        return Outcome::Rejected(e);
    }

    Outcome::Verified(Box::new(VerifiedIdentity::Agent(claims)))
}

#[allow(clippy::too_many_arguments)]
fn verify_person(
    decoded: &jwt::DecodedJwt,
    parsed: &sig::ParsedSignature,
    method: &str,
    authority: &str,
    path: &str,
    cfg: &AauthConfig,
    keys: &dyn KeyResolver,
    replay: Option<&ReplayGuard>,
) -> Outcome {
    let (iss, kid) = match issuer_and_kid(decoded, "person token") {
        Ok(v) => v,
        Err(e) => return Outcome::Rejected(e),
    };

    // A PS asserts WHO the person is, so its trust list is explicit-only.
    if !cfg.person_tokens.ps_trusted(&iss) {
        return Outcome::Rejected(SigError::new(
            SigErrorCode::InvalidKey,
            format!("person server '{iss}' is not in the trusted_person_servers allow-list"),
        ));
    }
    if validate_server_identifier(&iss, cfg.insecure_dev_mode).is_err() {
        return Outcome::Rejected(SigError::new(
            SigErrorCode::InvalidKey,
            format!("person server '{iss}' is not a valid AAuth server identifier"),
        ));
    }
    if let Err(e) = require_dwk(decoded, PERSON_DWK, "person token") {
        return Outcome::Rejected(e);
    }
    if let Err(e) = verify_token_signature(decoded, &iss, PERSON_DWK, &kid, keys) {
        return Outcome::Rejected(e);
    }

    let resource_id = cfg
        .person_tokens
        .resource_identifier
        .as_deref()
        .unwrap_or_default();
    let claims = match tokens::validate_person_token(
        decoded,
        now_unix(),
        resource_id,
        cfg.insecure_dev_mode,
    ) {
        Ok(c) => c,
        Err(e) => return Outcome::Rejected(claims_error(&e.0, "person token")),
    };

    if cfg.is_revoked(&claims.iss, &claims.jti) {
        return Outcome::Rejected(SigError::new(
            SigErrorCode::InvalidJwt,
            "person token is revoked",
        ));
    }

    if let Err(e) = sig::verify_parsed(parsed, &claims.cnf.jwk) {
        return Outcome::Rejected(e);
    }

    if let Some(guard) = replay
        && let Outcome::Rejected(e) = check_replay(
            guard,
            &claims.cnf.jwk,
            parsed.created,
            method,
            authority,
            path,
            cfg.signature_window_secs,
        )
    {
        return Outcome::Rejected(e);
    }

    Outcome::Verified(Box::new(VerifiedIdentity::Person(claims)))
}

/// Extract `iss` (payload) and `kid` (JOSE header) from a decoded token.
fn issuer_and_kid(decoded: &jwt::DecodedJwt, what: &str) -> Result<(String, String), SigError> {
    let iss = decoded
        .payload
        .get("iss")
        .and_then(|v| v.as_str())
        .ok_or_else(|| SigError::new(SigErrorCode::InvalidJwt, format!("{what} has no `iss`")))?
        .to_string();
    let kid = decoded
        .header
        .kid
        .as_deref()
        .ok_or_else(|| {
            SigError::new(
                SigErrorCode::InvalidJwt,
                format!("{what} header has no `kid`"),
            )
        })?
        .to_string();
    Ok((iss, kid))
}

/// Pin the well-known document name BEFORE the metadata fetch. Token types
/// fix their `dwk`, and enforcing it here also stops a hostile value from
/// path-injecting the metadata URL.
fn require_dwk(decoded: &jwt::DecodedJwt, expected: &str, what: &str) -> Result<(), SigError> {
    let dwk = decoded
        .payload
        .get("dwk")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if dwk != expected {
        return Err(SigError::new(
            SigErrorCode::InvalidJwt,
            format!("{what} `dwk` must be '{expected}', got '{dwk}'"),
        ));
    }
    Ok(())
}

/// Resolve the issuer's verifying key (egress-admitted, cached) and verify
/// the token signature, refreshing once on a same-kid failure (silent
/// re-key). Key-level failures keep their draft error codes instead of being
/// flattened into a generic signature failure.
fn verify_token_signature(
    decoded: &jwt::DecodedJwt,
    iss: &str,
    dwk: &str,
    kid: &str,
    keys: &dyn KeyResolver,
) -> Result<(), SigError> {
    let issuer_key = keys.get_key(iss, dwk, kid)?;
    match jwt::verify_with_jwk(decoded, &issuer_key) {
        Ok(()) => Ok(()),
        Err(_) => {
            let refreshed = keys.refresh_and_get(iss, dwk, kid)?;
            jwt::verify_with_jwk(decoded, &refreshed).map_err(|e| match e {
                jwt::JwtError::KeyMissingAlg
                | jwt::JwtError::UnsupportedAlgorithm
                | jwt::JwtError::UnimplementedAlgorithmEd448 => SigError::new(
                    SigErrorCode::UnsupportedAlgorithm,
                    format!("issuer key: {e}"),
                ),
                jwt::JwtError::InconsistentKey => {
                    SigError::new(SigErrorCode::InvalidKey, format!("issuer key: {e}"))
                }
                other => SigError::new(
                    SigErrorCode::InvalidJwt,
                    format!("token signature invalid: {other:?}"),
                ),
            })
        }
    }
}

/// Map a claims-validation failure onto the wire error codes.
fn claims_error(detail: &str, what: &str) -> SigError {
    let code = if detail.contains("expired") {
        SigErrorCode::ExpiredJwt
    } else {
        SigErrorCode::InvalidJwt
    };
    SigError::new(code, format!("{what} rejected: {detail}"))
}

/// The spec's replay tuple: reject a duplicate
/// `(key thumbprint, created, @method, @authority, @path)` within the window.
fn check_replay(
    guard: &ReplayGuard,
    cnf_jwk: &Jwk,
    created: i64,
    method: &str,
    authority: &str,
    path: &str,
    window_secs: u64,
) -> Outcome {
    let thumb = cnf_jwk.thumbprint().unwrap_or_default();
    let mut hasher = Sha256::new();
    for part in [thumb.as_str(), method, authority, path] {
        hasher.update(part.as_bytes());
        hasher.update([0u8]);
    }
    hasher.update(created.to_be_bytes());
    let tuple: [u8; 32] = hasher.finalize().into();
    if guard.check_and_insert(tuple, created, window_secs) {
        return Outcome::Rejected(SigError::new(
            SigErrorCode::InvalidSignature,
            "replayed signature: identical (key, created, method, authority, path) tuple \
             already accepted inside the signature window",
        ));
    }
    Outcome::NoCredential
}

/// Derive the RFC 9421 `@authority` value from a `Host` header (or an operator
/// override): lowercase, with the scheme's default port elided.
pub fn canonical_authority(host_value: &str) -> String {
    let lowered = host_value.trim().to_ascii_lowercase();
    // Elide the https default port; keep any non-default port.
    lowered
        .strip_suffix(":443")
        .map(|h| h.to_string())
        .unwrap_or(lowered)
}
