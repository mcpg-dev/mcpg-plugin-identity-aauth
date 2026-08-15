//! AAuth Pattern A (identity-based, rung 1) inbound verification.
//!
//! Chains the two cryptographic proofs that make an AAuth request trustworthy:
//! the issuer's JWKS key signs the `aa-agent+jwt` (proving the AP vouches for
//! the agent), and the token's `cnf.jwk` signs the request (proving possession
//! for *this* request). Because `signature-key` is a required covered
//! component, the whole token travels inside the verified signature base — an
//! attacker can neither swap the token nor forge the request.

use crate::aauth::ident::validate_server_identifier;
use crate::aauth::jwk::Jwk;
use crate::aauth::sig::{self, RequestParts, SigError, SigErrorCode, VerifyPolicy};
use crate::aauth::sigkey::SigKeyScheme;
use crate::aauth::tokens::{self, AgentTokenClaims};
use crate::aauth::{jwt, now_unix};
use crate::config::AauthConfig;

/// Resolves an Agent Provider's verifying key for a `(iss, dwk, kid)`. The
/// production impl is the egress-admitted [`crate::jwks::JwksResolver`]; a seam
/// so the verification orchestration is unit-testable without network I/O.
pub trait KeyResolver {
    fn get_key(&self, iss: &str, dwk: &str, kid: &str) -> Result<Jwk, SigError>;
    fn refresh_and_get(&self, iss: &str, dwk: &str, kid: &str) -> Result<Jwk, SigError>;
}

/// The agent-token document name for agent tokens. Fixed by the AAuth profile;
/// asserted before the metadata fetch so it can never be a path-injection
/// vector in `{iss}/.well-known/{dwk}`.
const AGENT_DWK: &str = "aauth-agent.json";

/// Names of the three AAuth signature headers.
const H_SIG_INPUT: &str = "signature-input";
const H_SIG: &str = "signature";
const H_SIG_KEY: &str = "signature-key";

/// What the verifier concluded about a request.
pub enum Outcome {
    /// No AAuth credential presented — let other resolvers/anonymous handle it.
    NoCredential,
    /// A valid, proof-of-possession-bound agent identity. Boxed because the
    /// verified claims are much larger than the other variants.
    Verified(Box<VerifiedIdentity>),
    /// A credential was presented but failed verification.
    Rejected(SigError),
}

/// The cryptographically verified agent identity.
pub struct VerifiedIdentity {
    pub claims: AgentTokenClaims,
}

/// Run the full Pattern A verification for one request.
///
/// `authority` is the already-canonicalized `@authority` (see
/// [`canonical_authority`]); `path`/`query` are split from the request target.
pub fn verify(
    headers: &[(String, String)],
    method: &str,
    authority: &str,
    path: &str,
    query: &str,
    cfg: &AauthConfig,
    keys: &dyn KeyResolver,
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

    // (2) Pattern A requires the `jwt` Signature-Key scheme (an agent token).
    let token = match &parsed.scheme {
        SigKeyScheme::Jwt(t) => t.clone(),
        _ => {
            return Outcome::Rejected(SigError::new(
                SigErrorCode::InvalidKey,
                "Signature-Key must use the `jwt` scheme (agent token) for identity-based access",
            ));
        }
    };

    // (3) Decode (no crypto yet) to learn iss / dwk / kid.
    let decoded = match jwt::decode(&token) {
        Ok(d) => d,
        Err(e) => {
            return Outcome::Rejected(SigError::new(
                SigErrorCode::InvalidJwt,
                format!("malformed agent token: {e:?}"),
            ));
        }
    };
    // AAuth -10 §5.2.2: a fully-specified `alg` is REQUIRED; `none`, the
    // polymorphic `EdDSA`, and symmetric algorithms MUST NOT be accepted.
    // Gated here, ahead of the metadata/JWKS fetch, so a token that can never
    // verify cannot drive outbound requests at the issuer it names, and so the
    // rejection carries the draft's `unsupported_algorithm` rather than being
    // flattened into a signature failure after a wasted refresh.
    if let Err(e) = jwt::check_alg(&decoded.header.alg) {
        return Outcome::Rejected(SigError::new(
            SigErrorCode::UnsupportedAlgorithm,
            format!("agent token `alg`: {e}"),
        ));
    }

    let iss = match decoded.payload.get("iss").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            return Outcome::Rejected(SigError::new(
                SigErrorCode::InvalidJwt,
                "agent token has no `iss`",
            ));
        }
    };
    let dwk = decoded
        .payload
        .get("dwk")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let kid = match decoded.header.kid.as_deref() {
        Some(k) => k.to_string(),
        None => {
            return Outcome::Rejected(SigError::new(
                SigErrorCode::InvalidJwt,
                "agent token header has no `kid`",
            ));
        }
    };

    // (4) Trust policy over the issuing AP, and a server-identifier shape check
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
    // (5) Fix the well-known document name. Agent tokens ALWAYS use
    // `aauth-agent.json`; enforcing it here also stops a hostile `dwk` from
    // path-injecting the metadata URL.
    if dwk != AGENT_DWK {
        return Outcome::Rejected(SigError::new(
            SigErrorCode::InvalidJwt,
            format!("agent token `dwk` must be '{AGENT_DWK}', got '{dwk}'"),
        ));
    }

    // (6) Resolve the issuer's verifying key (egress-admitted, cached), verify
    // the token signature, refreshing once on a same-kid failure (silent re-key).
    let issuer_key = match keys.get_key(&iss, &dwk, &kid) {
        Ok(k) => k,
        Err(e) => return Outcome::Rejected(e),
    };
    let verified_key = match jwt::verify_with_jwk(&decoded, &issuer_key) {
        Ok(()) => issuer_key,
        Err(_) => match keys.refresh_and_get(&iss, &dwk, &kid) {
            Ok(refreshed) => match jwt::verify_with_jwk(&decoded, &refreshed) {
                Ok(()) => refreshed,
                Err(e) => {
                    return Outcome::Rejected(SigError::new(
                        SigErrorCode::InvalidJwt,
                        format!("agent token signature invalid: {e:?}"),
                    ));
                }
            },
            Err(e) => return Outcome::Rejected(e),
        },
    };
    let _ = &verified_key;

    // (7) Structural + temporal validation (typ / dwk / iss / sub / exp / iat /
    // cnf.jwk). The signature was already checked in step 6.
    let claims = match tokens::validate_agent_token(&decoded, now_unix(), cfg.insecure_dev_mode) {
        Ok(c) => c,
        Err(e) => {
            let code = if e.0.contains("expired") {
                SigErrorCode::ExpiredJwt
            } else {
                SigErrorCode::InvalidJwt
            };
            return Outcome::Rejected(SigError::new(
                code,
                format!("agent token rejected: {}", e.0),
            ));
        }
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

    // (8) Proof of possession: the request's RFC 9421 signature MUST verify
    // under the token's confirmation key.
    if let Err(e) = sig::verify_parsed(&parsed, &claims.cnf.jwk) {
        return Outcome::Rejected(e);
    }

    Outcome::Verified(Box::new(VerifiedIdentity { claims }))
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
