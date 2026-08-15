//! Verification tests for `dev.mcpg.identity.aauth`.
//!
//! The full crypto path is exercised in-memory via the [`KeyResolver`] seam
//! (no network): each test mints an issuer key + agent key with the vendored
//! `aauth` primitives, signs a real request, and drives `verifier::verify`.

use super::*;
use crate::aauth::jwk::{Jwk, generate_signing_key};
use crate::aauth::sig::{SignedHeaders, sign_request};
use crate::aauth::sigkey::{serialize_hwk, serialize_jwt};
use crate::aauth::tokens::TYP_AGENT;
use crate::aauth::{jwt, now_unix};
use crate::verifier::{self, KeyResolver, Outcome};
use ed25519_dalek::SigningKey;

const ISS: &str = "https://ap.example";
const AUTHORITY: &str = "ap.example";
const SUB: &str = "aauth:k7q3p9n2@ap.example";

/// Returns the issuer's public JWK for any `(iss, dwk, kid)`.
struct StaticKeyResolver {
    key: Jwk,
}
impl KeyResolver for StaticKeyResolver {
    fn get_key(
        &self,
        _iss: &str,
        _dwk: &str,
        _kid: &str,
    ) -> Result<Jwk, crate::aauth::sig::SigError> {
        Ok(self.key.clone())
    }
    fn refresh_and_get(
        &self,
        _iss: &str,
        _dwk: &str,
        _kid: &str,
    ) -> Result<Jwk, crate::aauth::sig::SigError> {
        Ok(self.key.clone())
    }
}

struct Signed {
    headers: Vec<(String, String)>,
    resolver: StaticKeyResolver,
}

/// Mint an issuer + agent identity and sign a real request. `dwk`, `typ`, the
/// token lifetime, and the signing key are parameterized so tamper cases can
/// deviate from the valid path.
#[allow(clippy::too_many_arguments)]
fn sign_request_full(
    method: &str,
    authority: &str,
    path: &str,
    dwk: &str,
    typ: &str,
    sub: &str,
    iat_offset: i64,
    exp_offset: i64,
    use_hwk_scheme: bool,
) -> Signed {
    let issuer_key: SigningKey = generate_signing_key();
    let mut issuer_jwk = Jwk::from_verifying_key(&issuer_key.verifying_key());
    issuer_jwk.kid = Some("k1".into());

    let agent_key: SigningKey = generate_signing_key();
    let agent_jwk = Jwk::from_verifying_key(&agent_key.verifying_key());

    let now = now_unix() as i64;
    let payload = serde_json::json!({
        "iss": ISS,
        "dwk": dwk,
        "sub": sub,
        "jti": "jti-1",
        "cnf": { "jwk": agent_jwk },
        "iat": now + iat_offset,
        "exp": now + exp_offset,
    });
    let token = jwt::sign(typ, Some("k1"), None, &payload, &issuer_key);

    let sig_key_value = if use_hwk_scheme {
        serialize_hwk(&Jwk::from_verifying_key(&agent_key.verifying_key()))
    } else {
        serialize_jwt(&token)
    };
    let lookup = |_: &str| None;
    let SignedHeaders {
        signature_input,
        signature,
        signature_key,
    } = sign_request(
        method,
        authority,
        path,
        "",
        &[],
        &lookup,
        &sig_key_value,
        &agent_key,
        now as u64,
    )
    .expect("sign request");

    let headers = vec![
        ("host".to_string(), authority.to_string()),
        ("signature-input".to_string(), signature_input),
        ("signature".to_string(), signature),
        ("signature-key".to_string(), signature_key),
    ];
    Signed {
        headers,
        resolver: StaticKeyResolver { key: issuer_jwk },
    }
}

/// Mint an agent token with a caller-chosen JOSE `alg` and a caller-chosen
/// `cnf.jwk.alg` (`None` omits the member), then wrap it in a real RFC 9421
/// signed request under the matching agent key. `jwt::sign` deliberately
/// offers no `alg` override, so the JWS is assembled by hand here — the only
/// way to present the forms AAuth -10 forbids.
fn signed_with_algs(alg: &str, cnf_alg: Option<&str>, method: &str, path: &str) -> Signed {
    use ed25519_dalek::Signer;

    let issuer_key: SigningKey = generate_signing_key();
    let mut issuer_jwk = Jwk::from_verifying_key(&issuer_key.verifying_key());
    issuer_jwk.kid = Some("k1".into());
    let agent_key: SigningKey = generate_signing_key();

    let mut cnf_jwk =
        serde_json::to_value(Jwk::from_verifying_key(&agent_key.verifying_key())).unwrap();
    match cnf_alg {
        Some(a) => cnf_jwk["alg"] = serde_json::json!(a),
        None => {
            cnf_jwk.as_object_mut().unwrap().remove("alg");
        }
    }

    let now = now_unix() as i64;
    let header = serde_json::json!({"alg": alg, "typ": TYP_AGENT, "kid": "k1"});
    let payload = serde_json::json!({
        "iss": ISS,
        "dwk": "aauth-agent.json",
        "sub": SUB,
        "jti": "jti-1",
        "cnf": { "jwk": cnf_jwk },
        "iat": now,
        "exp": now + 3600,
    });
    let signing_input = format!(
        "{}.{}",
        crate::aauth::b64::encode(header.to_string().as_bytes()),
        crate::aauth::b64::encode(payload.to_string().as_bytes())
    );
    let sig = issuer_key.sign(signing_input.as_bytes());
    let token = format!(
        "{signing_input}.{}",
        crate::aauth::b64::encode(&sig.to_bytes())
    );

    let lookup = |_: &str| None;
    let SignedHeaders {
        signature_input,
        signature,
        signature_key,
    } = sign_request(
        method,
        AUTHORITY,
        path,
        "",
        &[],
        &lookup,
        &serialize_jwt(&token),
        &agent_key,
        now as u64,
    )
    .expect("sign request");

    Signed {
        headers: vec![
            ("host".to_string(), AUTHORITY.to_string()),
            ("signature-input".to_string(), signature_input),
            ("signature".to_string(), signature),
            ("signature-key".to_string(), signature_key),
        ],
        resolver: StaticKeyResolver { key: issuer_jwk },
    }
}

/// A valid, freshly-signed request.
fn valid(method: &str, path: &str) -> Signed {
    sign_request_full(
        method,
        AUTHORITY,
        path,
        "aauth-agent.json",
        TYP_AGENT,
        SUB,
        0,
        3600,
        false,
    )
}

fn cfg() -> AauthConfig {
    AauthConfig::parse(&serde_json::json!({ "trusted_issuers": [ISS] }).to_string()).unwrap()
}

fn run(s: &Signed, method: &str, path: &str, cfg: &AauthConfig) -> Outcome {
    verifier::verify(&s.headers, method, AUTHORITY, path, "", cfg, &s.resolver)
}

#[test]
fn happy_path_verifies_and_maps_sub() {
    let s = valid("POST", "/mcp");
    match run(&s, "POST", "/mcp", &cfg()) {
        Outcome::Verified(v) => {
            assert_eq!(v.claims.sub, SUB);
            assert_eq!(v.claims.iss, ISS);
        }
        Outcome::Rejected(e) => panic!("expected verified, got {}: {}", e.code.as_str(), e.detail),
        Outcome::NoCredential => panic!("expected verified, got no-credential"),
    }
}

#[test]
fn no_signature_headers_is_no_credential() {
    let headers = vec![("host".to_string(), AUTHORITY.to_string())];
    let out = verifier::verify(
        &headers,
        "POST",
        AUTHORITY,
        "/mcp",
        "",
        &cfg(),
        &StaticKeyResolver {
            key: Jwk::from_verifying_key(&generate_signing_key().verifying_key()),
        },
    );
    assert!(matches!(out, Outcome::NoCredential));
}

#[test]
fn untrusted_issuer_rejected() {
    let s = valid("POST", "/mcp");
    let other = AauthConfig::parse(
        &serde_json::json!({ "trusted_issuers": ["https://evil.example"] }).to_string(),
    )
    .unwrap();
    match run(&s, "POST", "/mcp", &other) {
        Outcome::Rejected(e) => assert_eq!(e.code.as_str(), "invalid_key"),
        other => panic!("expected rejection, got {}", outcome_name(&other)),
    }
}

#[test]
fn tampered_path_rejected() {
    let s = valid("POST", "/mcp");
    // Verify against a different path than was signed.
    match run(&s, "POST", "/admin", &cfg()) {
        Outcome::Rejected(e) => assert_eq!(e.code.as_str(), "invalid_signature"),
        other => panic!("expected rejection, got {}", outcome_name(&other)),
    }
}

#[test]
fn tampered_method_rejected() {
    let s = valid("POST", "/mcp");
    match run(&s, "GET", "/mcp", &cfg()) {
        Outcome::Rejected(e) => assert_eq!(e.code.as_str(), "invalid_signature"),
        other => panic!("expected rejection, got {}", outcome_name(&other)),
    }
}

#[test]
fn expired_token_rejected() {
    let s = sign_request_full(
        "POST",
        AUTHORITY,
        "/mcp",
        "aauth-agent.json",
        TYP_AGENT,
        SUB,
        -7200,
        -3600, // exp in the past
        false,
    );
    match run(&s, "POST", "/mcp", &cfg()) {
        Outcome::Rejected(e) => assert_eq!(e.code.as_str(), "expired_jwt", "detail: {}", e.detail),
        other => panic!("expected rejection, got {}", outcome_name(&other)),
    }
}

#[test]
fn wrong_typ_rejected() {
    let s = sign_request_full(
        "POST",
        AUTHORITY,
        "/mcp",
        "aauth-agent.json",
        "aa-auth+jwt", // not an agent token
        SUB,
        0,
        3600,
        false,
    );
    match run(&s, "POST", "/mcp", &cfg()) {
        Outcome::Rejected(e) => assert_eq!(e.code.as_str(), "invalid_jwt"),
        other => panic!("expected rejection, got {}", outcome_name(&other)),
    }
}

#[test]
fn wrong_dwk_rejected_before_fetch() {
    let s = sign_request_full(
        "POST",
        AUTHORITY,
        "/mcp",
        "../secrets", // hostile dwk (path injection attempt)
        TYP_AGENT,
        SUB,
        0,
        3600,
        false,
    );
    match run(&s, "POST", "/mcp", &cfg()) {
        Outcome::Rejected(e) => {
            assert_eq!(e.code.as_str(), "invalid_jwt");
            assert!(e.detail.contains("dwk"), "detail: {}", e.detail);
        }
        other => panic!("expected rejection, got {}", outcome_name(&other)),
    }
}

#[test]
fn non_jwt_scheme_rejected() {
    // A signed request presenting the `hwk` (inline key) scheme is not a
    // Pattern-A agent-token request.
    let s = sign_request_full(
        "POST",
        AUTHORITY,
        "/mcp",
        "aauth-agent.json",
        TYP_AGENT,
        SUB,
        0,
        3600,
        true, // hwk scheme
    );
    match run(&s, "POST", "/mcp", &cfg()) {
        Outcome::Rejected(e) => assert_eq!(e.code.as_str(), "invalid_key"),
        other => panic!("expected rejection, got {}", outcome_name(&other)),
    }
}

#[test]
fn overlong_token_lifetime_rejected() {
    // exp - iat exceeds the 24h AAuth ceiling (but exp is still in the future).
    let s = sign_request_full(
        "POST",
        AUTHORITY,
        "/mcp",
        "aauth-agent.json",
        TYP_AGENT,
        SUB,
        0,
        25 * 3600, // 25h lifetime
        false,
    );
    match run(&s, "POST", "/mcp", &cfg()) {
        Outcome::Rejected(e) => {
            assert_eq!(e.code.as_str(), "invalid_jwt");
            assert!(e.detail.contains("ceiling"), "detail: {}", e.detail);
        }
        other => panic!("expected rejection, got {}", outcome_name(&other)),
    }
}

/// AAuth -10 §5.2.2: the fully-specified identifier is what a compliant AP
/// emits, and it verifies end to end.
#[test]
fn ed25519_agent_token_accepted() {
    let s = signed_with_algs("Ed25519", Some("Ed25519"), "POST", "/mcp");
    match run(&s, "POST", "/mcp", &cfg()) {
        Outcome::Verified(v) => assert_eq!(v.claims.sub, SUB),
        other => panic!("expected verified, got {}", outcome_name(&other)),
    }
}

/// -10 §5.2.2 / signature-key-08 §3.3: `none`, the polymorphic `EdDSA`, and
/// symmetric algorithms MUST NOT be accepted — regardless of whether the bytes
/// underneath happen to be a good Ed25519 signature. The rejection reports the
/// draft's `unsupported_algorithm`, and happens before any JWKS fetch.
#[test]
fn forbidden_agent_token_algs_rejected() {
    for alg in ["EdDSA", "none", "HS256", "HS512", "RS256", "ES256"] {
        let s = signed_with_algs(alg, Some("Ed25519"), "POST", "/mcp");
        match run(&s, "POST", "/mcp", &cfg()) {
            Outcome::Rejected(e) => assert_eq!(
                e.code.as_str(),
                "unsupported_algorithm",
                "alg {alg} — detail: {}",
                e.detail
            ),
            other => panic!("alg {alg} must be rejected, got {}", outcome_name(&other)),
        }
    }
}

/// `Ed448` is spec-permitted but unimplemented here; the operator-facing reason
/// must say so rather than read as a malformed or badly-signed token.
#[test]
fn ed448_agent_token_reports_unimplemented() {
    let s = signed_with_algs("Ed448", Some("Ed25519"), "POST", "/mcp");
    match run(&s, "POST", "/mcp", &cfg()) {
        Outcome::Rejected(e) => {
            assert_eq!(e.code.as_str(), "unsupported_algorithm");
            assert!(e.detail.contains("Ed448"), "detail: {}", e.detail);
        }
        other => panic!("expected rejection, got {}", outcome_name(&other)),
    }
}

/// -10 §5.2.2: "The JWK MUST carry a fully-specified alg member."
#[test]
fn cnf_jwk_without_fully_specified_alg_rejected() {
    for cnf_alg in [None, Some("EdDSA"), Some("HS256")] {
        let s = signed_with_algs("Ed25519", cnf_alg, "POST", "/mcp");
        match run(&s, "POST", "/mcp", &cfg()) {
            Outcome::Rejected(e) => {
                assert_eq!(e.code.as_str(), "invalid_jwt", "cnf alg {cnf_alg:?}");
                assert!(e.detail.contains("cnf.jwk"), "detail: {}", e.detail);
            }
            other => panic!(
                "cnf alg {cnf_alg:?} must be rejected, got {}",
                outcome_name(&other)
            ),
        }
    }
}

#[test]
fn missing_required_extra_component_rejected() {
    // Operator requires `content-digest` covered; a signature that doesn't cover
    // it is rejected with invalid_input before any token work.
    let s = valid("POST", "/mcp");
    let strict = AauthConfig::parse(
        &serde_json::json!({
            "trusted_issuers": [ISS],
            "additional_covered_components": ["content-digest"],
        })
        .to_string(),
    )
    .unwrap();
    match run(&s, "POST", "/mcp", &strict) {
        Outcome::Rejected(e) => assert_eq!(e.code.as_str(), "invalid_input"),
        other => panic!("expected rejection, got {}", outcome_name(&other)),
    }
}

#[test]
fn plugin_no_credentials_falls_through() {
    // A configured plugin with a request carrying no AAuth headers returns
    // None so other resolvers / anonymous handling apply. Exercises the real
    // plugin (no network — returns before any fetch).
    let plugin = AauthIdentityPlugin::from_config_json(
        &serde_json::json!({ "trusted_issuers": [ISS] }).to_string(),
    );
    let metadata = mcpg_plugin_protocol::types::RequestMetadata {
        transport: "http".into(),
        method: Some("POST".into()),
        path: Some("/mcp".into()),
        ..Default::default()
    };
    let out = SyncIdentityResolver::resolve_identity(
        &plugin,
        &[("host".to_string(), AUTHORITY.to_string())],
        &metadata,
        &serde_json::json!({}),
    );
    assert!(matches!(out, IdentityResolution::None));
}

#[test]
#[should_panic(expected = "security hole")]
fn plugin_fails_closed_on_empty_issuers() {
    // Empty trusted_issuers without allow_any_issuer must refuse to load.
    let _ = AauthIdentityPlugin::from_config_json(&serde_json::json!({}).to_string());
}

fn outcome_name(o: &Outcome) -> String {
    match o {
        Outcome::Verified(_) => "verified".into(),
        Outcome::NoCredential => "no-credential".into(),
        Outcome::Rejected(e) => format!("rejected({})", e.code.as_str()),
    }
}
