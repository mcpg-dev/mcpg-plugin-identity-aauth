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
    verifier::verify(
        &s.headers,
        method,
        AUTHORITY,
        path,
        "",
        cfg,
        &s.resolver,
        None,
    )
}

/// Unwrap a verified AGENT identity or panic with the rejection detail.
fn expect_agent(out: Outcome) -> crate::aauth::tokens::AgentTokenClaims {
    match out {
        Outcome::Verified(v) => match *v {
            verifier::VerifiedIdentity::Agent(claims) => claims,
            other => panic!("expected agent, got {}", identity_kind(&other)),
        },
        Outcome::Rejected(e) => panic!("expected verified, got {}: {}", e.code.as_str(), e.detail),
        Outcome::NoCredential => panic!("expected verified, got no-credential"),
    }
}

#[test]
fn happy_path_verifies_and_maps_sub() {
    let s = valid("POST", "/mcp");
    let claims = expect_agent(run(&s, "POST", "/mcp", &cfg()));
    assert_eq!(claims.sub, SUB);
    assert_eq!(claims.iss, ISS);
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
        None,
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
fn non_jwt_scheme_rejected_as_unsupported_scheme() {
    // AAuth fixes `scheme=jwt`; a signed request presenting the `hwk`
    // (inline key) scheme is refused on the draft's defined path —
    // `unsupported_scheme`, the code that pairs with an
    // `Accept-Signature-Scheme: jwt` recovery hint.
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
        Outcome::Rejected(e) => assert_eq!(e.code.as_str(), "unsupported_scheme"),
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
    assert_eq!(expect_agent(run(&s, "POST", "/mcp", &cfg())).sub, SUB);
}

/// -10 §5.2.2 / signature-key-08 §3.3: `none`, the polymorphic `EdDSA`, and
/// symmetric algorithms MUST NOT be accepted — regardless of whether the bytes
/// underneath happen to be a good Ed25519 signature. The rejection reports the
/// draft's `unsupported_algorithm`, and happens before any JWKS fetch.
///
/// `ES256` is different: it clears the early gate (it is a supported
/// algorithm), but a token claiming it over an Ed25519 issuer key is refused
/// at signature verification for the header/key disagreement — same wire
/// code, later stage.
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

// ---------------------------------------------------------------------------
// Person tokens (person-identity access mode, opt-in)
// ---------------------------------------------------------------------------

const PS_ISS: &str = "https://ps.example";
const RESOURCE_ID: &str = "https://gw.example";

fn person_cfg() -> AauthConfig {
    AauthConfig::parse(
        &serde_json::json!({
            "trusted_issuers": [ISS],
            "person_tokens": {
                "enabled": true,
                "resource_identifier": RESOURCE_ID,
                "trusted_person_servers": [PS_ISS],
            }
        })
        .to_string(),
    )
    .unwrap()
}

/// Mint a PS identity and a person token bound to a fresh agent key, then
/// sign a real request with that key. `mutate` edits the claims before the
/// PS signs, so tamper cases deviate from the valid shape.
fn sign_person_request(
    aud: &str,
    lifetime: i64,
    mutate: impl FnOnce(&mut serde_json::Value),
) -> Signed {
    let ps_key: SigningKey = generate_signing_key();
    let mut ps_jwk = Jwk::from_verifying_key(&ps_key.verifying_key());
    ps_jwk.kid = Some("ps1".into());
    let agent_key: SigningKey = generate_signing_key();
    let agent_jwk = Jwk::from_verifying_key(&agent_key.verifying_key());

    let now = now_unix() as i64;
    let mut payload = serde_json::json!({
        "iss": PS_ISS,
        "dwk": "aauth-person.json",
        "aud": aud,
        "sub": "8f14e45fceea167a5a36dedd4bea2543",
        "cnf": { "jwk": agent_jwk },
        "jti": "pt-1",
        "iat": now,
        "exp": now + lifetime,
    });
    mutate(&mut payload);
    let token = jwt::sign(
        crate::aauth::tokens::TYP_PERSON,
        Some("ps1"),
        None,
        &payload,
        &ps_key,
    );

    let lookup = |_: &str| None;
    let SignedHeaders {
        signature_input,
        signature,
        signature_key,
    } = sign_request(
        "POST",
        AUTHORITY,
        "/mcp",
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
        resolver: StaticKeyResolver { key: ps_jwk },
    }
}

fn expect_person(out: Outcome) -> crate::aauth::tokens::PersonTokenClaims {
    match out {
        Outcome::Verified(v) => match *v {
            verifier::VerifiedIdentity::Person(claims) => claims,
            other => panic!("expected person, got {}", identity_kind(&other)),
        },
        Outcome::Rejected(e) => panic!("expected verified, got {}: {}", e.code.as_str(), e.detail),
        Outcome::NoCredential => panic!("expected verified, got no-credential"),
    }
}

#[test]
fn person_token_happy_path() {
    let s = sign_person_request(RESOURCE_ID, 1800, |c| {
        c["mission_s256"] = serde_json::json!("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        c["tenant"] = serde_json::json!("corp");
    });
    let claims = expect_person(run(&s, "POST", "/mcp", &person_cfg()));
    assert_eq!(claims.iss, PS_ISS);
    assert_eq!(claims.aud, RESOURCE_ID);
    assert_eq!(
        claims.mission_s256.as_deref(),
        Some("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
    );
    assert_eq!(claims.tenant.as_deref(), Some("corp"));
}

/// Only `typ` distinguishes a person token; a resource that has not opted in
/// MUST reject it rather than fail open (the spec calls this case out).
#[test]
fn person_token_rejected_when_mode_is_off() {
    let s = sign_person_request(RESOURCE_ID, 1800, |_| {});
    match run(&s, "POST", "/mcp", &cfg()) {
        Outcome::Rejected(e) => {
            assert_eq!(e.code.as_str(), "invalid_jwt");
            assert!(e.detail.contains("not accepted"), "detail: {}", e.detail);
        }
        other => panic!("expected rejection, got {}", outcome_name(&other)),
    }
}

/// `aud` names the one resource the PS issued the token for; presenting it at
/// a different resource is refused.
#[test]
fn person_token_wrong_aud_rejected() {
    let s = sign_person_request("https://other.example", 1800, |_| {});
    match run(&s, "POST", "/mcp", &person_cfg()) {
        Outcome::Rejected(e) => {
            assert_eq!(e.code.as_str(), "invalid_jwt");
            assert!(e.detail.contains("aud"), "detail: {}", e.detail);
        }
        other => panic!("expected rejection, got {}", outcome_name(&other)),
    }
}

/// A PS asserts WHO the person is; the trust list is explicit-only.
#[test]
fn person_token_from_untrusted_ps_rejected() {
    let mut cfg = person_cfg();
    cfg.person_tokens.trusted_person_servers = vec!["https://elsewhere.example".to_owned()];
    let s = sign_person_request(RESOURCE_ID, 1800, |_| {});
    match run(&s, "POST", "/mcp", &cfg) {
        Outcome::Rejected(e) => assert_eq!(e.code.as_str(), "invalid_key"),
        other => panic!("expected rejection, got {}", outcome_name(&other)),
    }
}

/// A person token MUST NOT contain `scope` or `account` — identity only, and
/// only `typ` separates it from an auth token.
#[test]
fn person_token_with_forbidden_scope_claim_rejected() {
    let s = sign_person_request(RESOURCE_ID, 1800, |c| {
        c["scope"] = serde_json::json!("data.read");
    });
    match run(&s, "POST", "/mcp", &person_cfg()) {
        Outcome::Rejected(e) => {
            assert!(e.detail.contains("scope"), "detail: {}", e.detail);
        }
        other => panic!("expected rejection, got {}", outcome_name(&other)),
    }
}

/// Person tokens MUST NOT live longer than 1 hour.
#[test]
fn person_token_lifetime_over_one_hour_rejected() {
    let s = sign_person_request(RESOURCE_ID, 2 * 3600, |_| {});
    match run(&s, "POST", "/mcp", &person_cfg()) {
        Outcome::Rejected(e) => {
            assert!(e.detail.contains("ceiling"), "detail: {}", e.detail);
        }
        other => panic!("expected rejection, got {}", outcome_name(&other)),
    }
}

/// Agent tokens keep verifying unchanged when person mode is on.
#[test]
fn agent_token_still_verifies_with_person_mode_on() {
    let s = valid("POST", "/mcp");
    assert_eq!(
        expect_agent(run(&s, "POST", "/mcp", &person_cfg())).sub,
        SUB
    );
}

// ---------------------------------------------------------------------------
// Replay protection + revocation
// ---------------------------------------------------------------------------

/// The spec's optional replay cache: an identical
/// `(key, created, method, authority, path)` tuple inside the window is a
/// replay; the same agent re-signing a fresh request is not affected because
/// the guard only fires on the SAME signature tuple.
#[test]
fn replay_guard_rejects_second_presentation() {
    let s = valid("POST", "/mcp");
    let guard = verifier::ReplayGuard::new();
    let cfg = cfg();
    let first = verifier::verify(
        &s.headers,
        "POST",
        AUTHORITY,
        "/mcp",
        "",
        &cfg,
        &s.resolver,
        Some(&guard),
    );
    assert!(matches!(first, Outcome::Verified(_)));
    let second = verifier::verify(
        &s.headers,
        "POST",
        AUTHORITY,
        "/mcp",
        "",
        &cfg,
        &s.resolver,
        Some(&guard),
    );
    match second {
        Outcome::Rejected(e) => {
            assert_eq!(e.code.as_str(), "invalid_signature");
            assert!(e.detail.contains("replayed"), "detail: {}", e.detail);
        }
        other => panic!("expected replay rejection, got {}", outcome_name(&other)),
    }
}

/// Without the guard (default), the same request verifies repeatedly.
#[test]
fn replay_allowed_when_protection_off() {
    let s = valid("POST", "/mcp");
    let cfg = cfg();
    for _ in 0..2 {
        assert!(matches!(
            run(&s, "POST", "/mcp", &cfg),
            Outcome::Verified(_)
        ));
    }
}

/// `(iss, jti)` — the pair AAuth keys revocation by — refuses an otherwise
/// valid token.
#[test]
fn revoked_token_rejected() {
    let mut cfg = cfg();
    cfg.revoked_tokens = vec![crate::config::RevokedToken {
        iss: ISS.to_owned(),
        jti: "jti-1".to_owned(),
    }];
    let s = valid("POST", "/mcp");
    match run(&s, "POST", "/mcp", &cfg) {
        Outcome::Rejected(e) => assert!(e.detail.contains("revoked"), "detail: {}", e.detail),
        other => panic!("expected rejection, got {}", outcome_name(&other)),
    }
    // A different jti under the same issuer is unaffected.
    cfg.revoked_tokens[0].jti = "other".to_owned();
    assert!(matches!(
        run(&s, "POST", "/mcp", &cfg),
        Outcome::Verified(_)
    ));
}

// ---------------------------------------------------------------------------
// Error → response-header mapping (Signature-Error / Accept-Signature-*)
// ---------------------------------------------------------------------------

#[test]
fn error_headers_carry_signature_error_and_recovery_hints() {
    use crate::aauth::sig::{SigError, SigErrorCode};

    let plain = super::error_response_headers(&SigError::new(
        SigErrorCode::ExpiredJwt,
        "agent token expired",
    ));
    assert_eq!(
        plain,
        vec![("signature-error".to_owned(), "error=expired_jwt".to_owned())]
    );

    let scheme = super::error_response_headers(&SigError::new(
        SigErrorCode::UnsupportedScheme,
        "hwk is not AAuth",
    ));
    assert!(scheme.contains(&(
        "signature-error".to_owned(),
        "error=unsupported_scheme".to_owned()
    )));
    assert!(scheme.contains(&("accept-signature-scheme".to_owned(), "jwt".to_owned())));

    let alg = super::error_response_headers(&SigError::new(
        SigErrorCode::UnsupportedAlgorithm,
        "EdDSA is polymorphic",
    ));
    assert!(alg.contains(&(
        "accept-signature-alg".to_owned(),
        "Ed25519, ES256".to_owned()
    )));

    let mut with_input = SigError::new(SigErrorCode::InvalidInput, "missing components");
    with_input.required_input = Some(vec!["@method".to_owned(), "signature-key".to_owned()]);
    let headers = super::error_response_headers(&with_input);
    assert_eq!(
        headers[0].1,
        "error=invalid_input, required_input=(\"@method\" \"signature-key\")"
    );
}

// ---------------------------------------------------------------------------
// Auth tokens (PS-authorization access mode, opt-in)
// ---------------------------------------------------------------------------

fn auth_cfg() -> AauthConfig {
    AauthConfig::parse(
        &serde_json::json!({
            "trusted_issuers": [ISS],
            "person_tokens": {
                "enabled": true,
                "resource_identifier": RESOURCE_ID,
                "trusted_person_servers": [PS_ISS],
            },
            "auth_tokens": { "enabled": true }
        })
        .to_string(),
    )
    .unwrap()
}

/// Mint a PS-issued auth token bound to a fresh agent key and sign a request
/// with it. `mutate` edits the claims before the PS signs.
fn sign_auth_request(mutate: impl FnOnce(&mut serde_json::Value)) -> Signed {
    let ps_key: SigningKey = generate_signing_key();
    let mut ps_jwk = Jwk::from_verifying_key(&ps_key.verifying_key());
    ps_jwk.kid = Some("ps1".into());
    let agent_key: SigningKey = generate_signing_key();
    let agent_jwk = Jwk::from_verifying_key(&agent_key.verifying_key());

    let now = now_unix() as i64;
    let mut payload = serde_json::json!({
        "iss": PS_ISS,
        "dwk": "aauth-person.json",
        "aud": RESOURCE_ID,
        "jti": "at-1",
        "ps": PS_ISS,
        "sub": "8f14e45fceea167a5a36dedd4bea2543",
        "cnf": { "jwk": agent_jwk },
        "iat": now,
        "exp": now + 900,
        "scope": "tools:read tools:write",
    });
    mutate(&mut payload);
    let token = jwt::sign(
        crate::aauth::tokens::TYP_AUTH,
        Some("ps1"),
        None,
        &payload,
        &ps_key,
    );

    let lookup = |_: &str| None;
    let SignedHeaders {
        signature_input,
        signature,
        signature_key,
    } = sign_request(
        "POST",
        AUTHORITY,
        "/mcp",
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
        resolver: StaticKeyResolver { key: ps_jwk },
    }
}

#[test]
fn auth_token_happy_path_yields_scopes() {
    let s = sign_auth_request(|c| {
        c["account"] = serde_json::json!("ws-42");
    });
    let cfg = auth_cfg();
    match run(&s, "POST", "/mcp", &cfg) {
        Outcome::Verified(v) => match *v {
            verifier::VerifiedIdentity::Auth(claims) => {
                assert_eq!(claims.scopes(), vec!["tools:read", "tools:write"]);
                assert_eq!(claims.account.as_deref(), Some("ws-42"));
                assert_eq!(claims.ps, PS_ISS);
            }
            _ => panic!("expected auth identity"),
        },
        other => panic!("expected verified, got {}", outcome_name(&other)),
    }
}

/// The plugin identity carries the grant as gateway scopes plus the
/// attributes the resource role needs (`agent_jkt`, `exp`, `ps`).
#[test]
fn auth_token_identity_mapping() {
    let s = sign_auth_request(|_| {});
    let plugin = AauthIdentityPlugin::from_config_json(
        &serde_json::json!({
            "trusted_issuers": [ISS],
            "person_tokens": {
                "enabled": true,
                "resource_identifier": RESOURCE_ID,
                "trusted_person_servers": [PS_ISS],
            },
            "auth_tokens": { "enabled": true }
        })
        .to_string(),
    );
    // Drive verify() through the plugin's identity builder using the static
    // resolver seam.
    let out = verifier::verify(
        &s.headers,
        "POST",
        AUTHORITY,
        "/mcp",
        "",
        &plugin.inner.config,
        &s.resolver,
        None,
    );
    let Outcome::Verified(vid) = out else {
        panic!("expected verified")
    };
    let id = super::build_identity(&plugin.inner, *vid);
    assert_eq!(id.scopes, vec!["tools:read", "tools:write"]);
    assert_eq!(id.issuer.as_deref(), Some(PS_ISS));
    assert_eq!(id.attributes["aauth.token_type"], "auth");
    assert_eq!(id.attributes["aauth.ps"], PS_ISS);
    assert_eq!(id.attributes["aauth.jti"], "at-1");
    assert_eq!(
        id.attributes["aauth.agent_jkt"].len(),
        43,
        "base64url SHA-256"
    );
    assert!(id.attributes.contains_key("aauth.exp"));
}

#[test]
fn auth_token_rejected_when_mode_off() {
    let s = sign_auth_request(|_| {});
    // person mode on, auth mode off
    match run(&s, "POST", "/mcp", &person_cfg()) {
        Outcome::Rejected(e) => {
            assert!(
                e.detail.contains("auth_tokens.enabled"),
                "detail: {}",
                e.detail
            );
        }
        other => panic!("expected rejection, got {}", outcome_name(&other)),
    }
}

#[test]
fn auth_token_from_untrusted_issuer_rejected() {
    let s = sign_auth_request(|c| {
        c["iss"] = serde_json::json!("https://rogue.example");
        c["ps"] = serde_json::json!("https://rogue.example");
    });
    match run(&s, "POST", "/mcp", &auth_cfg()) {
        Outcome::Rejected(e) => assert_eq!(e.code.as_str(), "invalid_key"),
        other => panic!("expected rejection, got {}", outcome_name(&other)),
    }
}

#[test]
fn auth_token_wrong_aud_rejected() {
    let s = sign_auth_request(|c| {
        c["aud"] = serde_json::json!("https://other.example");
    });
    match run(&s, "POST", "/mcp", &auth_cfg()) {
        Outcome::Rejected(e) => assert!(e.detail.contains("aud"), "detail: {}", e.detail),
        other => panic!("expected rejection, got {}", outcome_name(&other)),
    }
}

/// `auth_tokens.enabled` without person mode fails closed at load.
#[test]
fn auth_tokens_config_requires_person_mode() {
    assert!(
        AauthConfig::parse(
            &serde_json::json!({
                "trusted_issuers": [ISS],
                "auth_tokens": { "enabled": true }
            })
            .to_string()
        )
        .is_err()
    );
}

/// Person and agent identities also expose `agent_jkt` and `exp` — the
/// resource role mints resource tokens from them.
#[test]
fn person_identity_carries_thumbprint_and_expiry() {
    let s = sign_person_request(RESOURCE_ID, 1800, |_| {});
    let plugin = AauthIdentityPlugin::from_config_json(
        &serde_json::json!({
            "trusted_issuers": [ISS],
            "person_tokens": {
                "enabled": true,
                "resource_identifier": RESOURCE_ID,
                "trusted_person_servers": [PS_ISS],
            }
        })
        .to_string(),
    );
    let out = verifier::verify(
        &s.headers,
        "POST",
        AUTHORITY,
        "/mcp",
        "",
        &plugin.inner.config,
        &s.resolver,
        None,
    );
    let Outcome::Verified(vid) = out else {
        panic!("expected verified")
    };
    let id = super::build_identity(&plugin.inner, *vid);
    assert_eq!(id.attributes["aauth.token_type"], "person");
    assert_eq!(id.attributes["aauth.ps"], PS_ISS);
    assert_eq!(id.attributes["aauth.jti"], "pt-1");
    assert_eq!(id.attributes["aauth.agent_jkt"].len(), 43);
    assert!(id.scopes.is_empty(), "a person token grants no scopes");
}

fn identity_kind(v: &verifier::VerifiedIdentity) -> &'static str {
    match v {
        verifier::VerifiedIdentity::Agent(_) => "agent",
        verifier::VerifiedIdentity::Person(_) => "person",
        verifier::VerifiedIdentity::Auth(_) => "auth",
    }
}
