//! Egress-admitted Agent-Provider metadata + JWKS resolution with an
//! issuer-keyed cache.
//!
//! The `iss` and `jwks_uri` a request presents come from an attacker-chosen
//! token, so every fetch is SSRF-hardened: HTTPS only, no redirects, the host
//! is resolved up front and refused if *any* address is non-public (rebinding
//! smell), the connection is pinned to the vetted address, and the body is
//! size- and time-capped. The cache keys on `(iss, dwk)` with a ≥1/min fetch
//! floor and a ≤24h ceiling, mirroring the AAuth Agent-Provider profile.

use std::collections::HashMap;
use std::io::Read;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::aauth::ident::host_of;
use crate::aauth::jwk::{Jwk, Jwks};
use crate::aauth::sig::{SigError, SigErrorCode};
use crate::config::JwksConfig;

/// Hard ceiling on distinct cached issuers. With a fixed `trusted_issuers`
/// allow-list this is never approached; it bounds memory under the opt-in
/// `allow_any_issuer` mode where `iss` (the cache key) is attacker-chosen. On
/// overflow the whole map is cleared — correctness is unaffected (a miss just
/// re-fetches, floor-gated).
const MAX_CACHE_ENTRIES: usize = 4096;

/// Immutable egress + admission policy derived from operator config.
#[derive(Debug, Clone)]
pub struct EgressPolicy {
    pub allow_insecure: bool,
    pub timeout: Duration,
    pub max_response_bytes: usize,
    pub cross_origin_hosts: Vec<String>,
}

struct Entry {
    jwks: Jwks,
    fetched_at: Instant,
    /// Effective TTL for this entry: the JWKS response's `Cache-Control`
    /// freshness clamped into `[refresh_floor, max_ttl]`; the configured
    /// ceiling when the endpoint sent no cache headers.
    ttl: Duration,
}

/// Issuer-keyed JWKS cache. Thread-safe: `resolve_identity` runs concurrently.
pub struct JwksResolver {
    policy: EgressPolicy,
    fetch_floor: Duration,
    max_age: Duration,
    entries: Mutex<HashMap<String, Entry>>,
    last_attempt: Mutex<HashMap<String, Instant>>,
}

impl JwksResolver {
    pub fn new(jwks: &JwksConfig, insecure_dev_mode: bool) -> Self {
        Self {
            policy: EgressPolicy {
                allow_insecure: insecure_dev_mode,
                timeout: Duration::from_secs(jwks.fetch_timeout_secs),
                max_response_bytes: jwks.max_response_bytes,
                cross_origin_hosts: jwks.cross_origin_hosts.clone(),
            },
            fetch_floor: Duration::from_secs(jwks.refresh_floor_secs),
            max_age: Duration::from_secs(jwks.max_ttl_secs),
            entries: Mutex::new(HashMap::new()),
            last_attempt: Mutex::new(HashMap::new()),
        }
    }

    /// Resolve the issuer key for `kid`, serving a fresh-cached JWKS when it has
    /// the kid and refreshing (floor-gated) otherwise.
    pub fn get_key(&self, iss: &str, dwk: &str, kid: &str) -> Result<Jwk, SigError> {
        let cache_key = format!("{iss}|{dwk}");
        if let Ok(entries) = self.entries.lock()
            && let Some(entry) = entries.get(&cache_key)
            && entry.fetched_at.elapsed() < entry.ttl
            && let Some(key) = entry.jwks.find(kid)
        {
            return Ok(key);
        }
        self.refresh_key(iss, dwk, kid, &cache_key)
    }

    /// Force a floor-gated refresh, bypassing the cache-hit shortcut. Used for
    /// the single retry after a JWT signature fails under a known kid (silent
    /// issuer re-key).
    pub fn refresh_and_get(&self, iss: &str, dwk: &str, kid: &str) -> Result<Jwk, SigError> {
        let cache_key = format!("{iss}|{dwk}");
        self.refresh_key(iss, dwk, kid, &cache_key)
    }

    fn refresh_key(
        &self,
        iss: &str,
        dwk: &str,
        kid: &str,
        cache_key: &str,
    ) -> Result<Jwk, SigError> {
        // Floor gate — stamped on ATTEMPT (before the fetch), so a failing or
        // slow issuer cannot be hammered.
        {
            let mut attempts = self
                .last_attempt
                .lock()
                .map_err(|_| SigError::new(SigErrorCode::UnknownKey, "jwks cache poisoned"))?;
            if let Some(last) = attempts.get(cache_key)
                && last.elapsed() < self.fetch_floor
            {
                return Err(SigError::new(
                    SigErrorCode::UnknownKey,
                    format!("kid '{kid}' not found for {iss} (fetch floor active)"),
                ));
            }
            if attempts.len() >= MAX_CACHE_ENTRIES && !attempts.contains_key(cache_key) {
                attempts.clear();
            }
            attempts.insert(cache_key.to_string(), Instant::now());
        }

        let (jwks, response_ttl) = self.fetch(iss, dwk)?;
        // SHOULD respect the endpoint's cache headers — inside the floor the
        // per-issuer fetch gate already enforces, and never past the ceiling
        // that guarantees removed keys stop being trusted.
        let ttl = match response_ttl {
            Some(t) => t.clamp(self.fetch_floor, self.max_age),
            None => self.max_age,
        };
        let found = jwks.find(kid);
        let kid_present = jwks.kid_present(kid);
        if let Ok(mut entries) = self.entries.lock() {
            if entries.len() >= MAX_CACHE_ENTRIES && !entries.contains_key(cache_key) {
                entries.clear();
            }
            entries.insert(
                cache_key.to_string(),
                Entry {
                    jwks,
                    fetched_at: Instant::now(),
                    ttl,
                },
            );
        }
        found.ok_or_else(|| {
            if kid_present {
                // The kid exists — as a key type or algorithm this build does
                // not implement. That is a defined decline, not "no such key".
                SigError::new(
                    SigErrorCode::UnsupportedAlgorithm,
                    format!(
                        "kid '{kid}' at {iss} is a key type/algorithm this build does not \
                         implement"
                    ),
                )
            } else {
                SigError::new(
                    SigErrorCode::UnknownKey,
                    format!("kid '{kid}' not in JWKS of {iss}"),
                )
            }
        })
    }

    /// Fetch metadata (`{iss}/.well-known/{dwk}`), assert the document's
    /// `issuer == iss` (host-poisoning defense), admit the `jwks_uri` host
    /// (same-origin or allow-listed), then fetch + parse the JWKS. Returns the
    /// JWKS together with the freshness lifetime its response advertised.
    fn fetch(&self, iss: &str, dwk: &str) -> Result<(Jwks, Option<Duration>), SigError> {
        let meta_url = format!("{iss}/.well-known/{dwk}");
        let (metadata, _) = self
            .get_json(&meta_url)
            .map_err(|e| SigError::new(SigErrorCode::UnknownKey, format!("metadata fetch: {e}")))?;

        let doc_issuer = metadata.get("issuer").and_then(|v| v.as_str());
        match doc_issuer {
            None => {
                return Err(SigError::new(
                    SigErrorCode::IssuerMissing,
                    format!("metadata document at {meta_url} has no `issuer` member"),
                ));
            }
            Some(d) if d != iss => {
                return Err(SigError::new(
                    SigErrorCode::IssuerMismatch,
                    format!(
                        "metadata `issuer` at {meta_url} does not match the identity it was \
                             fetched under"
                    ),
                ));
            }
            Some(_) => {}
        }

        let jwks_uri = metadata
            .get("jwks_uri")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                SigError::new(
                    SigErrorCode::UnknownKey,
                    format!("no jwks_uri in {meta_url}"),
                )
            })?;

        // Cross-origin admission: the JWKS host must equal the issuer host
        // unless explicitly allow-listed.
        let iss_host = host_of(iss);
        let jwks_host = host_of(jwks_uri);
        let admitted = match (&iss_host, &jwks_host) {
            (Some(ih), Some(jh)) if ih == jh => true,
            (_, Some(jh)) => self.policy.cross_origin_hosts.iter().any(|h| h == jh),
            _ => false,
        };
        if !admitted {
            return Err(SigError::new(
                SigErrorCode::InvalidKey,
                format!(
                    "jwks_uri host for {iss} is cross-origin and not admitted \
                     (add it to jwks.cross_origin_hosts to allow)"
                ),
            ));
        }

        let (jwks_val, jwks_ttl) = self
            .get_json(jwks_uri)
            .map_err(|e| SigError::new(SigErrorCode::UnknownKey, format!("jwks fetch: {e}")))?;
        let jwks = serde_json::from_value(jwks_val)
            .map_err(|e| SigError::new(SigErrorCode::InvalidKey, format!("invalid JWKS: {e}")))?;
        Ok((jwks, jwks_ttl))
    }

    /// Egress-admitted `GET` returning parsed JSON plus the response's
    /// `Cache-Control` freshness lifetime (`max-age`, with `no-store` /
    /// `no-cache` reported as zero). Full SSRF checks run on EVERY URL
    /// (metadata and JWKS alike).
    fn get_json(&self, url: &str) -> Result<(serde_json::Value, Option<Duration>), String> {
        let parsed = reqwest::Url::parse(url).map_err(|e| format!("bad URL: {e}"))?;

        match parsed.scheme() {
            "https" => {}
            "http" if self.policy.allow_insecure => {}
            "http" => return Err("plain http egress not allowed".into()),
            other => return Err(format!("unsupported URL scheme '{other}'")),
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err("userinfo in URL rejected".into());
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| "URL has no host".to_string())?
            .to_string();
        let port = parsed
            .port_or_known_default()
            .ok_or_else(|| "URL has no port".to_string())?;

        // Resolve up front, vet every address, pin the connection to the first
        // admissible one. A host that resolves to a mix of public and private
        // addresses is refused outright (rebinding smell).
        let addrs: Vec<SocketAddr> = (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|e| format!("dns resolution of {host} failed: {e}"))?
            .collect();
        if addrs.is_empty() {
            return Err(format!("{host} did not resolve"));
        }
        if !self.policy.allow_insecure && addrs.iter().any(|a| !ip_is_public(a.ip())) {
            return Err(format!("host {host} resolves to a non-public address"));
        }
        let pinned = *addrs
            .iter()
            .find(|a| self.policy.allow_insecure || ip_is_public(a.ip()))
            .ok_or_else(|| format!("no admissible address for {host}"))?;

        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(self.policy.timeout)
            .connect_timeout(self.policy.timeout)
            .https_only(!self.policy.allow_insecure)
            .resolve(&host, pinned)
            .user_agent(concat!("mcpg-identity-aauth/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| format!("client build failed: {e}"))?;

        let resp = client
            .get(parsed)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .map_err(|e| format!("request failed: {e}"))?;

        if resp.status().is_redirection() {
            return Err(format!("redirect from {url} refused"));
        }
        if !resp.status().is_success() {
            return Err(format!("HTTP {} from {url}", resp.status().as_u16()));
        }

        let ttl = resp
            .headers()
            .get(reqwest::header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            .and_then(cache_control_ttl);

        // Hard body cap: read at most max+1 bytes and reject if it overflows.
        let cap = self.policy.max_response_bytes;
        let mut buf = Vec::with_capacity(cap.min(8192));
        let mut limited = resp.take((cap as u64).saturating_add(1));
        limited
            .read_to_end(&mut buf)
            .map_err(|e| format!("read body failed: {e}"))?;
        if buf.len() > cap {
            return Err(format!("response from {url} exceeds {cap} bytes"));
        }

        let value: serde_json::Value =
            serde_json::from_slice(&buf).map_err(|e| format!("invalid JSON from {url}: {e}"))?;
        Ok((value, ttl))
    }
}

/// The freshness lifetime a `Cache-Control` value asks for: `max-age=N`
/// (first occurrence wins), with `no-store` / `no-cache` reported as zero.
/// `None` when the header expresses no freshness policy this cache uses.
fn cache_control_ttl(value: &str) -> Option<Duration> {
    let mut max_age = None;
    for directive in value.split(',') {
        let d = directive.trim();
        if d.eq_ignore_ascii_case("no-store") || d.eq_ignore_ascii_case("no-cache") {
            return Some(Duration::ZERO);
        }
        if max_age.is_none()
            && let Some(v) = d
                .strip_prefix("max-age=")
                .or_else(|| d.strip_prefix("Max-Age="))
                .or_else(|| d.strip_prefix("MAX-AGE="))
            && let Ok(secs) = v.trim().trim_matches('"').parse::<u64>()
        {
            max_age = Some(Duration::from_secs(secs));
        }
    }
    max_age
}

impl crate::verifier::KeyResolver for JwksResolver {
    fn get_key(&self, iss: &str, dwk: &str, kid: &str) -> Result<Jwk, SigError> {
        JwksResolver::get_key(self, iss, dwk, kid)
    }
    fn refresh_and_get(&self, iss: &str, dwk: &str, kid: &str) -> Result<Jwk, SigError> {
        JwksResolver::refresh_and_get(self, iss, dwk, kid)
    }
}

/// Whether an IP may be the target of an egress fetch. Ported from apd's
/// `httpc::ip_is_public`; blocks loopback / private / link-local / CGNAT /
/// documentation / benchmarking / reserved ranges (v4 and v6). IPv4-mapped
/// IPv6 is canonicalized first so it can't slip a private v4 through.
fn ip_is_public(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xC0) == 64) // 100.64.0.0/10 CGNAT
                || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24
                || (o[0] == 198 && (o[1] & 0xFE) == 18) // 198.18.0.0/15 benchmarking
                || o[0] >= 240) // 240.0.0.0/4 reserved
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xFE00) == 0xFC00 // fc00::/7 ULA
                || (s[0] & 0xFFC0) == 0xFE80 // fe80::/10 link-local
                || (s[0] == 0x2001 && s[1] == 0x0DB8) // 2001:db8::/32 documentation
                // Embedded-IPv4 transition ranges: a `to_canonical()` only folds
                // IPv4-*mapped* (::ffff:), so block the others outright — on a
                // NAT64/6to4 network they translate to an IPv4 target and would
                // otherwise smuggle a private v4 (e.g. the metadata endpoint)
                // past the v4 checks.
                || (s[0] == 0x0064 && s[1] == 0xFF9B) // 64:ff9b::/32 NAT64 well-known
                || s[0] == 0x2002 // 2002::/16 6to4
                || (s[0] == 0x2001 && s[1] == 0x0000) // 2001::/32 Teredo
                || (s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0))
            // ::/96 IPv4-compatible (::a.b.c.d); loopback/unspecified already caught
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn private_and_reserved_v4_blocked() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "0.0.0.0",
            "100.64.0.1",
            "192.0.0.1",
            "198.18.0.1",
            "240.0.0.1",
            "203.0.113.7", // documentation
        ] {
            assert!(!ip_is_public(ip.parse().unwrap()), "{ip} must be blocked");
        }
    }

    #[test]
    fn public_v4_allowed() {
        for ip in ["8.8.8.8", "1.1.1.1", "93.184.216.34"] {
            assert!(ip_is_public(ip.parse().unwrap()), "{ip} must be allowed");
        }
    }

    #[test]
    fn v6_ranges() {
        assert!(!ip_is_public(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!ip_is_public("fc00::1".parse().unwrap())); // ULA
        assert!(!ip_is_public("fe80::1".parse().unwrap())); // link-local
        assert!(!ip_is_public("2001:db8::1".parse().unwrap())); // doc
        assert!(ip_is_public("2606:4700:4700::1111".parse().unwrap())); // public
    }

    #[test]
    fn v4_mapped_v6_private_blocked() {
        // ::ffff:10.0.0.1 must be treated as the private v4 it maps to.
        let mapped = IpAddr::V6(Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped());
        assert!(!ip_is_public(mapped));
    }

    #[test]
    fn cache_control_ttl_parsing() {
        assert_eq!(
            cache_control_ttl("max-age=300"),
            Some(Duration::from_secs(300))
        );
        assert_eq!(
            cache_control_ttl("public, max-age=60, must-revalidate"),
            Some(Duration::from_secs(60))
        );
        assert_eq!(cache_control_ttl("no-store"), Some(Duration::ZERO));
        assert_eq!(
            cache_control_ttl("max-age=900, no-cache"),
            Some(Duration::ZERO)
        );
        assert_eq!(cache_control_ttl("private"), None);
        assert_eq!(cache_control_ttl("max-age=nonsense"), None);
    }

    // -- live HTTP path (loopback server, insecure_dev_mode) ---------------

    use crate::aauth::jwk::generate_signing_key;
    use std::io::Write;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Minimal single-threaded HTTP responder: serves canned bodies by path,
    /// counts hits, closes each connection after one response. Runs until the
    /// test process exits (threads are detached; ports are ephemeral).
    struct TestServer {
        base: String,
        hits: Arc<AtomicUsize>,
    }

    fn resolver_for_tests() -> JwksResolver {
        let cfg = JwksConfig {
            cross_origin_hosts: Vec::new(),
            refresh_floor_secs: 60,
            max_ttl_secs: 24 * 3600,
            fetch_timeout_secs: 5,
            max_response_bytes: 4096,
        };
        JwksResolver::new(&cfg, /* insecure_dev_mode */ true)
    }

    fn ed25519_jwks_body(kid: &str) -> (String, crate::aauth::jwk::Jwk) {
        let sk = generate_signing_key();
        let mut jwk = crate::aauth::jwk::Jwk::from_verifying_key(&sk.verifying_key());
        jwk.kid = Some(kid.to_owned());
        let body = serde_json::json!({ "keys": [jwk] }).to_string();
        (body, jwk)
    }

    fn metadata_body(issuer: &str, jwks_uri: &str) -> String {
        serde_json::json!({ "issuer": issuer, "jwks_uri": jwks_uri }).to_string()
    }

    #[test]
    fn http_happy_path_resolves_and_caches() {
        let (jwks_body, expected) = ed25519_jwks_body("k1");
        // One listener: learn the port first, then serve the metadata that
        // names it from the same socket.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let iss = format!("http://{}", listener.local_addr().unwrap());
        let meta = metadata_body(&iss, &format!("{iss}/jwks.json"));
        let hits = Arc::new(AtomicUsize::new(0));
        let hits2 = hits.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut buf = [0u8; 4096];
                let n = std::io::Read::read(&mut stream, &mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let path = req
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/");
                hits2.fetch_add(1, Ordering::SeqCst);
                // The JWKS response advertises a freshness lifetime; the
                // metadata response does not.
                let (extra_header, body) = if path == "/jwks.json" {
                    ("cache-control: max-age=120\r\n", jwks_body.clone())
                } else {
                    ("", meta.clone())
                };
                let resp = format!(
                    "HTTP/1.1 200 X\r\ncontent-length: {}\r\n{extra_header}connection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });

        let resolver = resolver_for_tests();
        let key = resolver
            .get_key(&iss, "aauth-agent.json", "k1")
            .expect("resolves over live HTTP");
        assert_eq!(key.x, expected.x);
        assert_eq!(hits.load(Ordering::SeqCst), 2, "metadata + jwks");

        // Within the (floor-clamped) Cache-Control TTL the cache serves the
        // key without a refetch.
        let again = resolver.get_key(&iss, "aauth-agent.json", "k1").unwrap();
        assert_eq!(again.x, expected.x);
        assert_eq!(hits.load(Ordering::SeqCst), 2, "no additional fetches");
    }

    /// One helper serving the standard two routes with a caller-chosen
    /// metadata body; returns `(issuer_base, hits)`.
    fn standard_server(meta_for_base: impl Fn(&str) -> String, jwks_body: String) -> TestServer {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let base = format!("http://{addr}");
        let meta = meta_for_base(&base);
        let listener = std::net::TcpListener::bind(addr).unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits2 = hits.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut buf = [0u8; 4096];
                let n = std::io::Read::read(&mut stream, &mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let path = req
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_owned();
                hits2.fetch_add(1, Ordering::SeqCst);
                let body = if path == "/.well-known/aauth-agent.json" {
                    meta.clone()
                } else if path == "/jwks.json" {
                    jwks_body.clone()
                } else {
                    "{}".to_owned()
                };
                let resp = format!(
                    "HTTP/1.1 200 X\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        TestServer { base, hits }
    }

    #[test]
    fn http_metadata_issuer_mismatch_rejected() {
        let (jwks_body, _) = ed25519_jwks_body("k1");
        let server = standard_server(
            |base| metadata_body("https://evil.example", &format!("{base}/jwks.json")),
            jwks_body,
        );
        let err = resolver_for_tests()
            .get_key(&server.base, "aauth-agent.json", "k1")
            .unwrap_err();
        assert_eq!(err.code, SigErrorCode::IssuerMismatch);
    }

    #[test]
    fn http_metadata_issuer_missing_rejected() {
        let (jwks_body, _) = ed25519_jwks_body("k1");
        let server = standard_server(
            |base| serde_json::json!({ "jwks_uri": format!("{base}/jwks.json") }).to_string(),
            jwks_body,
        );
        let err = resolver_for_tests()
            .get_key(&server.base, "aauth-agent.json", "k1")
            .unwrap_err();
        assert_eq!(err.code, SigErrorCode::IssuerMissing);
    }

    #[test]
    fn http_metadata_without_jwks_uri_rejected() {
        let server = standard_server(
            |base| serde_json::json!({ "issuer": base }).to_string(),
            "{}".to_owned(),
        );
        let err = resolver_for_tests()
            .get_key(&server.base, "aauth-agent.json", "k1")
            .unwrap_err();
        assert_eq!(err.code, SigErrorCode::UnknownKey);
        assert!(err.detail.contains("jwks_uri"), "detail: {}", err.detail);
    }

    #[test]
    fn http_cross_origin_jwks_requires_admission() {
        // `localhost` and `127.0.0.1` are the same interface but DIFFERENT
        // host strings — exactly the cross-origin case the admission gate
        // polices. The JWKS lives on a second listener bound via the same
        // name resolution the client pins with, so the allow-listed leg
        // connects deterministically whether `localhost` prefers v4 or v6.
        let (jwks_body, expected) = ed25519_jwks_body("k1");
        let jwks_listener = std::net::TcpListener::bind(("localhost", 0)).unwrap();
        let jwks_port = jwks_listener.local_addr().unwrap().port();
        let body = jwks_body.clone();
        std::thread::spawn(move || {
            for stream in jwks_listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut buf = [0u8; 1024];
                let _ = std::io::Read::read(&mut stream, &mut buf);
                let resp = format!(
                    "HTTP/1.1 200 X\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        let server = standard_server(
            |base| metadata_body(base, &format!("http://localhost:{jwks_port}/jwks.json")),
            "{}".to_owned(),
        );
        let err = resolver_for_tests()
            .get_key(&server.base, "aauth-agent.json", "k1")
            .unwrap_err();
        assert_eq!(err.code, SigErrorCode::InvalidKey);
        assert!(
            err.detail.contains("cross-origin"),
            "detail: {}",
            err.detail
        );

        // Allow-listing the JWKS host admits the same fetch.
        let cfg = JwksConfig {
            cross_origin_hosts: vec!["localhost".to_owned()],
            refresh_floor_secs: 60,
            max_ttl_secs: 24 * 3600,
            fetch_timeout_secs: 5,
            max_response_bytes: 4096,
        };
        let resolver = JwksResolver::new(&cfg, true);
        let key = resolver
            .get_key(&server.base, "aauth-agent.json", "k1")
            .expect("allow-listed cross-origin host resolves");
        assert_eq!(key.x, expected.x);
    }

    #[test]
    fn http_kid_of_unsupported_type_reports_unsupported_algorithm() {
        let jwks_body = serde_json::json!({
            "keys": [{ "kty": "RSA", "n": "abc", "e": "AQAB", "kid": "rsa1" }]
        })
        .to_string();
        let server = standard_server(
            |base| metadata_body(base, &format!("{base}/jwks.json")),
            jwks_body,
        );
        let err = resolver_for_tests()
            .get_key(&server.base, "aauth-agent.json", "rsa1")
            .unwrap_err();
        assert_eq!(err.code, SigErrorCode::UnsupportedAlgorithm);
    }

    #[test]
    fn http_unknown_kid_floor_gates_refetch() {
        let (jwks_body, _) = ed25519_jwks_body("k1");
        let server = standard_server(
            |base| metadata_body(base, &format!("{base}/jwks.json")),
            jwks_body,
        );
        let resolver = resolver_for_tests();
        let err = resolver
            .get_key(&server.base, "aauth-agent.json", "missing")
            .unwrap_err();
        assert_eq!(err.code, SigErrorCode::UnknownKey);
        let fetched = server.hits.load(Ordering::SeqCst);
        // A second miss inside the floor must NOT hit the network again.
        let err2 = resolver
            .get_key(&server.base, "aauth-agent.json", "missing")
            .unwrap_err();
        assert_eq!(err2.code, SigErrorCode::UnknownKey);
        assert!(err2.detail.contains("floor"), "detail: {}", err2.detail);
        assert_eq!(server.hits.load(Ordering::SeqCst), fetched);
    }

    #[test]
    fn http_oversized_body_rejected() {
        let (_, jwk) = ed25519_jwks_body("k1");
        let mut padded = serde_json::json!({ "keys": [jwk] });
        padded["pad"] = serde_json::json!("x".repeat(8192));
        let server = standard_server(
            |base| metadata_body(base, &format!("{base}/jwks.json")),
            padded.to_string(),
        );
        let err = resolver_for_tests()
            .get_key(&server.base, "aauth-agent.json", "k1")
            .unwrap_err();
        assert!(err.detail.contains("exceeds"), "detail: {}", err.detail);
    }

    #[test]
    fn http_redirect_refused() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut buf = [0u8; 1024];
                let _ = std::io::Read::read(&mut stream, &mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 302 Found\r\nlocation: http://127.0.0.1:1/\r\ncontent-length: 0\r\n\r\n",
                );
            }
        });
        let err = resolver_for_tests()
            .get_key(&base, "aauth-agent.json", "k1")
            .unwrap_err();
        assert!(
            err.detail.contains("redirect") || err.detail.contains("HTTP 302"),
            "detail: {}",
            err.detail
        );
    }
}
