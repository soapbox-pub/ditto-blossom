//! BUD-11 authorization: a signed kind 24242 Nostr event, base64 in an
//! `Authorization: Nostr …` header.
//!
//! Every check that costs nothing comes before the signature, which costs
//! 36 µs of the 44 µs a header takes. A token whose id has been
//! verified already skips the signature: the id commits to every field, and
//! clients often send one token for `HEAD /upload` and then `PUT /upload`.

use std::num::NonZeroUsize;

use base64::Engine;
use hyper::StatusCode;
use hyper::header::HeaderMap;
use lru::LruCache;
use parking_lot::Mutex;
use secp256k1::{SECP256K1, XOnlyPublicKey, schnorr::Signature};
use serde::Deserialize;

use crate::hash::Hash;

const KIND: u64 = 24242;
/// How far in the future a token's `created_at` may be, for clocks that run
/// ahead.
const CLOCK_SKEW: u64 = 60;
/// The longest header worth decoding.
const MAX_HEADER: usize = 16 << 10;

#[derive(Debug, Clone)]
pub struct Token {
    pub pubkey: [u8; 32],
    /// The `x` tags: the blobs it's for.
    pub x: Vec<Hash>,
}

impl Token {
    pub fn names(&self, hash: &Hash) -> bool {
        self.x.contains(hash)
    }

    /// Whether it's good for `hash`: it names it, or names no blob at all.
    /// BUD-11 asks uploads and deletes to name theirs, but blossom-server
    /// lets a token without `x` tags through, and clients written against it
    /// send them; only mirrors must (as they must there).
    pub fn allows(&self, hash: &Hash) -> bool {
        self.x.is_empty() || self.names(hash)
    }
}

/// Why a request's authorization was refused: the status and `X-Reason`.
pub type Refusal = (StatusCode, &'static str);

const UNAUTHORIZED: StatusCode = StatusCode::UNAUTHORIZED;

#[derive(Deserialize)]
struct Event {
    id: String,
    pubkey: String,
    created_at: u64,
    kind: u64,
    tags: Vec<Vec<String>>,
    content: String,
    sig: String,
}

pub struct Verifier {
    domain: String,
    verified: Mutex<LruCache<[u8; 32], ()>>,
}

impl Verifier {
    pub fn new(domain: String) -> Verifier {
        Verifier {
            domain,
            verified: Mutex::new(LruCache::new(NonZeroUsize::new(4096).expect("non-zero"))),
        }
    }

    /// The token in `headers` for `verb`, if there is one; `Err` if there's
    /// one that isn't valid for it.
    pub fn check(
        &self,
        headers: &HeaderMap,
        verb: &str,
        now: u64,
    ) -> Result<Option<Token>, Refusal> {
        let Some(value) = headers.get(hyper::header::AUTHORIZATION) else {
            return Ok(None);
        };
        let value = value
            .to_str()
            .map_err(|_| (UNAUTHORIZED, "The Authorization header isn't text"))?;
        let (scheme, b64) = value
            .trim()
            .split_once(' ')
            .ok_or((UNAUTHORIZED, "The Authorization header isn't a Nostr token"))?;
        if !scheme.eq_ignore_ascii_case("nostr") {
            return Err((UNAUTHORIZED, "The Authorization header isn't a Nostr token"));
        }
        if b64.len() > MAX_HEADER {
            return Err((UNAUTHORIZED, "The auth token is too long"));
        }
        let json =
            decode_base64(b64.trim()).ok_or((UNAUTHORIZED, "The auth token isn't base64"))?;
        let event: Event = serde_json::from_slice(&json)
            .map_err(|_| (UNAUTHORIZED, "The auth token isn't a Nostr event"))?;
        self.verify(&event, verb, now).map(Some)
    }

    fn verify(&self, ev: &Event, verb: &str, now: u64) -> Result<Token, Refusal> {
        if ev.kind != KIND {
            return Err((UNAUTHORIZED, "The auth token isn't kind 24242"));
        }
        if ev.created_at > now + CLOCK_SKEW {
            return Err((UNAUTHORIZED, "The auth token was made in the future"));
        }
        let tag = |name: &'static str| {
            ev.tags
                .iter()
                .filter(move |t| t.first().is_some_and(|n| n == name))
                .filter_map(|t| t.get(1))
        };
        let expiration = tag("expiration")
            .next()
            .and_then(|e| e.parse::<u64>().ok())
            .ok_or((UNAUTHORIZED, "The auth token has no expiration"))?;
        if expiration <= now {
            return Err((UNAUTHORIZED, "The auth token has expired"));
        }
        if !tag("t").any(|t| t == verb) {
            return Err((UNAUTHORIZED, "The auth token is for something else"));
        }
        let mut servers = tag("server").peekable();
        if servers.peek().is_some() && !servers.any(|s| host_of(s) == self.domain) {
            return Err((UNAUTHORIZED, "The auth token is for another server"));
        }
        let x = tag("x").filter_map(|h| Hash::parse(h.as_bytes())).collect();
        let (pubkey, id) = ids(ev).map_err(|r| (UNAUTHORIZED, r))?;
        if self.verified.lock().get(&id).is_none() {
            signature(ev, &pubkey, &id).map_err(|r| (UNAUTHORIZED, r))?;
            self.verified.lock().put(id, ());
        }
        Ok(Token { pubkey, x })
    }
}

/// The event's pubkey and id, the id checked against its contents.
fn ids(ev: &Event) -> Result<([u8; 32], [u8; 32]), &'static str> {
    let pubkey = hex32(&ev.pubkey).ok_or("The event's pubkey is malformed")?;
    let id = hex32(&ev.id).ok_or("The event's id is malformed")?;
    if Hash::of(serialize(ev).as_bytes()).0 != id {
        return Err("The event's id doesn't match it");
    }
    Ok((pubkey, id))
}

fn signature(ev: &Event, pubkey: &[u8; 32], id: &[u8; 32]) -> Result<(), &'static str> {
    let sig = hex::decode(&ev.sig)
        .ok()
        .and_then(|s| <[u8; 64]>::try_from(s).ok())
        .ok_or("The event's signature is malformed")?;
    let key =
        XOnlyPublicKey::from_byte_array(*pubkey).map_err(|_| "The event's pubkey isn't a key")?;
    #[allow(deprecated)]
    SECP256K1
        .verify_schnorr(&Signature::from_byte_array(sig), id, &key)
        .map_err(|_| "The event's signature is invalid")
}

/// A BUD-09 report: a signed kind 1984 event naming one or more blobs by
/// `x` tags. Its id, and the blobs.
pub fn verify_report(json: &[u8]) -> Result<([u8; 32], Vec<Hash>), &'static str> {
    let ev: Event = serde_json::from_slice(json).map_err(|_| "The body isn't a Nostr event")?;
    if ev.kind != 1984 {
        return Err("A report is a kind 1984 event");
    }
    let mut hashes = Vec::new();
    for t in ev
        .tags
        .iter()
        .filter(|t| t.first().is_some_and(|n| n == "x"))
    {
        hashes.push(
            t.get(1)
                .and_then(|h| Hash::parse(h.as_bytes()))
                .ok_or("An x tag isn't a blob's hash")?,
        );
    }
    if hashes.is_empty() {
        return Err("A report names blobs in x tags");
    }
    let (pubkey, id) = ids(&ev)?;
    signature(&ev, &pubkey, &id)?;
    Ok((id, hashes))
}

/// Standard or URL-safe, padded or not: BUD-11 now says unpadded URL-safe,
/// but clients written before it send standard base64.
fn decode_base64(s: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    [URL_SAFE_NO_PAD, URL_SAFE, STANDARD, STANDARD_NO_PAD]
        .iter()
        .find_map(|e| e.decode(s).ok())
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || s.bytes().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    hex::decode(s).ok()?.try_into().ok()
}

/// A `server` tag's hostname: tags should hold a bare domain, but some
/// clients write a URL.
fn host_of(tag: &str) -> String {
    let t = tag.trim();
    let t = t.split_once("://").map_or(t, |(_, rest)| rest);
    let host = t.split(['/', '?', '#']).next().unwrap_or("");
    let host = host
        .rsplit_once(':')
        .filter(|(_, port)| port.bytes().all(|b| b.is_ascii_digit()))
        .map_or(host, |(h, _)| h);
    host.to_ascii_lowercase()
}

/// NIP-01's serialization, whose SHA-256 is the event's id: `[0, pubkey,
/// created_at, kind, tags, content]`, with strings escaped only as NIP-01
/// says (serde_json escapes other control characters too).
fn serialize(ev: &Event) -> String {
    let mut out = String::with_capacity(256 + ev.content.len());
    out.push_str("[0,");
    string(&mut out, &ev.pubkey);
    out.push_str(&format!(",{},{},[", ev.created_at, ev.kind));
    for (i, tag) in ev.tags.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('[');
        for (j, v) in tag.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            string(&mut out, v);
        }
        out.push(']');
    }
    out.push_str("],");
    string(&mut out, &ev.content);
    out.push(']');
    out
}

fn string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
pub mod tests {
    use secp256k1::Keypair;

    use super::*;

    /// A signed token, as a client makes one.
    pub fn token(
        kp: &Keypair,
        verb: &str,
        x: &[Hash],
        server: Option<&str>,
        expiration: u64,
        created_at: u64,
    ) -> String {
        let pubkey = hex::encode(kp.x_only_public_key().0.to_byte_array());
        let mut tags = vec![
            vec!["t".to_string(), verb.to_string()],
            vec!["expiration".into(), expiration.to_string()],
        ];
        for h in x {
            tags.push(vec!["x".into(), h.hex()]);
        }
        if let Some(s) = server {
            tags.push(vec!["server".into(), s.into()]);
        }
        let mut ev = Event {
            id: String::new(),
            pubkey,
            created_at,
            kind: KIND,
            tags,
            content: "Upload a \"thing\"\n".into(),
            sig: String::new(),
        };
        let id = Hash::of(serialize(&ev).as_bytes()).0;
        #[allow(deprecated)]
        let sig = SECP256K1.sign_schnorr_no_aux_rand(&id, kp);
        ev.id = hex::encode(id);
        ev.sig = hex::encode(sig.to_byte_array());
        let json = serde_json::json!({
            "id": ev.id, "pubkey": ev.pubkey, "created_at": ev.created_at, "kind": ev.kind,
            "tags": ev.tags, "content": ev.content, "sig": ev.sig,
        });
        format!(
            "Nostr {}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&json).unwrap())
        )
    }

    /// Any signed event, as JSON.
    pub fn signed(kp: &Keypair, kind: u64, tags: Vec<Vec<String>>, content: &str) -> String {
        let pubkey = hex::encode(kp.x_only_public_key().0.to_byte_array());
        let mut ev = Event {
            id: String::new(),
            pubkey,
            created_at: 1_760_000_000,
            kind,
            tags,
            content: content.into(),
            sig: String::new(),
        };
        let id = Hash::of(serialize(&ev).as_bytes()).0;
        #[allow(deprecated)]
        let sig = SECP256K1.sign_schnorr_no_aux_rand(&id, kp);
        ev.id = hex::encode(id);
        ev.sig = hex::encode(sig.to_byte_array());
        serde_json::json!({
            "id": ev.id, "pubkey": ev.pubkey, "created_at": ev.created_at, "kind": ev.kind,
            "tags": ev.tags, "content": ev.content, "sig": ev.sig,
        })
        .to_string()
    }

    pub fn keypair() -> Keypair {
        let mut secret = [0u8; 32];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut secret).unwrap();
        Keypair::from_secret_bytes(secret).unwrap()
    }

    fn headers(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(hyper::header::AUTHORIZATION, v.parse().unwrap());
        h
    }

    #[test]
    fn accepts_good_tokens_and_refuses_bad_ones() {
        let v = Verifier::new("blossom.example.com".into());
        let kp = keypair();
        let x = Hash::of(b"blob");
        let now = 1_800_000_000;
        let ok = token(
            &kp,
            "upload",
            &[x],
            Some("blossom.example.com"),
            now + 600,
            now - 5,
        );
        let t = v.check(&headers(&ok), "upload", now).unwrap().unwrap();
        assert!(t.names(&x));
        assert_eq!(t.pubkey, kp.x_only_public_key().0.to_byte_array());
        // Again, from the cache of verified ids.
        assert!(v.check(&headers(&ok), "upload", now).unwrap().is_some());

        assert!(v.check(&HeaderMap::new(), "upload", now).unwrap().is_none());
        let refused = |h: &str, verb: &str| v.check(&headers(h), verb, now).unwrap_err().1;
        assert_eq!(
            refused(&ok, "delete"),
            "The auth token is for something else"
        );
        assert_eq!(
            refused(
                &token(&kp, "upload", &[x], None, now - 1, now - 5),
                "upload"
            ),
            "The auth token has expired"
        );
        assert_eq!(
            refused(
                &token(&kp, "upload", &[x], Some("other.example"), now + 60, now),
                "upload"
            ),
            "The auth token is for another server"
        );
        assert_eq!(
            refused(
                &token(&kp, "upload", &[x], None, now + 600, now + 3600),
                "upload"
            ),
            "The auth token was made in the future"
        );
        assert_eq!(
            refused("Bearer abc", "upload"),
            "The Authorization header isn't a Nostr token"
        );
        // A URL in the server tag still names the host.
        assert!(
            v.check(
                &headers(&token(
                    &kp,
                    "upload",
                    &[],
                    Some("https://Blossom.Example.com/"),
                    now + 60,
                    now
                )),
                "upload",
                now
            )
            .is_ok()
        );

        // Tampering with a field breaks the id; a forged id breaks the signature.
        let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(ok.strip_prefix("Nostr ").unwrap())
            .unwrap();
        let mut ev: serde_json::Value = serde_json::from_slice(&json).unwrap();
        ev["content"] = "changed".into();
        let tampered = format!(
            "Nostr {}",
            base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&ev).unwrap())
        );
        assert_eq!(
            refused(&tampered, "upload"),
            "The event's id doesn't match it"
        );
    }

    #[test]
    fn serializes_as_nip01_says() {
        let ev = Event {
            id: String::new(),
            pubkey: "ab".into(),
            created_at: 1,
            kind: 1,
            tags: vec![vec!["t".into(), "a\"b".into()]],
            content: "line\nbreak\u{1} é /".into(),
            sig: String::new(),
        };
        assert_eq!(
            serialize(&ev),
            "[0,\"ab\",1,1,[[\"t\",\"a\\\"b\"]],\"line\\nbreak\u{1} é /\"]"
        );
    }
}
