//! End-to-end: two servers following each other's moderation.

use reqwest::StatusCode;

use super::{Server, client, put, start};
use crate::config::Peer;
use crate::hash::Hash;
use crate::store::Banned;

const TOKEN_A: &str = "a-token-for-reading-server-a-decisions";
const TOKEN_B: &str = "a-token-for-reading-server-b-decisions";

struct Pair {
    a: Server,
    b: Server,
    /// How each finds the other.
    a_as_peer: Peer,
    b_as_peer: Peer,
    evidence_b: tempfile::TempDir,
    _etc: tempfile::TempDir,
}

async fn pair(b_extra: &str) -> Pair {
    let etc = tempfile::tempdir().unwrap();
    let file = |name: &str, text: &str| {
        let p = etc.path().join(name);
        std::fs::write(&p, text).unwrap();
        p
    };
    let (tokens_a, tokens_b) = (file("tokens-a", TOKEN_A), file("tokens-b", TOKEN_B));
    let (to_a, to_b) = (file("to-a", TOKEN_A), file("to-b", TOKEN_B));
    let evidence_b = tempfile::tempdir().unwrap();
    let a = start(&format!("[moderation]\ntokens_file = {tokens_a:?}\n")).await;
    let b = start(&format!(
        "{b_extra}\n[admin]\npreserve = {:?}\n[moderation]\ntokens_file = {tokens_b:?}\n",
        evidence_b.path()
    ))
    .await;
    Pair {
        a_as_peer: Peer {
            url: a.url.clone(),
            token_file: to_a,
            skip: Vec::new(),
        },
        b_as_peer: Peer {
            url: b.url.clone(),
            token_file: to_b,
            skip: Vec::new(),
        },
        a,
        b,
        evidence_b,
        _etc: etc,
    }
}

/// `server` reads `peer`'s new decisions, as its loop would.
async fn pull(server: &Server, peer: &Peer, token: &str) {
    crate::peers::pull(
        server.app,
        peer,
        token,
        &tokio_util::sync::CancellationToken::new(),
    )
    .await
    .unwrap();
}

fn own(s: &Server, data: &[u8], pk: [u8; 32]) -> Hash {
    let h = put(s.app, data, None);
    let mut txn = s.app.store.write_txn().unwrap();
    let seq = s.app.store.seq_of(&txn, &h).unwrap().unwrap();
    s.app
        .store
        .add_owner(&mut txn, seq, 1_760_000_000, &pk)
        .unwrap();
    txn.commit().unwrap();
    h
}

fn banned(s: &Server, target: Banned) -> Option<String> {
    s.app
        .store
        .read(|txn| s.app.store.ban_of(txn, target))
        .unwrap()
        .unwrap()
        .map(|b| b.reason)
}

fn stored(s: &Server, h: Hash) -> bool {
    s.app.store.find(&h, false).unwrap().is_some()
}

#[tokio::test]
async fn bans_and_unbans_go_both_ways() {
    let p = pair("").await;
    let (a, b) = (&p.a, &p.b);
    let (spammer, other) = ([1; 32], [2; 32]);
    let x = put(a.app, b"on both", None);
    assert_eq!(put(b.app, b"on both", None), x);
    let theirs = own(b, b"the spammer's", spammer);
    let shared = own(b, b"theirs and another's", spammer);
    {
        let mut txn = b.app.store.write_txn().unwrap();
        let seq = b.app.store.seq_of(&txn, &shared).unwrap().unwrap();
        b.app
            .store
            .add_owner(&mut txn, seq, 1_760_000_000, &other)
            .unwrap();
        txn.commit().unwrap();
    }

    // Banned on A, a blob and a pubkey: B follows, and removes what only
    // the banned pubkey owned.
    crate::moderate::ban_in(
        a.app.store,
        a.app.files,
        &[Banned::Blob(x), Banned::Pubkey(spammer)],
        "spam",
        None,
    )
    .unwrap();
    pull(b, &p.a_as_peer, TOKEN_A).await;
    assert_eq!(banned(b, Banned::Blob(x)).as_deref(), Some("spam"));
    assert_eq!(banned(b, Banned::Pubkey(spammer)).as_deref(), Some("spam"));
    assert!(!stored(b, x) && !stored(b, theirs));
    assert!(stored(b, shared), "another owns it too");

    // What B took from A, served back, is no news to A; the ban B made of
    // the spammer's blob is, and keeps it out of A too.
    let before = a.app.store.bans().unwrap();
    pull(a, &p.b_as_peer, TOKEN_B).await;
    let after = a.app.store.bans().unwrap();
    assert!(before.iter().all(|b| after.contains(b)));
    assert_eq!(
        banned(a, Banned::Blob(theirs)).as_deref(),
        Some("uploader banned: spam")
    );
    assert_eq!(after.len(), before.len() + 1);
    pull(a, &p.b_as_peer, TOKEN_B).await;
    pull(b, &p.a_as_peer, TOKEN_A).await;
    assert_eq!(a.app.store.bans().unwrap(), after);

    // Lifted on B, later: lifted on A too.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    crate::moderate::unban_in(b.app.store, &[Banned::Pubkey(spammer)]).unwrap();
    pull(a, &p.b_as_peer, TOKEN_B).await;
    assert_eq!(banned(a, Banned::Pubkey(spammer)), None);
    assert!(banned(a, Banned::Blob(x)).is_some());
    // And A's older ban, read again, doesn't put it back on B.
    pull(b, &p.a_as_peer, TOKEN_A).await;
    assert_eq!(banned(b, Banned::Pubkey(spammer)), None);
}

#[tokio::test]
async fn csam_is_preserved_and_some_bans_are_not_followed() {
    let kp = crate::auth::tests::keypair();
    let exempt = kp.x_only_public_key().0.to_byte_array();
    let p = pair(&format!("[upload]\nexempt = [\"{}\"]", hex::encode(exempt))).await;
    let (a, b) = (&p.a, &p.b);
    let csam = put(b.app, b"evidence", None);
    let scored = put(b.app, b"explicit, by a scanner", None);
    crate::moderate::ban_in(
        a.app.store,
        a.app.files,
        &[Banned::Blob(csam)],
        "CSAM",
        None,
    )
    .unwrap();
    crate::moderate::ban_in(
        a.app.store,
        a.app.files,
        &[Banned::Blob(scored)],
        "scan: scored 0.912",
        None,
    )
    .unwrap();
    crate::moderate::ban_in(
        a.app.store,
        a.app.files,
        &[Banned::Pubkey(exempt)],
        "",
        None,
    )
    .unwrap();
    let mut peer = p.a_as_peer.clone();
    peer.skip = vec!["scan:".into()];
    pull(b, &peer, TOKEN_A).await;

    assert!(!stored(b, csam));
    assert_eq!(
        std::fs::read(p.evidence_b.path().join(csam.hex())).unwrap(),
        b"evidence"
    );
    assert!(stored(b, scored), "skipped");
    assert_eq!(banned(b, Banned::Pubkey(exempt)), None, "exempt here");
}

#[tokio::test]
async fn decisions_are_only_for_peers() {
    let p = pair("").await;
    let c = client();
    let url = format!("{}/moderation/decisions", p.a.url);
    let r = c.get(&url).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let r = c.get(&url).bearer_auth(TOKEN_B).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "B's token is for B");
    let r = c.get(&url).bearer_auth(TOKEN_A).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.headers()["cache-control"], "no-store, private");

    // Pages, read on from a cursor.
    for i in 0..5u8 {
        crate::moderate::ban_in(
            p.a.app.store,
            p.a.app.files,
            &[Banned::Blob(Hash::of(&[i]))],
            "",
            None,
        )
        .unwrap();
    }
    let page = |after: Option<String>| {
        let mut u = format!("{url}?limit=3");
        if let Some(a) = after {
            u.push_str(&format!("&after={a}"));
        }
        c.get(u).bearer_auth(TOKEN_A).send()
    };
    let first: serde_json::Value = page(None).await.unwrap().json().await.unwrap();
    assert_eq!(first["decisions"].as_array().unwrap().len(), 3);
    assert_eq!(first["more"], true);
    let cursor = first["decisions"][2]["cursor"]
        .as_str()
        .unwrap()
        .to_string();
    let rest: serde_json::Value = page(Some(cursor)).await.unwrap().json().await.unwrap();
    assert_eq!(rest["decisions"].as_array().unwrap().len(), 2);
    assert_eq!(rest["more"], false);

    // A server sharing nothing serves nothing.
    let none = start("").await;
    let r = c
        .get(format!("{}/moderation/decisions", none.url))
        .bearer_auth(TOKEN_A)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}
