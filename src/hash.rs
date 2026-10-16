//! A blob's name: the SHA-256 of its bytes.

use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    /// 64 hex digits, either case.
    pub fn parse(hex: &[u8]) -> Option<Hash> {
        if hex.len() != 64 {
            return None;
        }
        let digit = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        };
        let mut out = [0; 32];
        for (i, pair) in hex.chunks_exact(2).enumerate() {
            out[i] = digit(pair[0])? << 4 | digit(pair[1])?;
        }
        Some(Hash(out))
    }

    pub fn of(data: &[u8]) -> Hash {
        Hash(ring::digest::digest(&ring::digest::SHA256, data).as_ref().try_into().expect("32 bytes"))
    }

    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hex())
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", self.hex())
    }
}

/// SHA-256 over bytes that arrive in pieces.
pub struct Hasher(ring::digest::Context);

impl Hasher {
    pub fn new() -> Hasher {
        Hasher(ring::digest::Context::new(&ring::digest::SHA256))
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    pub fn finish(self) -> Hash {
        Hash(self.0.finish().as_ref().try_into().expect("32 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_either_case_and_prints_lowercase() {
        let h = Hash::of(b"hello");
        let hex = h.hex();
        assert_eq!(Hash::parse(hex.as_bytes()), Some(h));
        assert_eq!(Hash::parse(hex.to_uppercase().as_bytes()), Some(h));
        assert_eq!(hex, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
        assert_eq!(Hash::parse(b"2cf24dba"), None);
        assert_eq!(Hash::parse(&[b'g'; 64]), None);
    }

    #[test]
    fn hashing_in_pieces_agrees() {
        let mut h = Hasher::new();
        h.update(b"hel");
        h.update(b"lo");
        assert_eq!(h.finish(), Hash::of(b"hello"));
    }
}
