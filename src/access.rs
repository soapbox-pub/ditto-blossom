//! Which blobs have been read, at the cost of an atomic bit per read.
//!
//! A read sets its blob's bit (by seq). Every few minutes the bits are taken
//! and each blob read since gets today's date in the store's lazy `access`
//! table: at most one write per blob a day, never one per read. That's what
//! tells hot blobs from cold, for a cold tier or eviction one day.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;

#[derive(Default)]
pub struct Access {
    bits: RwLock<Vec<AtomicU64>>,
}

impl Access {
    pub fn touch(&self, seq: u64) {
        let (word, bit) = ((seq / 64) as usize, 1u64 << (seq % 64));
        {
            let bits = self.bits.read();
            if let Some(w) = bits.get(word) {
                // Checked first, so a hot blob's line isn't written to on
                // every read by every core.
                if w.load(Ordering::Relaxed) & bit == 0 {
                    w.fetch_or(bit, Ordering::Relaxed);
                }
                return;
            }
        }
        let mut bits = self.bits.write();
        if bits.len() <= word {
            bits.resize_with((word + 1).next_power_of_two(), AtomicU64::default);
        }
        bits[word].fetch_or(bit, Ordering::Relaxed);
    }

    /// The seqs read since the last take, clearing them.
    pub fn take(&self) -> Vec<u64> {
        let bits = self.bits.read();
        let mut out = Vec::new();
        for (i, w) in bits.iter().enumerate() {
            let mut v = w.swap(0, Ordering::Relaxed);
            while v != 0 {
                let b = v.trailing_zeros() as u64;
                out.push(i as u64 * 64 + b);
                v &= v - 1;
            }
        }
        out
    }
}

/// Days since the epoch, which fits a u16 until 2149.
pub fn today() -> u16 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    (secs / 86400) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn takes_what_was_touched_once() {
        let a = Access::default();
        for seq in [3, 3, 64, 1000, 5] {
            a.touch(seq);
        }
        assert_eq!(a.take(), [3, 5, 64, 1000]);
        assert!(a.take().is_empty());
    }
}
