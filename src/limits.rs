//! Per-client rate limits: a token bucket per address (per /64 for IPv6, as
//! one machine is given a whole /64).

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

use parking_lot::Mutex;

/// Buckets kept before idle ones are dropped.
const MAX_BUCKETS: usize = 100_000;

pub struct RateLimit {
    per_minute: f64,
    buckets: Mutex<HashMap<IpAddr, (f64, Instant)>>,
}

impl RateLimit {
    pub fn new(per_minute: u32) -> RateLimit {
        RateLimit {
            per_minute: per_minute as f64,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Whether `ip` may go ahead, taking a token if so.
    pub fn allow(&self, ip: IpAddr) -> bool {
        let key = match ip {
            IpAddr::V6(v6) if v6.to_ipv4_mapped().is_none() => {
                let s = v6.segments();
                IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
            IpAddr::V6(v6) => IpAddr::V4(v6.to_ipv4_mapped().expect("mapped")),
            v4 => v4,
        };
        let now = Instant::now();
        let mut buckets = self.buckets.lock();
        if buckets.len() > MAX_BUCKETS {
            let full = self.per_minute;
            buckets.retain(|_, (tokens, at)| {
                *tokens + now.duration_since(*at).as_secs_f64() * full / 60.0 < full
            });
        }
        let (tokens, at) = buckets.entry(key).or_insert((self.per_minute, now));
        *tokens = (*tokens + now.duration_since(*at).as_secs_f64() * self.per_minute / 60.0)
            .min(self.per_minute);
        *at = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_each_client_and_ipv6_by_prefix() {
        let l = RateLimit::new(3);
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        assert!((0..3).all(|_| l.allow(a)));
        assert!(!l.allow(a));
        assert!(l.allow("192.0.2.2".parse().unwrap()));
        let (x, y): (IpAddr, IpAddr) = (
            "2001:db8::1".parse().unwrap(),
            "2001:db8::ffff".parse().unwrap(),
        );
        assert!((0..3).all(|_| l.allow(x)));
        assert!(!l.allow(y), "the same /64");
    }
}
