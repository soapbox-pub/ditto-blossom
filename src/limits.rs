//! Per-client rate limits: a token bucket per address (per /64 for IPv6, as
//! one machine is given a whole /64).

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// Buckets kept before idle ones are dropped.
const MAX_BUCKETS: usize = 100_000;

/// A bucket of `full` tokens per address, refilling at `full` per `period`.
pub struct RateLimit {
    full: f64,
    /// Tokens a second.
    rate: f64,
    buckets: Mutex<HashMap<IpAddr, (f64, Instant)>>,
}

/// The key an address is limited by: its /64 if it's IPv6.
fn key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) if v6.to_ipv4_mapped().is_none() => {
            let s = v6.segments();
            IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
        IpAddr::V6(v6) => IpAddr::V4(v6.to_ipv4_mapped().expect("mapped")),
        v4 => v4,
    }
}

impl RateLimit {
    pub fn new(full: u64, period: Duration) -> RateLimit {
        RateLimit {
            full: full as f64,
            rate: full as f64 / period.as_secs_f64(),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// `n` a minute.
    pub fn per_minute(n: u32) -> RateLimit {
        RateLimit::new(n.into(), Duration::from_secs(60))
    }

    /// Whether `ip` may go ahead, taking a token if so.
    pub fn allow(&self, ip: IpAddr) -> bool {
        self.take(ip, 1).is_ok()
    }

    /// Take `cost` tokens from `ip`'s bucket, or say how long until it may.
    /// A cost over a full bucket needs a full one, and leaves it in debt.
    pub fn take(&self, ip: IpAddr, cost: u64) -> Result<(), Duration> {
        let cost = cost as f64;
        let need = cost.min(self.full);
        self.with(ip, |tokens| {
            if *tokens >= need {
                *tokens -= cost;
                Ok(())
            } else {
                Err(Duration::from_secs_f64((need - *tokens) / self.rate))
            }
        })
    }

    /// Take `cost` tokens whatever's left, for what's known only afterwards.
    pub fn charge(&self, ip: IpAddr, cost: u64) {
        self.with(ip, |tokens| *tokens -= cost as f64)
    }

    fn with<T>(&self, ip: IpAddr, f: impl FnOnce(&mut f64) -> T) -> T {
        let now = Instant::now();
        let (full, rate) = (self.full, self.rate);
        let refilled = |tokens: f64, at: Instant| {
            (tokens + now.duration_since(at).as_secs_f64() * rate).min(full)
        };
        let mut buckets = self.buckets.lock();
        if buckets.len() > MAX_BUCKETS {
            buckets.retain(|_, (tokens, at)| refilled(*tokens, *at) < full);
        }
        let (tokens, at) = buckets.entry(key(ip)).or_insert((full, now));
        *tokens = refilled(*tokens, *at);
        *at = now;
        f(tokens)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_each_client_and_ipv6_by_prefix() {
        let l = RateLimit::per_minute(3);
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

    #[test]
    fn costs_spend_the_bucket_and_big_ones_need_it_full() {
        let hour = Duration::from_secs(3600);
        let l = RateLimit::new(1000, hour);
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        assert!(l.take(a, 600).is_ok());
        let wait = l.take(a, 600).unwrap_err();
        assert!(wait > Duration::from_secs(700) && wait <= Duration::from_secs(720));
        assert!(l.take(a, 400).is_ok());
        assert!(l.take(a, 1).is_err());

        // Bigger than the bucket: once, from full, then a debt to wait out.
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        assert!(l.take(b, 5000).is_ok());
        let wait = l.take(b, 1).unwrap_err();
        assert!(wait > hour * 4, "{wait:?}");

        let c: IpAddr = "192.0.2.3".parse().unwrap();
        l.charge(c, 1500);
        assert!(l.take(c, 0).is_err());
    }
}
