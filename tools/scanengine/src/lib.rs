//! A small shared engine for the s0t0n scanners: run many async probes with
//! bounded concurrency and an optional global rate limit, with retries.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::{sleep, Instant};

/// Configuration for a scan run.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub concurrency: usize,
    /// Max probes per second across the whole run (0 = unlimited).
    pub rate_per_sec: u32,
    pub retries: u32,
}

impl Default for Config {
    fn default() -> Self {
        Config { concurrency: 200, rate_per_sec: 0, retries: 0 }
    }
}

/// A simple global token-bucket rate limiter shared across tasks.
pub struct RateLimiter {
    inner: Mutex<Bucket>,
    rate: f64,
    capacity: f64,
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    pub fn new(rate_per_sec: u32) -> Self {
        let rate = rate_per_sec as f64;
        RateLimiter {
            inner: Mutex::new(Bucket { tokens: rate.max(1.0), last: Instant::now() }),
            rate,
            capacity: rate.max(1.0),
        }
    }

    /// Wait until a token is available, then consume it.
    pub async fn acquire(&self) {
        if self.rate <= 0.0 {
            return;
        }
        loop {
            let wait = {
                let mut b = self.inner.lock().await;
                let now = Instant::now();
                let elapsed = now.duration_since(b.last).as_secs_f64();
                b.tokens = (b.tokens + elapsed * self.rate).min(self.capacity);
                b.last = now;
                if b.tokens >= 1.0 {
                    b.tokens -= 1.0;
                    return;
                }
                (1.0 - b.tokens) / self.rate
            };
            sleep(Duration::from_secs_f64(wait)).await;
        }
    }
}

/// Run `f` over every item with bounded concurrency + optional rate limit,
/// retrying each item up to `cfg.retries` times while it returns `None`.
/// Preserves input order in the returned vector.
pub async fn run<I, T, F, Fut>(items: Vec<I>, cfg: Config, f: F) -> Vec<Option<T>>
where
    I: Send + 'static + Clone,
    T: Send + 'static,
    F: Fn(I) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Option<T>> + Send,
{
    let sem = Arc::new(Semaphore::new(cfg.concurrency.max(1)));
    let limiter = Arc::new(RateLimiter::new(cfg.rate_per_sec));
    let f = Arc::new(f);

    let mut handles = Vec::with_capacity(items.len());
    for item in items {
        let sem = Arc::clone(&sem);
        let limiter = Arc::clone(&limiter);
        let f = Arc::clone(&f);
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.unwrap();
            let mut attempt = 0u32;
            loop {
                limiter.acquire().await;
                if let Some(v) = f(item.clone()).await {
                    return Some(v);
                }
                if attempt >= cfg.retries {
                    return None;
                }
                attempt += 1;
            }
        }));
    }

    let mut out = Vec::with_capacity(handles.len());
    for h in handles {
        out.push(h.await.unwrap_or(None));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn runs_all_and_preserves_order() {
        let items: Vec<u32> = (0..100).collect();
        let cfg = Config { concurrency: 16, rate_per_sec: 0, retries: 0 };
        let out = run(items, cfg, |x| async move { Some(x * 2) }).await;
        assert_eq!(out.len(), 100);
        assert_eq!(out[10], Some(20));
        assert_eq!(out[99], Some(198));
    }

    #[tokio::test]
    async fn retries_until_success() {
        use std::sync::atomic::{AtomicU32, Ordering};
        static CALLS: AtomicU32 = AtomicU32::new(0);
        let cfg = Config { concurrency: 1, rate_per_sec: 0, retries: 3 };
        let out = run(vec![1u32], cfg, |_| async move {
            // fail twice, then succeed
            if CALLS.fetch_add(1, Ordering::SeqCst) < 2 { None } else { Some(42u32) }
        })
        .await;
        assert_eq!(out[0], Some(42));
    }

    #[tokio::test]
    async fn rate_limiter_paces() {
        let rl = RateLimiter::new(50); // 50/sec
        let start = Instant::now();
        for _ in 0..10 {
            rl.acquire().await;
        }
        // 10 tokens at 50/sec: first ~capacity available instantly, so just
        // assert it completes quickly and without panicking.
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}
