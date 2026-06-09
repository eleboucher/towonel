//! The agent's two retry primitives, shared so retry policy lives in one place.
//!
//! * [`operation`] — a one-shot hub call: bounded jittered backoff, then give up.
//! * [`supervise`] — a long-lived activity: restart it until shutdown, backing
//!   off while it keeps failing fast. Recovers in-process, so the agent doesn't
//!   depend on an orchestrator to restart it.

use std::future::Future;
use std::time::{Duration, Instant};

use backon::{ExponentialBuilder, Retryable};
use tokio_util::sync::CancellationToken;
use tracing::warn;

const OPERATION_MAX_ATTEMPTS: usize = 10;

/// Jittered exponential backoff shared by every one-shot hub operation. Jitter
/// keeps replicas booting together from re-colliding on each retry.
pub fn operation_backoff() -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(Duration::from_millis(50))
        .with_max_delay(Duration::from_secs(2))
        .with_max_times(OPERATION_MAX_ATTEMPTS - 1)
        .with_jitter()
}

/// Retry `op` while `retry_if` deems the error transient, then return the last
/// error.
pub async fn operation<T, F, Fut>(
    label: &str,
    retry_if: impl Fn(&anyhow::Error) -> bool + Send + Sync,
    op: F,
) -> anyhow::Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = anyhow::Result<T>>,
{
    op.retry(operation_backoff())
        .when(|e| retry_if(e))
        .notify(|e, dur| {
            warn!(
                op = label,
                backoff_ms = u64::try_from(dur.as_millis()).unwrap_or(u64::MAX),
                error = %e,
                "retrying hub operation",
            );
        })
        .await
}

/// Restart `activity` until `shutdown`. `base` is the gap between healthy runs
/// (a poll interval, or the redial gap after a session ends). Each consecutive
/// error escalates the next delay up to `max`; a clean (`Ok`) run resets the
/// escalation. A single error after a long healthy run still redials at `base`
/// (escalation only bites on *consecutive* failures), so a timeout-bound
/// failure can no longer masquerade as healthy and pin the delay at `base`.
/// Delays are jittered so concurrent supervisors don't fire in lockstep.
pub async fn supervise<F, Fut>(
    label: &str,
    shutdown: &CancellationToken,
    base: Duration,
    max: Duration,
    mut activity: F,
) where
    F: FnMut() -> Fut,
    Fut: Future<Output = anyhow::Result<()>>,
{
    let mut failures: u32 = 0;
    loop {
        if shutdown.is_cancelled() {
            return;
        }
        let started = Instant::now();
        let outcome = tokio::select! {
            () = shutdown.cancelled() => return,
            r = activity() => r,
        };

        let ran = started.elapsed();
        if outcome.is_ok() {
            failures = 0;
        } else {
            failures = failures.saturating_add(1);
        }
        if let Err(e) = &outcome {
            warn!(
                task = label,
                ran_secs = ran.as_secs(),
                error = ?e,
                "supervised task exited with error; restarting"
            );
        }
        let delay = jitter(if failures == 0 {
            base
        } else {
            escalate(base, max, failures)
        });

        tokio::select! {
            () = shutdown.cancelled() => return,
            () = tokio::time::sleep(delay) => {}
        }
    }
}

/// `base * 2^(failures - 1)`, capped at `max`. `failures` is assumed >= 1.
fn escalate(base: Duration, max: Duration, failures: u32) -> Duration {
    let shift = failures.saturating_sub(1).min(16);
    base.checked_mul(1u32 << shift).unwrap_or(max).min(max)
}

/// Spread a delay by ±15 % so concurrent supervisors don't fire in lockstep.
fn jitter(d: Duration) -> Duration {
    d.mul_f64(fastrand::f64().mul_add(0.30, 0.85))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escalate_grows_then_caps() {
        let base = Duration::from_secs(5);
        let max = Duration::from_mins(1);
        assert_eq!(escalate(base, max, 1), Duration::from_secs(5));
        assert_eq!(escalate(base, max, 2), Duration::from_secs(10));
        assert_eq!(escalate(base, max, 3), Duration::from_secs(20));
        // 5 * 2^4 = 80 > 60, so it caps.
        assert_eq!(escalate(base, max, 5), max);
        // Huge failure counts can't overflow the multiply.
        assert_eq!(escalate(base, max, u32::MAX), max);
    }

    #[test]
    fn jitter_stays_within_bounds() {
        let d = Duration::from_secs(10);
        for _ in 0..1000 {
            let j = jitter(d);
            assert!(j >= d.mul_f64(0.85) && j <= d.mul_f64(1.15));
        }
    }
}
