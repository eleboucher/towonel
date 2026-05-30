//! Active/passive hub leader election.
//!
//! One hub holds a Postgres session advisory lock and is the leader; the rest
//! report not-ready on `/v1/readyz` and skip singleton work. A crash drops the
//! lock-holding connection, Postgres frees the lock, and a standby acquires it
//! on its next poll — mutually exclusive, so no dual-leader window.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use sea_orm::sqlx;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// `pg_advisory_lock` key shared by every hub in a cluster (`b"twnlhubl"`).
const LEADER_LOCK_KEY: i64 = i64::from_be_bytes(*b"twnlhubl");

/// Standby poll interval and leader heartbeat interval; bounds crash failover.
const TICK: Duration = Duration::from_secs(2);

#[async_trait::async_trait]
pub trait LeaderElector: Send + Sync {
    async fn run(
        &self,
        is_leader: Arc<AtomicBool>,
        gauge: prometheus::IntGauge,
        shutdown: CancellationToken,
    );
}

pub struct PgAdvisoryLockElector {
    /// Should point at the Postgres primary directly (not a pooler), so a
    /// pooler restart can't drop the lock and trigger a spurious failover.
    dsn: String,
}

impl PgAdvisoryLockElector {
    #[must_use]
    pub const fn new(dsn: String) -> Self {
        Self { dsn }
    }
}

fn set_leader(is_leader: &AtomicBool, gauge: &prometheus::IntGauge, leader: bool) {
    gauge.set(i64::from(leader));
    if is_leader.swap(leader, Ordering::SeqCst) != leader {
        info!(leader, "hub leadership changed");
    }
}

#[async_trait::async_trait]
impl LeaderElector for PgAdvisoryLockElector {
    async fn run(
        &self,
        is_leader: Arc<AtomicBool>,
        gauge: prometheus::IntGauge,
        shutdown: CancellationToken,
    ) {
        while !shutdown.is_cancelled() {
            // `attempt` owns the connection pool; returning drops it, which
            // closes the connection and releases the lock.
            if let Err(e) = self.attempt(&is_leader, &gauge, &shutdown).await {
                warn!(error = %e, "leader election connection error; retrying");
            }
            set_leader(&is_leader, &gauge, false);
            tokio::select! {
                () = shutdown.cancelled() => return,
                () = tokio::time::sleep(TICK) => {}
            }
        }
    }
}

impl PgAdvisoryLockElector {
    async fn attempt(
        &self,
        is_leader: &AtomicBool,
        gauge: &prometheus::IntGauge,
        shutdown: &CancellationToken,
    ) -> anyhow::Result<()> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .min_connections(1)
            .connect(&self.dsn)
            .await?;
        let mut conn = pool.acquire().await?;

        while !shutdown.is_cancelled() {
            let held: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
                .bind(LEADER_LOCK_KEY)
                .fetch_one(&mut *conn)
                .await?;
            if held {
                break;
            }
            set_leader(is_leader, gauge, false);
            tokio::select! {
                () = shutdown.cancelled() => return Ok(()),
                () = tokio::time::sleep(TICK) => {}
            }
        }

        set_leader(is_leader, gauge, true);
        loop {
            tokio::select! {
                // Step down before the pool drop releases the lock.
                () = shutdown.cancelled() => {
                    set_leader(is_leader, gauge, false);
                    return Ok(());
                }
                () = tokio::time::sleep(TICK) => {}
            }
            // A failed heartbeat means the connection (and lock) is gone.
            sqlx::query("SELECT 1").execute(&mut *conn).await?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_key_is_stable() {
        assert_eq!(LEADER_LOCK_KEY, i64::from_be_bytes(*b"twnlhubl"));
    }

    #[test]
    fn set_leader_updates_flag_and_gauge() {
        let flag = AtomicBool::new(false);
        let gauge = prometheus::IntGauge::new("test_is_leader", "test").unwrap();
        set_leader(&flag, &gauge, true);
        assert!(flag.load(Ordering::SeqCst));
        assert_eq!(gauge.get(), 1);
        set_leader(&flag, &gauge, false);
        assert!(!flag.load(Ordering::SeqCst));
        assert_eq!(gauge.get(), 0);
    }
}
