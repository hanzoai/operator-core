//! Generic reconciler primitives shared by every operator.
//!
//! This module deliberately stops short of re-implementing
//! `kube_runtime::Controller` — kube-rs already does that well. What it
//! provides is the canonical retry/backoff cadence and a typed wrapper for
//! the `Action` requeue cases each operator's KMS / IAM / replicate
//! reconciler hits.

use kube::runtime::controller::Action;
use std::time::Duration;

/// Fast retry on a transient error (network blip, rate limit). 30 seconds
/// matches the cadence every existing operator already uses.
pub const ERROR_REQUEUE_SECS: u64 = 30;

/// Default healthy-resync interval. Most KMS-bridge CRDs use 60s.
pub const DEFAULT_RESYNC_SECS: u64 = 60;

/// Floor on `resyncInterval` to prevent a malicious CR from DDoSing the
/// upstream KMS / IAM service.
pub const MIN_RESYNC_SECS: u64 = 10;

/// Ceiling on `resyncInterval`. 24h means once-a-day reconciles are still
/// permitted but no longer.
pub const MAX_RESYNC_SECS: u64 = 86_400;

/// Clamp `raw` (typically read off `spec.resyncInterval` from a CR) into the
/// safe `[MIN_RESYNC_SECS, MAX_RESYNC_SECS]` band. Treats 0 as "unset" and
/// returns `DEFAULT_RESYNC_SECS`.
pub fn clamp_resync(raw: u64) -> u64 {
    if raw == 0 {
        DEFAULT_RESYNC_SECS
    } else {
        raw.clamp(MIN_RESYNC_SECS, MAX_RESYNC_SECS)
    }
}

/// Build a healthy-resync Action.
pub fn requeue_after(secs: u64) -> Action {
    Action::requeue(Duration::from_secs(secs))
}

/// Build the standard error-retry Action (30s backoff).
pub fn requeue_on_error() -> Action {
    Action::requeue(Duration::from_secs(ERROR_REQUEUE_SECS))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_yields_default() {
        assert_eq!(clamp_resync(0), DEFAULT_RESYNC_SECS);
    }

    #[test]
    fn clamps_below_min() {
        assert_eq!(clamp_resync(1), MIN_RESYNC_SECS);
        assert_eq!(clamp_resync(5), MIN_RESYNC_SECS);
    }

    #[test]
    fn clamps_above_max() {
        assert_eq!(clamp_resync(MAX_RESYNC_SECS + 1), MAX_RESYNC_SECS);
        assert_eq!(clamp_resync(u64::MAX), MAX_RESYNC_SECS);
    }

    #[test]
    fn passes_through_in_band() {
        assert_eq!(clamp_resync(60), 60);
        assert_eq!(clamp_resync(3600), 3600);
    }
}
