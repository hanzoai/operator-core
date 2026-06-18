//! Lease-based leader election for kube-rs operators.
//!
//! Uses Kubernetes Lease objects (`coordination.k8s.io/v1`). Only the holder
//! of the lease runs the controllers; all other replicas wait and retry every
//! 15 seconds.
//!
//! Generalized from the byte-identical implementations that previously lived
//! in `~/work/{lux,zoo}/operator/src/leader.rs`. Each operator configures a
//! unique `lease_name` and `identity_prefix` via `LeaderConfig`.

use k8s_openapi::api::coordination::v1::{Lease, LeaseSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::MicroTime;
use kube::api::{Api, Patch, PatchParams, PostParams};
use kube::Client;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{info, warn};

/// Default lease duration. Long enough to survive a pod restart but short
/// enough to fail over within a minute.
const LEASE_DURATION_SECONDS: i32 = 30;
const RENEW_INTERVAL_SECS: u64 = 10;
const RETRY_INTERVAL_SECS: u64 = 15;

/// Per-operator configuration for leader election. Each operator picks a
/// unique `lease_name` (e.g. `hanzo-operator-leader`, `lux-operator-leader`)
/// so multiple operators can coexist in the same cluster without contending
/// on a single lease.
#[derive(Clone, Debug)]
pub struct LeaderConfig {
    /// Lease object name. Must be unique per operator.
    pub lease_name: String,
    /// Identity prefix used when `HOSTNAME` is not set
    /// (e.g. `hanzo-operator-`). The PID is appended.
    pub identity_prefix: String,
}

/// Shared flag indicating whether this instance is the leader.
pub struct LeaderElection {
    is_leader: Arc<AtomicBool>,
    identity: String,
    namespace: String,
    client: Client,
    config: LeaderConfig,
}

impl LeaderElection {
    /// Construct a new leader election handle. The identity defaults to the
    /// `HOSTNAME` env var (the pod name in K8s) and falls back to
    /// `<identity_prefix><pid>` for local runs.
    pub fn new(client: Client, namespace: String, config: LeaderConfig) -> Self {
        let identity = std::env::var("HOSTNAME")
            .unwrap_or_else(|_| format!("{}{}", config.identity_prefix, std::process::id()));

        LeaderElection {
            is_leader: Arc::new(AtomicBool::new(false)),
            identity,
            namespace,
            client,
            config,
        }
    }

    /// Returns true if this instance currently holds the leader lease.
    pub fn is_leader(&self) -> bool {
        self.is_leader.load(Ordering::Relaxed)
    }

    /// Returns a clone of the is_leader flag for sharing with other tasks.
    pub fn leader_flag(&self) -> Arc<AtomicBool> {
        self.is_leader.clone()
    }

    /// Run the leader election loop. This never returns under normal
    /// operation. On shutdown (when `shutdown` resolves), it releases the
    /// lease.
    pub async fn run(&self, shutdown: tokio::sync::watch::Receiver<bool>) {
        let leases: Api<Lease> = Api::namespaced(self.client.clone(), &self.namespace);
        let mut shutdown = shutdown;

        loop {
            match self.try_acquire_or_renew(&leases).await {
                Ok(true) => {
                    if !self.is_leader.load(Ordering::Relaxed) {
                        info!(identity = %self.identity, lease = %self.config.lease_name, "Acquired leader lease");
                        self.is_leader.store(true, Ordering::Relaxed);
                    }
                    tokio::select! {
                        _ = tokio::time::sleep(std::time::Duration::from_secs(RENEW_INTERVAL_SECS)) => {}
                        _ = shutdown.changed() => {
                            self.release(&leases).await;
                            return;
                        }
                    }
                }
                Ok(false) => {
                    if self.is_leader.load(Ordering::Relaxed) {
                        warn!(identity = %self.identity, lease = %self.config.lease_name, "Lost leader lease");
                        self.is_leader.store(false, Ordering::Relaxed);
                    }
                    tokio::select! {
                        _ = tokio::time::sleep(std::time::Duration::from_secs(RETRY_INTERVAL_SECS)) => {}
                        _ = shutdown.changed() => {
                            return;
                        }
                    }
                }
                Err(e) => {
                    warn!(identity = %self.identity, lease = %self.config.lease_name, error = %e, "Leader election error, retrying");
                    if self.is_leader.load(Ordering::Relaxed) {
                        self.is_leader.store(false, Ordering::Relaxed);
                    }
                    tokio::select! {
                        _ = tokio::time::sleep(std::time::Duration::from_secs(RETRY_INTERVAL_SECS)) => {}
                        _ = shutdown.changed() => {
                            return;
                        }
                    }
                }
            }
        }
    }

    async fn try_acquire_or_renew(&self, leases: &Api<Lease>) -> anyhow::Result<bool> {
        let now = chrono::Utc::now();
        let lease_name = self.config.lease_name.as_str();

        match leases.get(lease_name).await {
            Ok(existing) => {
                let spec = existing.spec.as_ref();
                let holder = spec.and_then(|s| s.holder_identity.as_deref());
                let renew_time = spec.and_then(|s| s.renew_time.as_ref()).map(|t| t.0);
                let duration = spec
                    .and_then(|s| s.lease_duration_seconds)
                    .unwrap_or(LEASE_DURATION_SECONDS);
                let transitions = spec.and_then(|s| s.lease_transitions).unwrap_or(0);

                let is_expired = match renew_time {
                    Some(t) => now.signed_duration_since(t).num_seconds() > duration as i64,
                    None => true,
                };

                if holder == Some(self.identity.as_str()) {
                    let patch = serde_json::json!({
                        "spec": {
                            "renewTime": now.to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
                        }
                    });
                    leases
                        .patch(lease_name, &PatchParams::default(), &Patch::Merge(patch))
                        .await?;
                    Ok(true)
                } else if is_expired {
                    let patch = serde_json::json!({
                        "spec": {
                            "holderIdentity": self.identity,
                            "leaseDurationSeconds": LEASE_DURATION_SECONDS,
                            "acquireTime": now.to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
                            "renewTime": now.to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
                            "leaseTransitions": transitions + 1,
                        }
                    });
                    leases
                        .patch(lease_name, &PatchParams::default(), &Patch::Merge(patch))
                        .await?;
                    info!(
                        identity = %self.identity,
                        previous = holder.unwrap_or("<none>"),
                        lease = %lease_name,
                        "Took over expired leader lease"
                    );
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            Err(kube::Error::Api(err)) if err.code == 404 => {
                let lease = Lease {
                    metadata: kube::core::ObjectMeta {
                        name: Some(lease_name.to_string()),
                        namespace: Some(self.namespace.clone()),
                        ..Default::default()
                    },
                    spec: Some(LeaseSpec {
                        holder_identity: Some(self.identity.clone()),
                        lease_duration_seconds: Some(LEASE_DURATION_SECONDS),
                        acquire_time: Some(MicroTime(now)),
                        renew_time: Some(MicroTime(now)),
                        lease_transitions: Some(0),
                    }),
                };
                leases.create(&PostParams::default(), &lease).await?;
                info!(identity = %self.identity, lease = %lease_name, "Created leader lease");
                Ok(true)
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn release(&self, leases: &Api<Lease>) {
        if !self.is_leader.load(Ordering::Relaxed) {
            return;
        }
        info!(identity = %self.identity, lease = %self.config.lease_name, "Releasing leader lease");
        let patch = serde_json::json!({
            "spec": {
                "holderIdentity": null,
            }
        });
        let _ = leases
            .patch(
                &self.config.lease_name,
                &PatchParams::default(),
                &Patch::Merge(patch),
            )
            .await;
        self.is_leader.store(false, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_clone_is_cheap() {
        let cfg = LeaderConfig {
            lease_name: "test-leader".into(),
            identity_prefix: "test-".into(),
        };
        let dup = cfg.clone();
        assert_eq!(cfg.lease_name, dup.lease_name);
        assert_eq!(cfg.identity_prefix, dup.identity_prefix);
    }

    #[test]
    fn identity_prefix_used_for_pid_fallback() {
        // We can't easily construct LeaderElection without a Client, but we
        // can confirm the prefix flows through the Config struct correctly.
        let cfg = LeaderConfig {
            lease_name: "operator-leader".into(),
            identity_prefix: "operator-".into(),
        };
        assert_eq!(cfg.identity_prefix, "operator-");
    }
}
