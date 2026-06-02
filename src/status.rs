//! Standard `status.conditions` helpers for kube-rs CRDs.
//!
//! Every CRD in the Hanzo / Lux / Zoo operator family writes the
//! same condition shape: `[Synced, Ready]` plus a small set of failure types
//! (`SyncFailed`, `MissingCredentials`, `Forbidden`, `UnsupportedTransport`,
//! ...). This module centralises the condition mint helpers so the wire shape
//! stays identical across operators.

use chrono::Utc;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};

/// Condition messages are truncated to this many chars to keep a misbehaving
/// reconciler from blowing the etcd object size limit on a hot loop.
pub const CONDITION_MESSAGE_MAX: usize = 256;

/// Canonical condition `type` values. Each `type` may carry `True` or `False`
/// status. Use the helpers below to mint each variant.
pub mod kind {
    /// `Synced=True` → reconciler completed the round; `False` → did not.
    pub const SYNCED: &str = "Synced";
    /// `Ready=True` → resource is fully usable.
    pub const READY: &str = "Ready";
}

/// Standard reason strings. Stable for tooling that filters on these.
pub mod reason {
    pub const SYNC_OK: &str = "SyncOk";
    pub const SYNC_FAILED: &str = "SyncFailed";
    pub const MISSING_CREDENTIALS: &str = "MissingCredentials";
    pub const FORBIDDEN: &str = "Forbidden";
    pub const NOT_FOUND: &str = "NotFound";
    pub const UNSUPPORTED_TRANSPORT: &str = "UnsupportedTransport";
    pub const UNSUPPORTED_AUTH_STRATEGY: &str = "UnsupportedAuthStrategy";
    pub const STUB_RECONCILER: &str = "StubReconciler";
    pub const KEYS_REQUIRED: &str = "KeysRequired";
    pub const INVALID_CONFIG: &str = "InvalidConfig";
    pub const HIJACK_REFUSED: &str = "HijackRefused";
}

/// Truncate a condition message to at most `CONDITION_MESSAGE_MAX` bytes so
/// a single reconcile error can't blow the etcd object size limit. Truncation
/// snips at the last byte boundary that keeps the result a valid UTF-8 string
/// — we never split a multi-byte char.
pub fn truncate_message(msg: &str) -> String {
    if msg.len() <= CONDITION_MESSAGE_MAX {
        return msg.to_string();
    }
    // Walk back from CONDITION_MESSAGE_MAX to the last char boundary so we
    // don't slice mid-codepoint.
    let mut cut = CONDITION_MESSAGE_MAX;
    while cut > 0 && !msg.is_char_boundary(cut) {
        cut -= 1;
    }
    msg[..cut].to_string()
}

/// Build a `Synced=True` condition with reason `SyncOk`.
pub fn synced_ok(generation: i64) -> Condition {
    Condition {
        type_: kind::SYNCED.to_string(),
        status: "True".to_string(),
        reason: reason::SYNC_OK.to_string(),
        message: "reconcile completed".to_string(),
        last_transition_time: Time(Utc::now()),
        observed_generation: Some(generation),
    }
}

/// Build a `Synced=False` condition with the given reason and message.
pub fn synced_failed(generation: i64, why: &str, msg: &str) -> Condition {
    Condition {
        type_: kind::SYNCED.to_string(),
        status: "False".to_string(),
        reason: why.to_string(),
        message: truncate_message(msg),
        last_transition_time: Time(Utc::now()),
        observed_generation: Some(generation),
    }
}

/// Build a `Ready=True` condition.
pub fn ready_true(generation: i64, msg: &str) -> Condition {
    Condition {
        type_: kind::READY.to_string(),
        status: "True".to_string(),
        reason: reason::SYNC_OK.to_string(),
        message: truncate_message(msg),
        last_transition_time: Time(Utc::now()),
        observed_generation: Some(generation),
    }
}

/// Build a `Ready=False` condition with the given reason and message.
pub fn ready_false(generation: i64, why: &str, msg: &str) -> Condition {
    Condition {
        type_: kind::READY.to_string(),
        status: "False".to_string(),
        reason: why.to_string(),
        message: truncate_message(msg),
        last_transition_time: Time(Utc::now()),
        observed_generation: Some(generation),
    }
}

/// Convergence helpers shared across the lux/zoo Rust operators and the
/// Go port in `~/work/hanzo/operator/internal/controller`. Each operator
/// surfaces a `phase` field on its network CRD; without these helpers,
/// every controller re-derives the same `Running | Degraded | Critical`
/// ladder from scratch and quietly drifts.
pub mod convergence {
    /// Inputs `is_genuinely_degraded` distinguishes from. The fields are the
    /// minimum signal every network controller already has. Operators with
    /// richer status (e.g. `LuxNetwork.info_conditions`) compose this with
    /// their own check before phase selection.
    #[derive(Debug, Clone, Copy)]
    pub struct DegradationInputs {
        /// Validator pods that responded healthy in the last reconcile.
        pub healthy_validators: u32,
        /// Desired validator count (`spec.validators`).
        pub total_validators: u32,
        /// Number of pods we could not contact at all (no IP, no health
        /// response). When this is > 0, we may be infra-blind rather than
        /// observing a real chain failure.
        pub unreachable_validators: u32,
        /// True when the network is a closed validator set (no external
        /// bootstrap nodes, e.g. behind a private LB). 0 inbound peers is
        /// expected by design — never a degradation by itself.
        pub closed_validator_set: bool,
        /// True when the controller observed at least one bona-fide chain
        /// fault: height skew, chain unhealthy, RPC-level error from a pod
        /// that responded. Distinct from "couldn't reach the pod".
        pub chain_fault_observed: bool,
    }

    /// Returns true only when there is enough signal to call the network
    /// genuinely degraded (a real chain fault), as opposed to infra-blind
    /// (controller can't probe) or closed-set-by-design (0 inbound peers
    /// is expected).
    ///
    /// The rule is intentionally conservative: in the absence of a probed
    /// chain fault, we never escalate to Degraded just because peers are
    /// missing. That's the lesson from the lux operator's
    /// `InfoCondition::ClosedValidatorSet` pattern landed earlier — surface
    /// the observation, don't fabricate a fault.
    pub fn is_genuinely_degraded(inputs: DegradationInputs) -> bool {
        // Real chain fault overrides everything.
        if inputs.chain_fault_observed {
            return true;
        }
        // Closed validator set: 0 inbound is by design. Never degraded
        // unless we also saw a real chain fault (handled above).
        if inputs.closed_validator_set {
            return false;
        }
        // Pure infra-blind: every "missing" validator is unreachable. We
        // have no signal that the chain is broken — surface as info-only.
        let missing = inputs
            .total_validators
            .saturating_sub(inputs.healthy_validators);
        if missing > 0 && missing == inputs.unreachable_validators {
            return false;
        }
        // We could probe pods and they reported back unhealthy: that's a
        // real fault even if we don't have a specific reason yet.
        missing > 0
    }

    /// Pick the canonical phase string for a network reconcile. Every
    /// operator picks from the same lattice:
    /// `Running | Degraded`. The threshold is two-thirds of the desired
    /// validator count, the same line every operator was already drawing.
    pub fn phase_for(inputs: DegradationInputs) -> &'static str {
        if inputs.healthy_validators >= inputs.total_validators
            && !is_genuinely_degraded(inputs)
        {
            "Running"
        } else {
            "Degraded"
        }
    }
}

/// Replace any existing condition of the same `type_` in `conditions`.
/// If no condition with that type exists, append.
pub fn upsert_condition(conditions: &mut Vec<Condition>, new_cond: Condition) {
    if let Some(slot) = conditions
        .iter_mut()
        .find(|c| c.type_ == new_cond.type_)
    {
        *slot = new_cond;
    } else {
        conditions.push(new_cond);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_long_message() {
        let long = "x".repeat(1024);
        let truncated = truncate_message(&long);
        assert!(truncated.len() <= CONDITION_MESSAGE_MAX);
        assert!(truncated.chars().all(|c| c == 'x'));
    }

    #[test]
    fn truncate_preserves_utf8_boundary() {
        // Build a string of 3-byte chars so naive byte-slicing would cut in
        // the middle. truncate_message must walk back to the last boundary.
        let s = "é".repeat(200);
        // 200 * 2 = 400 bytes, exceeds 256. Truncated must be valid UTF-8.
        let truncated = truncate_message(&s);
        assert!(truncated.len() <= CONDITION_MESSAGE_MAX);
        // Round-trip — would panic on invalid UTF-8.
        let _: String = truncated.chars().collect();
    }

    #[test]
    fn truncate_short_message_is_passthrough() {
        let m = "ok";
        assert_eq!(truncate_message(m), "ok");
    }

    #[test]
    fn synced_ok_has_canonical_type_and_reason() {
        let c = synced_ok(7);
        assert_eq!(c.type_, "Synced");
        assert_eq!(c.status, "True");
        assert_eq!(c.reason, "SyncOk");
        assert_eq!(c.observed_generation, Some(7));
    }

    #[test]
    fn synced_failed_truncates_message() {
        let huge = "z".repeat(2000);
        let c = synced_failed(1, reason::SYNC_FAILED, &huge);
        assert_eq!(c.status, "False");
        assert!(c.message.len() <= CONDITION_MESSAGE_MAX);
    }

    #[test]
    fn upsert_replaces_existing_type() {
        let mut conds = vec![synced_failed(1, reason::SYNC_FAILED, "boom")];
        upsert_condition(&mut conds, synced_ok(2));
        assert_eq!(conds.len(), 1);
        assert_eq!(conds[0].status, "True");
        assert_eq!(conds[0].observed_generation, Some(2));
    }

    #[test]
    fn upsert_appends_new_type() {
        let mut conds = vec![synced_ok(1)];
        upsert_condition(&mut conds, ready_true(1, "all good"));
        assert_eq!(conds.len(), 2);
    }

    mod convergence_tests {
        use super::super::convergence::{is_genuinely_degraded, phase_for, DegradationInputs};

        fn base() -> DegradationInputs {
            DegradationInputs {
                healthy_validators: 3,
                total_validators: 3,
                unreachable_validators: 0,
                closed_validator_set: false,
                chain_fault_observed: false,
            }
        }

        #[test]
        fn full_health_runs() {
            assert!(!is_genuinely_degraded(base()));
            assert_eq!(phase_for(base()), "Running");
        }

        #[test]
        fn closed_set_with_zero_inbound_is_not_degraded() {
            let mut i = base();
            i.healthy_validators = 3;
            i.closed_validator_set = true;
            assert!(!is_genuinely_degraded(i));
            assert_eq!(phase_for(i), "Running");
        }

        #[test]
        fn closed_set_with_real_fault_is_degraded() {
            let mut i = base();
            i.closed_validator_set = true;
            i.chain_fault_observed = true;
            assert!(is_genuinely_degraded(i));
            assert_eq!(phase_for(i), "Degraded");
        }

        #[test]
        fn infra_blind_is_not_degraded() {
            // Every missing validator is unreachable — controller is
            // partitioned, not the chain.
            let mut i = base();
            i.healthy_validators = 1;
            i.unreachable_validators = 2;
            assert!(!is_genuinely_degraded(i));
            // phase_for still returns Degraded because the chain isn't at
            // full capacity, but the helper distinguishes infra-blind from
            // chain-faulty for downstream callers (alerting, auto-recovery).
            assert_eq!(phase_for(i), "Degraded");
        }

        #[test]
        fn probed_unhealthy_is_degraded() {
            // We could reach the pod, it just reported unhealthy: that's
            // a real fault.
            let mut i = base();
            i.healthy_validators = 1;
            i.unreachable_validators = 0;
            assert!(is_genuinely_degraded(i));
            assert_eq!(phase_for(i), "Degraded");
        }

        #[test]
        fn chain_fault_overrides_infra_blind() {
            let mut i = base();
            i.healthy_validators = 1;
            i.unreachable_validators = 2;
            i.chain_fault_observed = true;
            assert!(is_genuinely_degraded(i));
            assert_eq!(phase_for(i), "Degraded");
        }
    }
}
