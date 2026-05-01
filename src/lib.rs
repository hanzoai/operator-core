//! # hanzo-operator-core
//!
//! Shared reconciler primitives for the Hanzo, Lux, Liquidity, and Zoo
//! Kubernetes operator family. The four org operators (`liquidity/operator`,
//! `lux/operator`, `zoo/operator`, and the future Rust port of
//! `hanzo/operator`) each carry per-org CRDs (`LiquidNetwork`, `LuxNetwork`,
//! ...) but share ~80% of their controller plumbing — leader election, the
//! IAM admin upsert client, KMS secret materialisation, status-condition
//! shape, error type, retry cadence.
//!
//! This crate is the canonical home for that shared plumbing. Per
//! `~/.claude/CLAUDE.md`: one and only one way to do everything; forward-only;
//! no back-compat shims.
//!
//! ## What lives here
//!
//! | Module        | What it owns                                                            |
//! |---------------|-------------------------------------------------------------------------|
//! | [`error`]     | `OperatorError` — single canonical error type for every operator.       |
//! | [`leader`]    | `LeaderElection` — `coordination.k8s.io/v1` lease loop.                 |
//! | [`iam_admin`] | IAM admin client (`POST /v1/iam/admin/applications/upsert`).            |
//! | [`secret`]    | Strict hijack guard + `\0` rejection for KMS-projected K8s Secrets.     |
//! | [`status`]    | Standard `status.conditions` mint helpers.                              |
//! | [`reconciler`]| `Action` requeue cadence + `clamp_resync`.                              |
//!
//! ## What lives in each operator
//!
//! - Per-org CRD types (`LiquidNetwork`, `LuxNetwork`, ...) — kept in each
//!   operator because the API group is brand-specific
//!   (`liquid.network`, `lux.network`, `zoo.ngo`, etc.) and the field set
//!   diverges per platform.
//! - The org-specific reconcile bodies for each CRD — they call into this
//!   crate for leader/IAM/secret/status but own their domain logic.
//! - The KMSSecret reconciler body itself — the strict hijack guard and
//!   `\0` rejection live here, but each operator owns its KMS API group
//!   (`secrets.liquid.network`, `secrets.lux.network`, ...) and wires the
//!   reconciler with the helpers from this crate.

pub mod error;
pub mod iam_admin;
pub mod leader;
pub mod reconciler;
pub mod secret;
pub mod status;

pub use error::{OperatorError, Result};
pub use iam_admin::{IamAdminConfig, UpsertData, UpsertRequest, UpsertResponse};
pub use leader::{LeaderConfig, LeaderElection};
pub use reconciler::{
    clamp_resync, requeue_after, requeue_on_error, DEFAULT_RESYNC_SECS, ERROR_REQUEUE_SECS,
    MAX_RESYNC_SECS, MIN_RESYNC_SECS,
};
pub use secret::{is_operator_managed, owner_ref, validate_secret_value, MANAGED_BY_LABEL};
pub use status::{
    convergence, kind, ready_false, ready_true, reason, synced_failed, synced_ok,
    truncate_message, upsert_condition, CONDITION_MESSAGE_MAX,
};
