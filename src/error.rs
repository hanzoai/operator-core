//! Canonical error type for every operator built on `hanzo-operator-core`.
//!
//! Convergence target for the per-org `OperatorError` variants that previously
//! existed in lux/zoo operators. Each variant maps 1:1 to a single
//! failure domain — no overlap, no wrappers around `Other(String)` for new
//! cases.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum OperatorError {
    #[error("Kubernetes API error: {0}")]
    KubeApi(#[from] kube::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Reconciliation error: {0}")]
    Reconcile(String),

    #[error("MPC error: {0}")]
    Mpc(String),

    #[error("KMS error: {0}")]
    Kms(String),

    #[error("IAM error: {0}")]
    Iam(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, OperatorError>;
