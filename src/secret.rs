//! Helpers for materialising K8s `Secret` resources from KMS data.
//!
//! Centralises the **strict hijack guard** that every operator's KMS bridge
//! enforces:
//!
//! > Refuse to overwrite any Secret that lacks the
//! > `app.kubernetes.io/managed-by=<operator>` label AND isn't owned by the
//! > reconciling CR. The "brand-new (no labels AND no ownerReferences) →
//! > allowed" branch from older Go operators is REMOVED — an attacker with
//! > `secrets.create` in the target namespace must NOT be able to race-create
//! > a blank Secret and ride the overwrite.
//!
//! Also enforces the **control-byte rejection** rule: secret values
//! containing `\0` or C0 controls (except TAB, CR, LF) are rejected at
//! parse time. CR/LF are ALLOWED — PEM blocks, X.509 chains, pretty-printed
//! JSON all require them. `\0` stays rejected as the load-bearing exploit
//! primitive (env-var truncation on POSIX).

use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;

/// Standard label key for marking Secrets the operator manages.
pub const MANAGED_BY_LABEL: &str = "app.kubernetes.io/managed-by";

/// Returns true iff the given Secret is one we may safely overwrite:
/// either (a) carries the `managed-by=<operator>` label, or (b) has an
/// ownerReference whose UID matches `cr_uid`.
///
/// Pure function — no I/O, no allocation beyond the borrowed slice walks.
pub fn is_operator_managed(existing: &Secret, managed_by: &str, cr_uid: &str) -> bool {
    if let Some(labels) = &existing.metadata.labels {
        if labels.get(MANAGED_BY_LABEL).map(String::as_str) == Some(managed_by) {
            return true;
        }
    }
    if let Some(refs) = &existing.metadata.owner_references {
        if refs.iter().any(|r| r.uid == cr_uid) {
            return true;
        }
    }
    false
}

/// Reject any value that would silently change behaviour at the consumer.
/// `\0` truncates env vars on POSIX — that's the load-bearing exploit. Other
/// C0 controls (except TAB, CR, LF) are also refused. CR/LF must be allowed
/// because real-world secrets (PEM, X.509, JSON-pretty) require them.
pub fn validate_secret_value(value: &[u8]) -> Result<(), String> {
    for (i, &b) in value.iter().enumerate() {
        if b == 0 {
            return Err(format!(
                "secret value contains NUL byte at offset {i} (env-var truncation hazard)"
            ));
        }
        if b < 0x20 && b != b'\t' && b != b'\r' && b != b'\n' {
            return Err(format!(
                "secret value contains control byte 0x{b:02x} at offset {i}"
            ));
        }
    }
    Ok(())
}

/// Build an `OwnerReference` pointing at a CR. The CR must have a UID set
/// (i.e. has been created on the API server already).
pub fn owner_ref(api_version: &str, kind: &str, name: &str, uid: &str) -> OwnerReference {
    OwnerReference {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        name: name.to_string(),
        uid: uid.to_string(),
        controller: Some(true),
        block_owner_deletion: Some(true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::Secret;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use std::collections::BTreeMap;

    #[test]
    fn rejects_nul_byte() {
        let v = b"hello\0world";
        let err = validate_secret_value(v).unwrap_err();
        assert!(err.contains("NUL"));
    }

    #[test]
    fn rejects_other_c0_controls() {
        let v = b"hello\x07world"; // BEL
        assert!(validate_secret_value(v).is_err());
    }

    #[test]
    fn allows_tab_cr_lf() {
        // PEM headers / pretty JSON / multi-line config all have these.
        let v = b"line1\nline2\r\nline3\there";
        assert!(validate_secret_value(v).is_ok());
    }

    #[test]
    fn allows_high_bytes() {
        // Random binary blobs (KMS may store DER bundles).
        let v: &[u8] = &[0x20, 0xff, 0x80, 0x42];
        assert!(validate_secret_value(v).is_ok());
    }

    #[test]
    fn unlabelled_secret_is_not_managed() {
        let s = Secret {
            metadata: ObjectMeta::default(),
            ..Default::default()
        };
        assert!(!is_operator_managed(&s, "hanzo-operator", "cr-uid"));
    }

    #[test]
    fn label_match_is_managed() {
        let mut labels = BTreeMap::new();
        labels.insert(MANAGED_BY_LABEL.to_string(), "hanzo-operator".to_string());
        let s = Secret {
            metadata: ObjectMeta {
                labels: Some(labels),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(is_operator_managed(&s, "hanzo-operator", "cr-uid"));
    }

    #[test]
    fn label_mismatch_is_not_managed() {
        let mut labels = BTreeMap::new();
        labels.insert(MANAGED_BY_LABEL.to_string(), "another-operator".to_string());
        let s = Secret {
            metadata: ObjectMeta {
                labels: Some(labels),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(!is_operator_managed(&s, "hanzo-operator", "cr-uid"));
    }

    #[test]
    fn matching_owner_ref_is_managed() {
        let owner = OwnerReference {
            api_version: "secrets.hanzo.ai/v1alpha1".to_string(),
            kind: "KMSSecret".to_string(),
            name: "my-cr".to_string(),
            uid: "cr-uid-123".to_string(),
            controller: Some(true),
            block_owner_deletion: Some(true),
        };
        let s = Secret {
            metadata: ObjectMeta {
                owner_references: Some(vec![owner]),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(is_operator_managed(&s, "anything", "cr-uid-123"));
    }
}
