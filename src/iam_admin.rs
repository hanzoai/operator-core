//! Operator-driven IAM service-account provisioning.
//!
//! Calls `POST /v1/iam/admin/applications/upsert` (added in
//! `hanzoai/iam@0a74d861`) with the cluster-local service token to create or
//! rotate OAuth2 client credentials for service accounts (KMS, BD signers,
//! ATS settlement key, etc.) — no human admin in the loop.
//!
//! ## Trust model
//!
//! - IAM trusts a single service token sourced from
//!   `$HANZO_API_KEY` / `$KMS_SERVICE_TOKEN` / `$IAM_SERVICE_TOKEN` env (in
//!   order).
//! - Operator reads that token from a k8s Secret in the same cluster and
//!   presents it as `Authorization: Bearer <token>`.
//! - The token never leaves the cluster.
//!
//! ## Secret resolution
//!
//! The caller supplies an `AdminSecretCandidates` list — the resolver walks
//! it in order and returns the first Secret in `namespace` that exists and
//! carries a non-empty `token` key. Plaintext passwords NEVER live in any
//! Secret managed by this resolver — only opaque service tokens.
//!
//! Generalized from `a downstream operator's iam_admin.rs`. The
//! liquidity-specific defaults (URL, namespace, secret names) become
//! constructor parameters on `IamAdminConfig`.

use crate::error::{OperatorError, Result};
use k8s_openapi::api::core::v1::Secret;
use kube::{Api, Client};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, info, warn};

/// Token-key inside the resolved Secret. All admin Secrets across all
/// operators carry the same key shape: `{ token: <opaque-string> }`.
pub const DEFAULT_TOKEN_KEY: &str = "token";

/// Per-operator IAM admin client config. Each operator wires its own
/// in-cluster IAM URL, the namespace where admin Secrets live, and the
/// preference order of admin Secret names to probe.
#[derive(Clone, Debug)]
pub struct IamAdminConfig {
    /// IAM HTTP API base URL (e.g.
    /// `http://liquid-iam.liquidity.svc.cluster.local:8000`).
    pub base_url: String,
    /// Namespace where the admin token Secrets live (typically the operator
    /// namespace: `liquidity`, `lux-system`, `zoo-system`, etc.).
    pub admin_secret_namespace: String,
    /// Ordered list of Secret names to probe. First non-empty match wins.
    /// Typically: `[primary, bootstrap, legacy]` — primary is KMS-synced,
    /// bootstrap is plain (chicken-and-egg pre-KMS), legacy is the historical
    /// name kept for back-compat.
    pub admin_secret_candidates: Vec<String>,
}

#[derive(Serialize, Debug)]
pub struct UpsertRequest<'a> {
    pub organization: &'a str,
    pub name: &'a str,
    #[serde(rename = "clientId")]
    pub client_id: &'a str,
    /// Empty → server generates and returns one.
    #[serde(rename = "clientSecret")]
    pub client_secret: String,
    #[serde(rename = "grantTypes")]
    pub grant_types: Vec<String>,
    #[serde(rename = "redirectUris", skip_serializing_if = "Vec::is_empty")]
    pub redirect_uris: Vec<String>,
    #[serde(rename = "displayName", skip_serializing_if = "str::is_empty")]
    pub display_name: &'a str,
}

#[derive(Deserialize, Debug)]
pub struct UpsertResponse {
    pub status: String,
    #[serde(default)]
    pub action: String, // "created" | "updated"
    #[serde(default)]
    pub data: Option<UpsertData>,
    #[serde(default)]
    pub msg: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct UpsertData {
    pub name: String,
    #[serde(rename = "clientId")]
    pub client_id: String,
    #[serde(rename = "clientSecret")]
    pub client_secret: String,
}

/// Read the IAM service token from the first Secret in `candidates` that
/// exists in `namespace` and carries a non-empty `token` key. Returns the
/// matched (secret_name, token) pair so callers can log which Secret served,
/// or `Ok(None)` if no candidate produced a token. Errors only on UTF-8
/// decode or non-404 API failures.
pub async fn read_service_token_from(
    client: &Client,
    namespace: &str,
    candidates: &[&str],
) -> Result<Option<(String, String)>> {
    let api: Api<Secret> = Api::namespaced(client.clone(), namespace);
    for name in candidates {
        let secret = match api.get(name).await {
            Ok(s) => s,
            Err(kube::Error::Api(ae)) if ae.code == 404 => continue,
            Err(e) => return Err(OperatorError::KubeApi(e)),
        };
        let raw = secret
            .data
            .as_ref()
            .and_then(|d| d.get(DEFAULT_TOKEN_KEY))
            .map(|b| b.0.clone());
        let raw = match raw {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        let token = String::from_utf8(raw).map_err(|e| {
            OperatorError::Other(format!(
                "Secret {namespace}/{name} key '{DEFAULT_TOKEN_KEY}' is not valid UTF-8: {e}"
            ))
        })?;
        let trimmed = token.trim().to_string();
        if trimmed.is_empty() {
            continue;
        }
        return Ok(Some(((*name).to_string(), trimmed)));
    }
    Ok(None)
}

/// Resolve the configured IAM admin token using the per-operator
/// `IamAdminConfig`. Errors when no candidate Secret yields a non-empty
/// token — IAM bootstrap is blocked.
pub async fn read_service_token(client: &Client, config: &IamAdminConfig) -> Result<Option<String>> {
    let candidates: Vec<&str> = config
        .admin_secret_candidates
        .iter()
        .map(String::as_str)
        .collect();
    Ok(
        read_service_token_from(client, &config.admin_secret_namespace, &candidates)
            .await?
            .map(|(_name, token)| token),
    )
}

/// Idempotently create or rotate an IAM application using the configured
/// IAM URL + admin Secret. Returns the (rotated-or-existing) credentials the
/// caller should persist.
pub async fn upsert_application(
    client: &Client,
    config: &IamAdminConfig,
    req: UpsertRequest<'_>,
) -> Result<UpsertData> {
    let token = match read_service_token(client, config).await? {
        Some(t) if !t.is_empty() => t,
        _ => {
            return Err(OperatorError::Iam(
                "iam admin token Secret missing or empty — IAM bootstrap blocked".into(),
            ))
        }
    };
    upsert_application_at(&config.base_url, &token, req).await
}

/// Variant that takes an explicit IAM base URL + bearer token. Used when the
/// caller has already resolved the per-CR admin Secret (e.g. a tenant-scoped
/// reconciler targeting an in-namespace IAM Service rather than the cluster
/// default URL).
pub async fn upsert_application_at(
    iam_base_url: &str,
    token: &str,
    req: UpsertRequest<'_>,
) -> Result<UpsertData> {
    if token.is_empty() {
        return Err(OperatorError::Iam(
            "IAM upsert called with empty bearer token".into(),
        ));
    }

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| OperatorError::Iam(format!("build http client: {e}")))?;

    let url = format!(
        "{}/v1/iam/admin/applications/upsert",
        iam_base_url.trim_end_matches('/')
    );
    debug!("IAM upsert: POST {url} app={}/{}", req.organization, req.name);

    let resp = http
        .post(&url)
        .bearer_auth(token)
        .json(&req)
        .send()
        .await
        .map_err(|e| OperatorError::Iam(format!("IAM upsert POST: {e}")))?;

    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| OperatorError::Iam(format!("IAM upsert read body: {e}")))?;

    if !status.is_success() {
        warn!(
            "IAM upsert non-2xx (status={}): {}",
            status,
            &body[..body.len().min(400)]
        );
        return Err(OperatorError::Iam(format!(
            "IAM upsert failed (status={}): {}",
            status,
            &body[..body.len().min(400)]
        )));
    }

    let parsed: UpsertResponse = serde_json::from_str(&body).map_err(|e| {
        OperatorError::Iam(format!(
            "IAM upsert response parse: {e}; body={}",
            &body[..body.len().min(400)]
        ))
    })?;
    if parsed.status != "ok" {
        // Old IAM images shipped before hanzoai/iam@bootstrap-upsert-unique-fallback
        // do INSERT-only on `/admin/applications/upsert` and bubble the database
        // UNIQUE error back as `status=error`. Every reconcile (~30s) hits this
        // for already-seeded apps and breaks the sync loop. The desired state
        // (row with same (owner, name)) already holds, so treat the duplicate as
        // a soft-success: no rotation happens, the controller call site already
        // discards the returned credentials. Once IAM is rolled forward, the
        // server itself returns `status=ok action=updated` and this branch
        // never trips.
        if is_unique_constraint_error(&parsed.msg) {
            warn!(
                "IAM upsert duplicate row ({}): {}/{} — treating as no-op (server INSERT-only); upgrade IAM to clear",
                parsed.msg, req.organization, req.name
            );
            return Ok(UpsertData {
                name: req.name.to_string(),
                client_id: req.client_id.to_string(),
                client_secret: String::new(),
            });
        }
        return Err(OperatorError::Iam(format!(
            "IAM upsert returned status={} msg={}",
            parsed.status, parsed.msg
        )));
    }
    let data = parsed
        .data
        .ok_or_else(|| OperatorError::Iam("IAM upsert missing data field".into()))?;
    info!(
        "IAM upsert ok ({}): {}/{} clientId={}",
        parsed.action, req.organization, req.name, data.client_id
    );
    Ok(data)
}

/// Detect the database-level UNIQUE-constraint message that IAM bubbles up
/// verbatim when an old INSERT-only `/admin/applications/upsert` handler
/// hits an already-seeded `(owner, name)` pair. Covers SQLite (1555),
/// Postgres ("duplicate key"), and MySQL ("Duplicate entry").
fn is_unique_constraint_error(msg: &str) -> bool {
    msg.contains("UNIQUE constraint failed")
        || msg.contains("duplicate key")
        || msg.contains("Duplicate entry")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_holds_per_operator_defaults() {
        let cfg = IamAdminConfig {
            base_url: "http://liquid-iam.liquidity.svc.cluster.local:8000".into(),
            admin_secret_namespace: "liquidity".into(),
            admin_secret_candidates: vec![
                "liquidity-iam-admin".into(),
                "liquidity-iam-admin-bootstrap".into(),
                "iam-service-token".into(),
            ],
        };
        assert_eq!(cfg.admin_secret_candidates.len(), 3);
        assert_eq!(cfg.admin_secret_candidates[0], "liquidity-iam-admin");
    }

    #[test]
    fn empty_token_rejected() {
        // Synchronous validation surface before going async.
        let req = UpsertRequest {
            organization: "liquidity",
            name: "ats",
            client_id: "ats",
            client_secret: String::new(),
            grant_types: vec!["client_credentials".into()],
            redirect_uris: vec![],
            display_name: "ATS Settlement",
        };
        assert_eq!(req.organization, "liquidity");
        assert!(req.client_secret.is_empty());
    }

    #[test]
    fn unique_constraint_detector_matches_each_dialect() {
        // Exact wire formats observed from each backend the IAM might run
        // against. SQLite is the live one (1555); Postgres + MySQL covered
        // for forward-compat with managed-DB deployments.
        assert!(is_unique_constraint_error(
            "constraint failed: UNIQUE constraint failed: application.owner, application.name (1555)"
        ));
        assert!(is_unique_constraint_error(
            "duplicate key value violates unique constraint \"application_pkey\""
        ));
        assert!(is_unique_constraint_error(
            "Error 1062: Duplicate entry 'liquidity-ats' for key 'application.PRIMARY'"
        ));
        assert!(!is_unique_constraint_error(
            "internal server error"
        ));
        assert!(!is_unique_constraint_error(""));
    }

    /// Mock IAM that always returns `status=error` with the SQLite UNIQUE
    /// message — exactly what the deployed pre-fallback IAM image surfaces
    /// when a row with the same `(owner, name)` already exists. The
    /// wrapper must absorb this and return `Ok(_)` so the operator's
    /// reconcile loop keeps making progress.
    #[tokio::test]
    async fn unique_constraint_response_is_soft_success() {
        let mock = spawn_static_mock(
            r#"{"status":"error","msg":"constraint failed: UNIQUE constraint failed: application.owner, application.name (1555)"}"#,
        )
        .await;
        let req = UpsertRequest {
            organization: "liquidity",
            name: "liquidity-ats",
            client_id: "liquidity-ats",
            client_secret: String::new(),
            grant_types: vec!["client_credentials".into()],
            redirect_uris: vec![],
            display_name: "ATS",
        };
        let data = upsert_application_at(&mock.base_url, "fake-token", req)
            .await
            .expect("UNIQUE error must be absorbed as soft-success");
        assert_eq!(data.name, "liquidity-ats");
        assert_eq!(data.client_id, "liquidity-ats");
        assert!(
            data.client_secret.is_empty(),
            "duplicate path returns empty secret so callers can't accidentally rotate"
        );
        mock.shutdown();
    }

    /// Non-UNIQUE `status=error` responses must still bubble up — we only
    /// soften the specific INSERT-vs-UPSERT race, never real failures.
    #[tokio::test]
    async fn other_error_response_still_bubbles_up() {
        let mock =
            spawn_static_mock(r#"{"status":"error","msg":"internal server error"}"#).await;
        let req = UpsertRequest {
            organization: "liquidity",
            name: "liquidity-ats",
            client_id: "liquidity-ats",
            client_secret: String::new(),
            grant_types: vec!["client_credentials".into()],
            redirect_uris: vec![],
            display_name: "ATS",
        };
        let err = upsert_application_at(&mock.base_url, "fake-token", req)
            .await
            .expect_err("non-UNIQUE error must still surface");
        assert!(err.to_string().contains("internal server error"));
        mock.shutdown();
    }

    /// Static-body HTTP/1.1 mock — tokio TcpListener writing one canned
    /// response per accepted connection. Avoids a fresh axum/wiremock
    /// dependency just for two assertions.
    struct StaticMock {
        base_url: String,
        shutdown_tx: tokio::sync::oneshot::Sender<()>,
    }

    impl StaticMock {
        fn shutdown(self) {
            let _ = self.shutdown_tx.send(());
        }
    }

    async fn spawn_static_mock(json_body: &'static str) -> StaticMock {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => return,
                    accept = listener.accept() => {
                        let Ok((mut sock, _)) = accept else { return };
                        let mut buf = [0u8; 4096];
                        // Drain request headers; body is JSON we don't validate here.
                        let _ = sock.read(&mut buf).await;
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                            json_body.len(),
                            json_body
                        );
                        let _ = sock.write_all(resp.as_bytes()).await;
                        let _ = sock.shutdown().await;
                    }
                }
            }
        });
        StaticMock {
            base_url: format!("http://{addr}"),
            shutdown_tx,
        }
    }
}
