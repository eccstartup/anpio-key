//! Single coordinated signing operation, with injectable clock and backend.
use super::http::CanonicalHttpRequest;
use super::origin::{audit_options, OriginProof, SignedOrigin};
use crate::error::{KeydError, Result};
use crate::persistence::{
    catalog::KeyRecord, clock::Clock, requests::RequestStatus, requests::Reservation, Database,
};
use serde_json::{json, Value};

/// 一次签名的产物,由各自的 backend 填好;写库和收尾是共用的一段。
struct Produced {
    result: Value,
    created_at: i64,
    expires_at: i64,
    signature_base_digest: String,
    /// 只有 origin proof 有:审计里那一段 proof options。
    audit: Option<Value>,
}

/// Caller holds the coordinator through both transactions and the backend call.
/// Backend errors may follow signing, so only KEY_LOCKED is a definite non-sign.
pub(crate) fn execute(
    db: &mut Database,
    principal: &str,
    grant_id: &str,
    request_id: &str,
    canonical: &CanonicalHttpRequest,
    clock: &dyn Clock,
    backend: impl FnOnce(&KeyRecord, i64, i64) -> Result<crate::sign::rfc9421::Signed>,
) -> Result<RequestStatus> {
    let start = clock.now()?;
    let reservation = db.reserve_http(principal, grant_id, request_id, canonical, start)?;
    run(db, principal, request_id, reservation, clock, |key, _, expiry, deadline| {
        let signed = backend(key, expiry, deadline)?;
        let expiry = signed
            .expires_at
            .ok_or_else(|| KeydError::Protocol("missing profile expiry".into()))?;
        let created_at = signed
            .created_at
            .ok_or_else(|| KeydError::Protocol("missing profile creation time".into()))?;
        // Upstream returns generated headers only. Preserve the profile's covered
        // content-type so transports cannot replace it with their default. Do not
        // persist arbitrary caller headers (which may carry API credentials).
        let mut headers = signed.headers;
        if let Some(value) = canonical.signing_request().headers.get("content-type") {
            headers.insert("content-type".into(), value.clone());
        }
        Ok(Produced {
            result: json!({"request_id":request_id,"url":canonical.signing_request().url,"headers":headers,"covered":signed.covered,"expires_at":expiry}),
            created_at,
            expires_at: expiry,
            signature_base_digest: signed
                .signature_base_digest
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
            audit: None,
        })
    })
}

/// ANP origin proof:签名基由 `anp` 拼,`created` 用 daemon 的钟。
///
/// `expires` 可以缺省 —— 上游允许;但缓存窗口仍按 profile 上限算,否则一条
/// 没有 expires 的缓存结果会一直可取。
pub(crate) fn execute_origin(
    db: &mut Database,
    principal: &str,
    grant_id: &str,
    request_id: &str,
    proof: &OriginProof,
    clock: &dyn Clock,
    backend: impl FnOnce(&KeyRecord, &OriginProof, i64) -> Result<SignedOrigin>,
) -> Result<RequestStatus> {
    let start = clock.now()?;
    let reservation = db.reserve_origin(principal, grant_id, request_id, proof, start)?;
    run(db, principal, request_id, reservation, clock, |key, created, _, _| {
        let signed = backend(key, proof, created)?;
        let expires_at = signed
            .expires_at
            .unwrap_or(created.saturating_add(super::origin::MAX_LIFETIME_SECONDS));
        Ok(Produced {
            result: json!({
                "request_id":request_id,
                "content_digest":signed.content_digest,
                "signature_input":signed.signature_input,
                "signature":signed.signature,
                "created":signed.created_at,
                "expires":signed.expires_at,
            }),
            created_at: signed.created_at,
            expires_at,
            signature_base_digest: signed.signature_base_digest,
            audit: Some(audit_options(proof, signed.created_at)),
        })
    })
}

fn run(
    db: &mut Database,
    principal: &str,
    request_id: &str,
    reservation: Reservation,
    clock: &dyn Clock,
    produce: impl FnOnce(&KeyRecord, i64, i64, i64) -> Result<Produced>,
) -> Result<RequestStatus> {
    let (grant, key, deadline) = match reservation {
        Reservation::Existing(status) => return Ok(status),
        Reservation::New {
            grant,
            key,
            deadline,
        } => (grant, key, deadline),
    };
    let before = clock.now()?;
    if before.wall >= grant.expiry || before.monotonic_ms >= deadline {
        db.fail_reserved(principal, request_id, false, before)?;
        return Err(KeydError::Misuse("GRANT_EXPIRED".into()));
    }
    let produced = match produce(&key, before.wall, grant.expiry, deadline) {
        Ok(produced) => produced,
        Err(error) => {
            let after = clock.now()?;
            let known = matches!(error, KeydError::Locked);
            db.fail_reserved(principal, request_id, !known, after)?;
            return Err(KeydError::Misuse(
                if known {
                    "KEY_LOCKED"
                } else {
                    "OUTCOME_UNKNOWN"
                }
                .into(),
            ));
        }
    };
    let lifetime = produced
        .expires_at
        .checked_sub(produced.created_at)
        .filter(|s| (1..=300).contains(s))
        .ok_or_else(|| KeydError::Protocol("invalid profile lifetime".into()))?;
    let validity = (
        produced.expires_at,
        deadline.min(before.monotonic_ms.saturating_add(lifetime * 1000)),
    );
    let completed = match &produced.audit {
        Some(options) => db.complete_origin(
            principal,
            request_id,
            &produced.result,
            validity,
            &produced.signature_base_digest,
            options.clone(),
            clock.now()?,
        ),
        None => db.complete_http(
            principal,
            request_id,
            &produced.result,
            validity,
            &produced.signature_base_digest,
            clock.now()?,
        ),
    };
    if let Err(error) = completed {
        // Reconcile a possibly committed transaction without releasing its result.
        // If even the reconciliation audit fails, recovery owns the reservation.
        if let Ok(status) = db.request_status(principal, request_id, clock.now()?) {
            if status.state == "reserved" {
                let _ = db.fail_reserved(principal, request_id, true, clock.now()?);
            }
        }
        return Err(error);
    }
    // A result-commit failure never releases the in-memory signature. The caller
    // latches emergency stop; restart converts any unresolved reserve to unknown.
    db.request_status(principal, request_id, clock.now()?)
}
