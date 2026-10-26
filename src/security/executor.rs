//! Single coordinated signing operation, with injectable clock and backend.
use super::ecdh::{EcdhRequest, SharedSecretReply};
use super::http::CanonicalHttpRequest;
use super::origin::{audit_options, OriginProof, SignedOrigin};
use super::purpose::{PurposeRequest, SignedPurpose};
use crate::crypto::hygiene::LockedBytes;
use crate::error::{KeydError, Result};
use crate::persistence::{
    catalog::KeyRecord, clock::Clock, requests::RequestStatus, requests::Reservation, Database,
};
use serde_json::{json, Value};

/// Purpose 签名的结果能取多久。签名本身不过期,这个数只限制缓存窗口,
/// 和 `run()` 的 profile 寿命上限对齐。
const PURPOSE_CACHE_SECONDS: i64 = 300;

/// 一次签名的产物,由各自的 backend 填好;写库和收尾是共用的一段。
struct Produced {
    result: Value,
    created_at: i64,
    expires_at: i64,
    signature_base_digest: String,
    /// 有它才有额外的审计段:origin proof 的 proof options,或 purpose 的标签。
    audit: Option<(&'static str, Value)>,
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
    run(
        db,
        principal,
        request_id,
        reservation,
        clock,
        |key, _, expiry, deadline| {
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
        },
    )
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
    run(
        db,
        principal,
        request_id,
        reservation,
        clock,
        |key, created, _, _| {
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
                audit: Some(("origin", audit_options(proof, signed.created_at))),
            })
        },
    )
}

/// `SIGN_PURPOSE`:签调用方给的字节,daemon 只按 purpose 加冻结的前缀。
///
/// 结果没有到期时刻 —— 断言不是凭证,它的有效性由使用方按用途自己判断;
/// `expires_at` 只决定缓存能取多久。
pub(crate) fn execute_purpose(
    db: &mut Database,
    principal: &str,
    grant_id: &str,
    request_id: &str,
    request: &PurposeRequest,
    clock: &dyn Clock,
    backend: impl FnOnce(&KeyRecord, &PurposeRequest) -> Result<SignedPurpose>,
) -> Result<RequestStatus> {
    let start = clock.now()?;
    let reservation = db.reserve_purpose(principal, grant_id, request_id, request, start)?;
    run(
        db,
        principal,
        request_id,
        reservation,
        clock,
        |key, created, _, _| {
            let signed = backend(key, request)?;
            Ok(Produced {
                result: json!({
                    "request_id":request_id,
                    "signature":signed.signature,
                    "public_multibase":signed.public_multibase,
                    "purpose":signed.purpose,
                }),
                created_at: created,
                expires_at: created.saturating_add(PURPOSE_CACHE_SECONDS),
                signature_base_digest: request.message_digest(),
                audit: Some(("signing", request.audit_options())),
            })
        },
    )
}

/// `ECDH`:算一次共享密钥,交给调用方**一次**。
///
/// 和上面几条路不同,它不走 [`run`]:`run` 的结果写进 `requests.result` 再读
/// 回来,而共享密钥不能落库(见 `Database::complete_ecdh`)。所以这里自己写
/// 预留 → 算 → 完成 → 用内存里的那份结果作答;重放拿到的是
/// `completed` + 空结果,由客户端判成 `OUTCOME_UNKNOWN`。
///
/// 完成后才构造应答:完成事件写不进去,密钥就一个字节都不出去。
pub(crate) fn execute_ecdh(
    db: &mut Database,
    principal: &str,
    grant_id: &str,
    request_id: &str,
    request: &EcdhRequest,
    clock: &dyn Clock,
    backend: impl FnOnce(&KeyRecord, &EcdhRequest) -> Result<LockedBytes>,
) -> Result<RequestStatus> {
    let start = clock.now()?;
    let reservation = db.reserve_ecdh(principal, grant_id, request_id, request, start)?;
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
    let shared = match backend(&key, request) {
        Ok(shared) => shared,
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
    let mut options = request.audit_options();
    options["grant_id"] = json!(grant_id);
    options["key_id"] = json!(key.key_id);
    options["kid"] = json!(key.kid);
    if let Err(error) = db.complete_ecdh(principal, request_id, options, clock.now()?) {
        if let Ok(status) = db.request_status(principal, request_id, clock.now()?) {
            if status.state == "reserved" {
                let _ = db.fail_reserved(principal, request_id, true, clock.now()?);
            }
        }
        return Err(error);
    }
    Ok(RequestStatus {
        request_id: request_id.into(),
        state: "completed".into(),
        result: Some(
            serde_json::to_value(SharedSecretReply::new(&shared, request)?)?,
        ),
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
        Some(("origin", options)) => db.complete_origin(
            principal,
            request_id,
            &produced.result,
            validity,
            &produced.signature_base_digest,
            options.clone(),
            clock.now()?,
        ),
        Some(("signing", options)) => db.complete_purpose(
            principal,
            request_id,
            &produced.result,
            validity,
            &produced.signature_base_digest,
            options.clone(),
            clock.now()?,
        ),
        Some(_) => return Err(KeydError::Protocol("unknown audit section".into())),
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
