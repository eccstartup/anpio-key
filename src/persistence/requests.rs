//! Quota and audit commit before signing; results commit before delivery.
use super::*;
use crate::security::http::CanonicalHttpRequest;
use crate::security::origin::OriginProof;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestStatus {
    pub request_id: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
}
pub enum Reservation {
    New {
        grant: grants::Grant,
        key: Box<catalog::KeyRecord>,
        deadline: i64,
    },
    Existing(RequestStatus),
}
fn refused(code: &str) -> KeydError {
    KeydError::Misuse(code.into())
}
type StoredRequest = (String, String, Option<Vec<u8>>, Option<i64>);
impl Database {
    /// Bounded maintenance deletes signatures, retaining permanent ID tombstones.
    pub fn prune_results(&mut self, now: Time) -> Result<usize> {
        self.refresh_grants(now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let count=tx.execute("UPDATE requests SET result=NULL WHERE rowid IN (SELECT r.rowid FROM requests r JOIN grants g USING(grant_id) LEFT JOIN grant_deadlines d USING(grant_id) WHERE r.result IS NOT NULL AND (r.result_expiry<=?1 OR g.expiry<=?1 OR d.monotonic_deadline<=?2 OR g.boot_epoch!=?3 OR g.state NOT IN ('active','exhausted') OR json_extract(CAST(r.result AS TEXT),'$.monotonic_expiry')<=?2) LIMIT 256)",params![now.wall,now.monotonic_ms,self.boot_epoch]).map_err(db_error)?;
        if count > 0 {
            append(
                &tx,
                &json!({"event":"SIGN_RESULTS_PRUNED","count":count,"at":now.wall}),
            )?;
        }
        tx.commit().map_err(db_error)?;
        Ok(count)
    }
    /// Existing requests are resolved before quota checks, including the last use.
    pub fn reserve_http(
        &mut self,
        principal: &str,
        grant_id: &str,
        id: &str,
        request: &CanonicalHttpRequest,
        now: Time,
    ) -> Result<Reservation> {
        let digest = request.digest()?;
        self.reserve(
            principal,
            grant_id,
            id,
            digest,
            "http-authentication",
            now,
            |db| db.authorize_http(principal, grant_id, request, now),
        )
    }

    /// 同一条 origin proof 用同一个 request_id 重放:命中缓存,不再签第二次。
    pub fn reserve_origin(
        &mut self,
        principal: &str,
        grant_id: &str,
        id: &str,
        proof: &OriginProof,
        now: Time,
    ) -> Result<Reservation> {
        let digest = proof.digest();
        self.reserve(principal, grant_id, id, digest, "origin-proof", now, |db| {
            db.authorize_origin(principal, grant_id, proof, now)
        })
    }

    /// 同一份 purpose 签名用同一个 request_id 重放:命中缓存,不再签第二次。
    /// 摘要里带 purpose 标签,所以两个 purpose 的同名 payload 不会撞车。
    pub fn reserve_purpose(
        &mut self,
        principal: &str,
        grant_id: &str,
        id: &str,
        request: &crate::security::purpose::PurposeRequest,
        now: Time,
    ) -> Result<Reservation> {
        let digest = request.digest();
        let purpose = request.purpose();
        self.reserve(principal, grant_id, id, digest, purpose.name(), now, |db| {
            db.authorize_purpose(principal, grant_id, &purpose, now)
        })
    }

    /// 对象 proof 的摘要按对象自己的域算,文档 proof 另外带上 purpose 与
    /// domain/challenge —— 同一个 request_id 换了其中任何一项都算另一个请求。
    pub fn reserve_object_proof(
        &mut self,
        principal: &str,
        grant_id: &str,
        id: &str,
        request: &crate::security::proofs::ObjectProofRequest,
        now: Time,
    ) -> Result<Reservation> {
        let digest = request.digest();
        self.reserve(principal, grant_id, id, digest, "object-proof", now, |db| {
            db.authorize_object_proof(principal, grant_id, now)
        })
    }

    /// 文档 proof。文档对不对得上这把键由授权那一步判,所以走不到签名的请求
    /// 不会留下一行 `outcome_unknown`。
    pub fn reserve_document_proof(
        &mut self,
        principal: &str,
        grant_id: &str,
        id: &str,
        request: &crate::security::proofs::DocumentProofRequest,
        now: Time,
    ) -> Result<Reservation> {
        let digest = request.digest();
        self.reserve(
            principal,
            grant_id,
            id,
            digest,
            "document-proof",
            now,
            |db| db.authorize_document_proof(principal, grant_id, request, now),
        )
    }

    /// 同一个 request_id 重放拿到的是"做过"而不是那把密钥 —— 见
    /// [`Database::complete_ecdh`]。
    pub fn reserve_ecdh(
        &mut self,
        principal: &str,
        grant_id: &str,
        id: &str,
        request: &crate::security::ecdh::EcdhRequest,
        now: Time,
    ) -> Result<Reservation> {
        let digest = request.digest();
        self.reserve(principal, grant_id, id, digest, "ecdh", now, |db| {
            db.authorize_ecdh(principal, grant_id, request, now)
        })
    }

    /// 两种签名共用的预留:先看是不是老请求,再判权,再扣配额。
    #[allow(clippy::too_many_arguments)]
    fn reserve(
        &mut self,
        principal: &str,
        grant_id: &str,
        id: &str,
        digest: String,
        purpose: &str,
        now: Time,
        authorize: impl FnOnce(&mut Database) -> Result<(grants::Grant, catalog::KeyRecord)>,
    ) -> Result<Reservation> {
        if !crate::principal::validate_uuid(id) {
            return Err(refused("REQUEST_ID_INVALID"));
        }
        let old: Option<(String,String)> = self.connection.query_row(
            "SELECT grant_id,input_digest FROM requests WHERE principal_id=?1 AND request_id=?2",
            params![principal,id], |r| Ok((r.get(0)?,r.get(1)?))).optional().map_err(db_error)?;
        if let Some((old_grant, old_digest)) = old {
            if old_grant != grant_id || old_digest != digest {
                return Err(refused("REQUEST_ID_CONFLICT"));
            }
            return Ok(Reservation::Existing(
                self.request_status(principal, id, now)?,
            ));
        }
        let (grant, key) = match authorize(self) {
            Ok(authorized) => authorized,
            Err(KeydError::Misuse(code)) => {
                self.record(json!({"event":"SIGN_DENIED","principal_id":principal,"grant_id":grant_id,"request_id":id,"purpose":purpose,"input_digest":digest,"reason":code,"at":now.wall}))?;
                return Err(refused(&code));
            }
            Err(error) => return Err(error),
        };
        let deadline = self
            .connection
            .query_row(
                "SELECT monotonic_deadline FROM grant_deadlines WHERE grant_id=?1",
                [grant_id],
                |r| r.get(0),
            )
            .map_err(db_error)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let changed = tx.execute("UPDATE grants SET used_uses=used_uses+1 WHERE grant_id=?1 AND state='active' AND used_uses<max_uses AND boot_epoch=?2",params![grant_id,self.boot_epoch]).map_err(db_error)?;
        if changed != 1 {
            return Err(refused("GRANT_EXHAUSTED"));
        }
        tx.execute("INSERT INTO requests(principal_id,request_id,grant_id,input_digest,state) VALUES(?1,?2,?3,?4,'reserved')",params![principal,id,grant_id,digest]).map_err(db_error)?;
        append(
            &tx,
            &json!({"event":"SIGN_RESERVED","principal_id":principal,"request_id":id,"grant_id":grant_id,"key_id":key.key_id,"kid":key.kid,"policy_id":grant.policy_id,"policy_version":grant.policy_version,"purpose":purpose,"input_digest":digest,"at":now.wall}),
        )?;
        tx.commit().map_err(db_error)?;
        Ok(Reservation::New {
            grant,
            key: Box::new(key),
            deadline,
        })
    }
    pub fn complete_http(
        &mut self,
        principal: &str,
        id: &str,
        result: &Value,
        validity: (i64, i64),
        signature_digest: &str,
        now: Time,
    ) -> Result<()> {
        self.complete(principal, id, result, validity, signature_digest, None, now)
    }
    /// origin proof 的完成事件多一段 proof options,和 HTTP 的字段并存不互斥。
    #[allow(clippy::too_many_arguments)]
    pub fn complete_origin(
        &mut self,
        principal: &str,
        id: &str,
        result: &Value,
        validity: (i64, i64),
        signature_digest: &str,
        options: Value,
        now: Time,
    ) -> Result<()> {
        self.complete(
            principal,
            id,
            result,
            validity,
            signature_digest,
            Some(("origin", options)),
            now,
        )
    }
    /// purpose 签名的完成事件记下 purpose/domain/摘要,不记 payload 字节。
    #[allow(clippy::too_many_arguments)]
    pub fn complete_purpose(
        &mut self,
        principal: &str,
        id: &str,
        result: &Value,
        validity: (i64, i64),
        signature_digest: &str,
        options: Value,
        now: Time,
    ) -> Result<()> {
        self.complete(
            principal,
            id,
            result,
            validity,
            signature_digest,
            Some(("signing", options)),
            now,
        )
    }
    /// proof 的完成事件记下证明的形状(purpose/proofType/cryptosuite/
    /// verificationMethod/created)与两端摘要,不记对象或文档正文。
    #[allow(clippy::too_many_arguments)]
    pub fn complete_proof(
        &mut self,
        principal: &str,
        id: &str,
        result: &Value,
        validity: (i64, i64),
        signature_digest: &str,
        options: Value,
        now: Time,
    ) -> Result<()> {
        self.complete(
            principal,
            id,
            result,
            validity,
            signature_digest,
            Some(("proof", options)),
            now,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn complete(
        &mut self,
        principal: &str,
        id: &str,
        result: &Value,
        validity: (i64, i64),
        signature_digest: &str,
        options: Option<(&'static str, Value)>,
        now: Time,
    ) -> Result<()> {
        let (expiry, monotonic_expiry) = validity;
        let bytes =
            serde_json::to_vec(&json!({"response":result,"monotonic_expiry":monotonic_expiry}))?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        if tx.execute("UPDATE requests SET state='completed',result=?3,result_expiry=?4 WHERE principal_id=?1 AND request_id=?2 AND state='reserved'",params![principal,id,bytes,expiry]).map_err(db_error)? != 1 { return Err(unavailable()); }
        let mut event = json!({"event":"SIGN_COMPLETED","principal_id":principal,"request_id":id,"signature_base_digest":signature_digest,"delivery":"not_observed","at":now.wall});
        if let Some((field, options)) = options {
            event[field] = options;
        }
        append(&tx, &event)?;
        tx.commit().map_err(db_error)
    }
    /// ECDH 的完成事件**不存结果**。
    ///
    /// 共享密钥只从执行器那条返回值交给调用方一次;库里那条记录写的是
    /// `completed` + `result IS NULL`,所以同一个 `request_id` 再来一次拿到的是
    /// "做过,但结果不在库里"。这不是缺陷,是唯一一种不会让秘密在数据库里
    /// 多留一份的写法 —— 而那个库里存着所有签名结果,是备份和投影都会读的地方。
    pub fn complete_ecdh(
        &mut self,
        principal: &str,
        id: &str,
        options: Value,
        now: Time,
    ) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        if tx.execute("UPDATE requests SET state='completed',result=NULL,result_expiry=NULL WHERE principal_id=?1 AND request_id=?2 AND state='reserved'",params![principal,id]).map_err(db_error)? != 1 { return Err(unavailable()); }
        let mut event = json!({"event":"SIGN_COMPLETED","principal_id":principal,"request_id":id,"delivery":"not_observed","at":now.wall});
        event["ecdh"] = options;
        append(&tx, &event)?;
        tx.commit().map_err(db_error)
    }
    pub fn fail_reserved(
        &mut self,
        principal: &str,
        id: &str,
        unknown: bool,
        now: Time,
    ) -> Result<()> {
        let state = if unknown {
            "outcome_unknown"
        } else {
            "failed_reserved"
        };
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        if tx.execute("UPDATE requests SET state=?3,result=NULL WHERE principal_id=?1 AND request_id=?2 AND state='reserved'",params![principal,id,state]).map_err(db_error)? != 1 { return Err(unavailable()); }
        append(
            &tx,
            &json!({"event":"SIGN_FAILED","principal_id":principal,"request_id":id,"state":state,"at":now.wall}),
        )?;
        tx.commit().map_err(db_error)
    }
    pub fn request_status(
        &mut self,
        principal: &str,
        id: &str,
        now: Time,
    ) -> Result<RequestStatus> {
        self.refresh_grants(now)?;
        let row: Option<StoredRequest> = self.connection.query_row("SELECT grant_id,state,result,result_expiry FROM requests WHERE principal_id=?1 AND request_id=?2",params![principal,id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional().map_err(db_error)?;
        let (grant_id, state, bytes, expiry) = row.ok_or_else(|| refused("REQUEST_NOT_FOUND"))?;
        let g = self.grant_status(principal, &grant_id, now)?;
        let deadline: Option<i64> = self
            .connection
            .query_row(
                "SELECT monotonic_deadline FROM grant_deadlines WHERE grant_id=?1",
                [&grant_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_error)?;
        // Exhaustion blocks new reservations, not retrieval of the last result.
        let stored: Option<Value> = bytes
            .as_ref()
            .map(|b| serde_json::from_slice(b))
            .transpose()?;
        let allowed = stored
            .as_ref()
            .and_then(|v| v["monotonic_expiry"].as_i64())
            .is_some_and(|d| now.monotonic_ms < d)
            && g.boot_epoch == self.boot_epoch
            && ["active", "exhausted"].contains(&g.state.as_str())
            && now.wall < g.expiry
            && deadline.is_some_and(|d| now.monotonic_ms < d)
            && expiry.is_some_and(|e| now.wall < e);
        let result = if allowed && state == "completed" {
            // 角色不再写死:轮换、撤角色、文档变更都会在这里让缓存的结果作废。
            grants::active_key(&self.connection, &self.root, &g.key_id)?;
            stored.map(|v| v["response"].clone())
        } else {
            None
        };
        if !allowed && bytes_present(&self.connection, principal, id)? {
            // Keep the tombstone forever; never resurrect a signature after rollback.
            let tx = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(db_error)?;
            tx.execute(
                "UPDATE requests SET result=NULL WHERE principal_id=?1 AND request_id=?2",
                params![principal, id],
            )
            .map_err(db_error)?;
            append(
                &tx,
                &json!({"event":"SIGN_RESULT_PURGED","principal_id":principal,"request_id":id,"at":now.wall}),
            )?;
            tx.commit().map_err(db_error)?;
        }
        Ok(RequestStatus {
            request_id: id.into(),
            state,
            result,
        })
    }
}
fn bytes_present(db: &Connection, principal: &str, id: &str) -> Result<bool> {
    db.query_row(
        "SELECT result IS NOT NULL FROM requests WHERE principal_id=?1 AND request_id=?2",
        params![principal, id],
        |r| r.get(0),
    )
    .map_err(db_error)
}
