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
        self.reserve(
            principal,
            grant_id,
            id,
            digest,
            "origin-proof",
            now,
            |db| db.authorize_origin(principal, grant_id, proof, now),
        )
    }

    /// 两种签名共用的预留:先看是不是老请求,再判权,再扣配额。
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
            Some(options),
            now,
        )
    }
    fn complete(
        &mut self,
        principal: &str,
        id: &str,
        result: &Value,
        validity: (i64, i64),
        signature_digest: &str,
        options: Option<Value>,
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
        if let Some(options) = options {
            event["origin"] = options;
        }
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
            grants::hot_key(&self.connection, &self.root, &g.key_id)?;
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
