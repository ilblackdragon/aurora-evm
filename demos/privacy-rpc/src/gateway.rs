use crate::{
    auth,
    engine::{self, Engine, Scope, CHAIN_ID, GAS},
};
use aurora_evm::privacy::{can_export, ProtectedLog};
use primitive_types::{H160, U256};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::broadcast;

type Id = [u8; 32];
type RpcResult = Result<Value, RpcError>;
#[derive(Clone, Copy, Debug)]
pub struct RpcError(pub i64, pub &'static str);
pub const DENIED: RpcError = RpcError(4100, "Unauthorized");
pub const INVALID: RpcError = RpcError(-32602, "Invalid parameters");
pub fn now() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}
pub fn hx(v: impl AsRef<[u8]>) -> String {
    format!("0x{}", hex::encode(v))
}
pub fn addr(v: &Value) -> Result<H160, RpcError> {
    let bytes = hexbytes(v)?;
    if bytes.len() != 20 {
        return Err(INVALID);
    }
    Ok(H160::from_slice(&bytes))
}
fn hexbytes(v: &Value) -> Result<Vec<u8>, RpcError> {
    hex::decode(
        v.as_str()
            .and_then(|v| v.strip_prefix("0x"))
            .ok_or(INVALID)?,
    )
    .map_err(|_| INVALID)
}
fn quantity(v: &Value) -> Result<u64, RpcError> {
    u64::from_str_radix(
        v.as_str()
            .and_then(|v| v.strip_prefix("0x"))
            .ok_or(INVALID)?,
        16,
    )
    .map_err(|_| INVALID)
}
#[derive(Clone)]
pub struct Session {
    pub user: H160,
    pub root: bool,
    pub parent: Id,
    pub origin: String,
    pub contracts: BTreeSet<H160>,
    pub expires: u64,
    pub history_from: u64,
}
#[derive(Clone)]
pub struct IndexedLog {
    pub log: ProtectedLog,
    pub tx: String,
    pub block: u64,
    pub block_hash: String,
    pub index: usize,
    pub removed: bool,
}
impl IndexedLog {
    pub fn json(&self) -> Value {
        json!({"address":hx(self.log.emitter),"topics":self.log.topics.iter().map(hx).collect::<Vec<_>>(),
        "data":hx(&self.log.data),"transactionHash":self.tx,"blockNumber":format!("0x{:x}",self.block),"blockHash":self.block_hash,
        "transactionIndex":"0x0","logIndex":format!("0x{:x}",self.index),"removed":self.removed})
    }
}
#[derive(Clone)]
struct Receipt {
    sender: H160,
    target: H160,
    hash: String,
    block: u64,
    block_hash: String,
    success: bool,
    logs: Vec<IndexedLog>,
}
#[derive(Clone)]
struct Snapshot {
    engine: Engine,
    events: Vec<IndexedLog>,
    receipts: BTreeMap<String, Receipt>,
    height: u64,
}
struct Cursor {
    session: Id,
    epoch: u64,
    filter: Value,
    offset: usize,
}
pub struct Gateway {
    pub engine: Engine,
    pub tokens: [H160; 2],
    pub forwarder: H160,
    pub batch: H160,
    pub height: u64,
    pub base: String,
    pub app_origins: [String; 2],
    sessions: BTreeMap<Id, Session>,
    events: Vec<IndexedLog>,
    receipts: BTreeMap<String, Receipt>,
    snapshots: Vec<Snapshot>,
    cursors: BTreeMap<String, Cursor>,
    epoch: u64,
    pub changes: broadcast::Sender<Vec<IndexedLog>>,
}
impl Gateway {
    pub fn new(base: String, app_origins: [String; 2]) -> (Self, Value) {
        let (mut engine, tokens, forwarder, batch, admin) = Engine::bootstrap();
        let (changes, _) = broadcast::channel(128);
        let mut sessions = BTreeMap::new();
        let mut identities = serde_json::Map::new();
        for (name, seed) in [("alice", 1), ("bob", 2)] {
            let (user, key) = auth::fixture_identity(seed);
            for token in tokens {
                let input = engine::calldata(
                    "mint(address,uint256)",
                    &[engine::address_word(user), U256::from(1000).to_big_endian()],
                );
                assert!(
                    engine
                        .execute(admin, Some(token), input, false, false, None, 0, GAS)
                        .success
                );
            }
            let secret = auth::secret();
            let id = auth::key_id(&secret);
            sessions.insert(
                id,
                Session {
                    user,
                    root: true,
                    parent: id,
                    origin: base.clone(),
                    contracts: tokens.into_iter().collect(),
                    expires: now() + 86_400_000,
                    history_from: 0,
                },
            );
            identities.insert(name.into(),json!({"address":hx(user),"privateKey":key,"rpcUrl":format!("{base}/rpc/{secret}")}));
        }
        let public = json!({"chainId":format!("0x{CHAIN_ID:x}"),"tokens":tokens.map(hx),"forwarder":hx(forwarder),"batch":hx(batch),"apps":app_origins});
        let private = json!({"users":identities,"public":public,"baseUrl":base});
        (
            Self {
                engine,
                tokens,
                forwarder,
                batch,
                height: 0,
                base,
                app_origins,
                sessions,
                events: vec![],
                receipts: BTreeMap::new(),
                snapshots: vec![],
                cursors: BTreeMap::new(),
                epoch: 0,
                changes,
            },
            private,
        )
    }
    pub fn public_config(&self) -> Value {
        json!({"chainId":format!("0x{CHAIN_ID:x}"),"tokens":self.tokens.map(hx),"forwarder":hx(self.forwarder),"batch":hx(self.batch),"apps":self.app_origins})
    }
    pub fn session(&self, id: Id, origin: Option<&str>) -> Result<Session, RpcError> {
        let s = self
            .sessions
            .get(&id)
            .filter(|s| s.expires > now())
            .ok_or(DENIED)?;
        if !s.root {
            let parent = self
                .sessions
                .get(&s.parent)
                .filter(|p| p.root && p.expires > now())
                .ok_or(DENIED)?;
            if parent.user != s.user || origin != Some(s.origin.as_str()) {
                return Err(DENIED);
            }
        } else if origin.is_some_and(|v| v != s.origin) {
            return Err(DENIED);
        }
        Ok(s.clone())
    }
    pub fn process(&mut self, id: Id, origin: Option<&str>, request: &Value) -> Value {
        let result = (|| {
            if request.get("jsonrpc") != Some(&json!("2.0"))
                || !request["method"].is_string()
                || !request["params"].is_array()
            {
                return Err(INVALID);
            }
            let s = self.session(id, origin)?;
            self.rpc(
                id,
                &s,
                request["method"].as_str().unwrap(),
                request["params"].as_array().unwrap(),
            )
        })();
        match result {
            Ok(result) => json!({"jsonrpc":"2.0","id":request["id"],"result":result}),
            Err(RpcError(code, message)) => {
                json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":code,"message":message}})
            }
        }
    }
    fn scope(&self, s: &Session) -> Scope {
        let mut scope: Scope = s
            .contracts
            .iter()
            .map(|a| (a.0, engine::read_selectors()))
            .collect();
        scope.insert(
            self.forwarder.0,
            [engine::selector("pretend(address,address)")]
                .into_iter()
                .collect(),
        );
        scope
    }
    fn rpc(&mut self, id: Id, s: &Session, method: &str, params: &[Value]) -> RpcResult {
        match method {
            "eth_chainId" => Ok(json!(format!("0x{CHAIN_ID:x}"))),
            "eth_blockNumber" => Ok(json!(format!("0x{:x}", self.height))),
            "eth_accounts" => Ok(json!([hx(s.user)])),
            "eth_getTransactionCount" => {
                if !s.root
                    || params.len() != 2
                    || addr(&params[0])? != s.user
                    || !matches!(params[1].as_str(), Some("latest" | "pending"))
                {
                    return Err(DENIED);
                }
                Ok(json!(format!("0x{:x}", self.engine.nonce(s.user))))
            }
            "eth_call" => {
                if params.len() != 2 || params[1] != "latest" {
                    return Err(INVALID);
                }
                let obj = params[0].as_object().ok_or(INVALID)?;
                if obj
                    .keys()
                    .any(|k| !matches!(k.as_str(), "to" | "from" | "data"))
                {
                    return Err(INVALID);
                }
                if let Some(from) = obj.get("from") {
                    if addr(from)? != s.user {
                        return Err(DENIED);
                    }
                }
                let to = addr(&params[0]["to"])?;
                let input = hexbytes(&params[0]["data"])?;
                let scope = self.scope(s);
                let r = self.engine.execute(
                    s.user,
                    Some(to),
                    input,
                    true,
                    true,
                    Some(scope),
                    self.height,
                    GAS,
                );
                if !r.success {
                    return Err(DENIED);
                }
                Ok(json!(hx(r.output)))
            }
            // Deliberately no speculative execution: this is a conservative demo bound.
            "eth_estimateGas" => {
                if params.len() != 1 || !s.contracts.contains(&addr(&params[0]["to"])?) {
                    return Err(DENIED);
                }
                if let Some(from) = params[0].get("from") {
                    if addr(from)? != s.user {
                        return Err(DENIED);
                    }
                }
                Ok(json!(format!("0x{GAS:x}")))
            }
            "eth_sendRawTransaction" => {
                if !s.root || params.len() != 1 || self.snapshots.len() >= 128 {
                    return Err(DENIED);
                }
                let raw = hexbytes(&params[0])?;
                let tx = auth::decode(&raw).map_err(|_| DENIED)?;
                if tx.sender != s.user
                    || tx.nonce != self.engine.nonce(tx.sender)
                    || (!s.contracts.contains(&tx.to) && tx.to != self.batch)
                {
                    return Err(DENIED);
                }
                let snapshot = Snapshot {
                    engine: self.engine.clone(),
                    events: self.events.clone(),
                    receipts: self.receipts.clone(),
                    height: self.height,
                };
                let next = self.height + 1;
                let r = self.engine.execute(
                    tx.sender,
                    Some(tx.to),
                    tx.data,
                    false,
                    true,
                    None,
                    next,
                    tx.gas,
                );
                let tx_hash = hx(tx.hash);
                let block_hash = hx(engine::hash(
                    &[
                        tx.hash.as_slice(),
                        &next.to_be_bytes(),
                        &self.epoch.to_be_bytes(),
                    ]
                    .concat(),
                ));
                let logs: Vec<_> = r
                    .logs
                    .into_iter()
                    .enumerate()
                    .map(|(index, log)| IndexedLog {
                        log,
                        tx: tx_hash.clone(),
                        block: next,
                        block_hash: block_hash.clone(),
                        index,
                        removed: false,
                    })
                    .collect();
                assert!(r.success || logs.is_empty());
                // One mutex transaction atomically publishes state, index and receipt.
                self.height = next;
                self.events.extend(logs.clone());
                self.receipts.insert(
                    tx_hash.clone(),
                    Receipt {
                        sender: s.user,
                        target: tx.to,
                        hash: tx_hash.clone(),
                        block: next,
                        block_hash,
                        success: r.success,
                        logs: logs.clone(),
                    },
                );
                self.snapshots.push(snapshot);
                let _ = self.changes.send(logs);
                Ok(json!(tx_hash))
            }
            "eth_getLogs" => {
                if params.len() != 1 {
                    return Err(INVALID);
                }
                self.validate_filter(s, &params[0])?;
                Ok(Value::Array(
                    self.events
                        .iter()
                        .filter(|e| self.visible(s, e, &params[0]))
                        .map(IndexedLog::json)
                        .collect(),
                ))
            }
            "aurora_getEvents" => {
                if params.len() != 1 {
                    return Err(INVALID);
                }
                let p = &params[0];
                let filter = p.get("filter").cloned().unwrap_or(json!({}));
                self.validate_filter(s, &filter)?;
                let limit = p.get("limit").and_then(Value::as_u64).unwrap_or(20);
                if limit == 0 || limit > 100 {
                    return Err(INVALID);
                }
                let offset = if let Some(cursor) = p.get("cursor").and_then(Value::as_str) {
                    let c = self.cursors.get(cursor).ok_or(DENIED)?;
                    if c.session != id || c.epoch != self.epoch || c.filter != filter {
                        return Err(DENIED);
                    }
                    c.offset
                } else {
                    0
                };
                let visible: Vec<_> = self
                    .events
                    .iter()
                    .filter(|e| self.visible(s, e, &filter))
                    .collect();
                let rows: Vec<_> = visible
                    .iter()
                    .skip(offset)
                    .take(limit as usize)
                    .map(|e| e.json())
                    .collect();
                let end = offset + rows.len();
                let more = end < visible.len();
                let cursor = if more {
                    if self.cursors.len() >= 1024 {
                        return Err(DENIED);
                    }
                    let c = auth::secret();
                    self.cursors.insert(
                        c.clone(),
                        Cursor {
                            session: id,
                            epoch: self.epoch,
                            filter,
                            offset: end,
                        },
                    );
                    Some(c)
                } else {
                    None
                };
                Ok(json!({"events":rows,"nextCursor":cursor,"hasMore":more}))
            }
            "eth_getTransactionReceipt" => {
                if params.len() != 1 {
                    return Err(INVALID);
                }
                let r = self
                    .receipts
                    .get(params[0].as_str().ok_or(INVALID)?)
                    .ok_or(DENIED)?;
                let logs: Vec<_> = r
                    .logs
                    .iter()
                    .filter(|e| self.visible(s, e, &json!({})))
                    .map(IndexedLog::json)
                    .collect();
                if logs.is_empty()
                    && !(r.sender == s.user
                        && (s.contracts.contains(&r.target) || (s.root && r.target == self.batch))
                        && r.block >= s.history_from)
                {
                    return Err(DENIED);
                }
                // Explicit privacy projection, never advertised as a canonical proof-bearing receipt.
                Ok(
                    json!({"transactionHash":r.hash,"blockNumber":format!("0x{:x}",r.block),"blockHash":r.block_hash,
                    "status":if r.success {"0x1"}else{"0x0"},"logs":logs,"privacyView":true}),
                )
            }
            "aurora_createReadSession" => {
                if !s.root
                    || params.len() != 1
                    || self.sessions.values().filter(|v| v.parent == id).count() >= 64
                {
                    return Err(DENIED);
                }
                let p = &params[0];
                let origin = p["origin"].as_str().ok_or(INVALID)?;
                if !self.app_origins.iter().any(|v| v == origin) {
                    return Err(DENIED);
                }
                let contracts: BTreeSet<_> = p["contracts"]
                    .as_array()
                    .ok_or(INVALID)?
                    .iter()
                    .map(addr)
                    .collect::<Result<_, _>>()?;
                if contracts.is_empty() || !contracts.is_subset(&s.contracts) {
                    return Err(DENIED);
                }
                let ttl = p["ttlSeconds"].as_u64().ok_or(INVALID)?;
                if ttl == 0 || ttl > 600 {
                    return Err(INVALID);
                }
                let from = p.get("historyFrom").and_then(Value::as_u64).unwrap_or(0);
                let secret = auth::secret();
                let expires = (now() + ttl * 1000).min(s.expires);
                self.sessions.insert(
                    auth::key_id(&secret),
                    Session {
                        user: s.user,
                        root: false,
                        parent: id,
                        origin: origin.into(),
                        contracts: contracts.clone(),
                        expires,
                        history_from: from,
                    },
                );
                Ok(
                    json!({"rpcUrl":format!("{}/rpc/{secret}",self.base),"account":hx(s.user),"expiresAt":expires,"contracts":contracts.into_iter().map(hx).collect::<Vec<_>>()}),
                )
            }
            "aurora_revokeSession" => {
                if !s.root || params.len() != 1 {
                    return Err(DENIED);
                }
                let secret = params[0]
                    .as_str()
                    .ok_or(INVALID)?
                    .strip_prefix(&format!("{}/rpc/", self.base))
                    .ok_or(INVALID)?;
                let target = auth::key_id(secret);
                let victim = self.sessions.get(&target).ok_or(DENIED)?;
                if victim.parent != id || victim.root {
                    return Err(DENIED);
                }
                self.sessions.remove(&target);
                self.cursors.retain(|_, v| v.session != target);
                let _ = self.changes.send(vec![]);
                Ok(json!(true))
            }
            "aurora_rotateWalletUrl" => {
                if !s.root || !params.is_empty() {
                    return Err(DENIED);
                }
                self.sessions.retain(|_, v| v.parent != id);
                self.cursors
                    .retain(|_, cursor| self.sessions.contains_key(&cursor.session));
                let secret = auth::secret();
                let new_id = auth::key_id(&secret);
                let mut new = s.clone();
                new.parent = new_id;
                self.sessions.insert(new_id, new);
                let _ = self.changes.send(vec![]);
                Ok(json!({"rpcUrl":format!("{}/rpc/{secret}",self.base)}))
            }
            _ => Err(RpcError(-32601, "Unsupported method")),
        }
    }
    pub fn validate_filter(&self, s: &Session, f: &Value) -> Result<(), RpcError> {
        let f = f.as_object().ok_or(INVALID)?;
        if f.keys()
            .any(|k| !matches!(k.as_str(), "address" | "topics" | "fromBlock" | "toBlock"))
        {
            return Err(INVALID);
        }
        if let Some(address) = f.get("address") {
            let addresses = if let Some(a) = address.as_array() {
                a.clone()
            } else {
                vec![address.clone()]
            };
            if addresses.len() > 16
                || addresses
                    .iter()
                    .any(|a| addr(a).is_err() || !s.contracts.contains(&addr(a).unwrap()))
            {
                return Err(DENIED);
            }
        }
        if let Some(topics) = f.get("topics") {
            let topics = topics.as_array().ok_or(INVALID)?;
            if topics.len() > 4 {
                return Err(INVALID);
            }
            for topic in topics {
                let options = if let Some(a) = topic.as_array() {
                    a.clone()
                } else {
                    vec![topic.clone()]
                };
                if options.len() > 16 {
                    return Err(INVALID);
                }
                for v in options {
                    if !v.is_null() && hexbytes(&v)?.len() != 32 {
                        return Err(INVALID);
                    }
                }
            }
        }
        for key in ["fromBlock", "toBlock"] {
            if let Some(v) = f.get(key) {
                if !matches!(v.as_str(), Some("latest" | "earliest")) {
                    quantity(v)?;
                }
            }
        }
        Ok(())
    }
    pub fn visible(&self, s: &Session, e: &IndexedLog, f: &Value) -> bool {
        if e.block < s.history_from
            || !s.contracts.contains(&H160(e.log.emitter))
            || !can_export(&e.log, Some(s.user.0))
        {
            return false;
        }
        if let Some(a) = f.get("address") {
            if let Some(arr) = a.as_array() {
                if !arr
                    .iter()
                    .any(|v| addr(v).ok() == Some(H160(e.log.emitter)))
                {
                    return false;
                }
            } else if addr(a).ok() != Some(H160(e.log.emitter)) {
                return false;
            }
        }
        let block = |v: &Value, default: u64| match v.as_str() {
            Some("latest") => self.height,
            Some("earliest") => 0,
            _ => quantity(v).unwrap_or(default),
        };
        if e.block < f.get("fromBlock").map_or(0, |v| block(v, 0))
            || e.block > f.get("toBlock").map_or(u64::MAX, |v| block(v, u64::MAX))
        {
            return false;
        }
        if let Some(topics) = f.get("topics").and_then(Value::as_array) {
            for (i, expected) in topics.iter().enumerate() {
                if expected.is_null() {
                    continue;
                }
                let Some(actual) = e.log.topics.get(i) else {
                    return false;
                };
                let matches = |v: &Value| hexbytes(v).ok().is_some_and(|v| v.as_slice() == actual);
                if let Some(options) = expected.as_array() {
                    if !options.iter().any(matches) {
                        return false;
                    }
                } else if !matches(expected) {
                    return false;
                }
            }
        }
        true
    }
    pub fn rollback(&mut self) -> Result<(), RpcError> {
        let snapshot = self.snapshots.pop().ok_or(DENIED)?;
        let mut removed: Vec<_> = self
            .events
            .iter()
            .filter(|e| e.block > snapshot.height)
            .cloned()
            .collect();
        for e in &mut removed {
            e.removed = true;
        }
        self.engine = snapshot.engine;
        self.events = snapshot.events;
        self.receipts = snapshot.receipts;
        self.height = snapshot.height;
        self.epoch += 1;
        self.cursors.clear();
        let _ = self.changes.send(removed);
        Ok(())
    }
}
