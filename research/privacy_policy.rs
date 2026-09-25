//! Executable reference evaluator, NOT an Aurora executor patch.
//! std-only: rustc --edition=2021 --test privacy_policy.rs -o /tmp/policy-tests
//! All contexts must be constructed by the trusted host, never from RPC claims.
use std::collections::{BTreeMap, BTreeSet};

pub type Address = [u8; 20];
pub type Hash = [u8; 32];
pub type Selector = [u8; 4];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Denied; // Externally expose a single denial, not private details.
type Result<T> = std::result::Result<T, Denied>;

#[derive(Clone, Copy)]
pub enum Arg {
    Address,
    Uint256,
}

#[derive(Clone)]
pub enum Permit {
    Public,
    PrincipalArg(usize),
    CallerArg(usize),
    // Actual executing caller code, resolved by the host, not EXTCODEHASH(proxy).
    TrustedCaller { address: Address, code_hash: Hash },
}

#[derive(Clone)]
pub struct Method {
    pub args: Vec<Arg>,      // This version supports only fixed, 32-byte ABI words.
    pub any_of: Vec<Permit>, // Empty = deny.
    pub query: bool,         // Eligible for authenticated/static read-only execution.
}

#[derive(Clone)]
pub enum Recipient {
    TopicAddress(usize), // 1-based for non-anonymous events: topic 0 is signature.
    Principal,
    Caller,
}

#[derive(Clone)]
pub enum EventAudience {
    Public,
    Participants(Vec<Recipient>),
}

#[derive(Clone)]
pub struct EventRule {
    pub topics: usize,     // Exact topic count including signature.
    pub data_words: usize, // Fixed-size, uint256-word event data in this version.
    pub address_topics: Vec<usize>,
    pub audience: EventAudience,
}

#[derive(Clone)]
pub struct Policy {
    pub address: Address,
    pub code_hash: Hash,
    pub version: u64,
    pub methods: BTreeMap<Selector, Method>,
    pub events: BTreeMap<Hash, EventRule>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CallKind {
    Call,
    StaticCall,
    DelegateCall,
    CallCode,
}

#[derive(Clone, Copy)]
pub struct Caller {
    pub address: Address,
    pub code_hash: Option<Hash>, // None for an authenticated EOA.
}

pub struct CallContext {
    pub principal: Option<Address>, // Verified signer; inherited, never replaced.
    pub caller: Option<Caller>,     // None for anonymous top-level queries.
    pub storage_address: Address,
    pub code_address: Address,
    pub code_hash: Hash, // Host-computed hash of actual resolved code.
    pub kind: CallKind,
    pub query: bool,     // Root execution mode, inherited by all children.
    pub is_static: bool, // Actual runtime-enforced flag, not ABI's `view` claim.
}

// Private fields prevent arbitrary event contexts from being fabricated by users
// of this module. The executor must keep this with the actual active EVM frame.
pub struct Frame {
    policy: Policy, // Snapshot: policies cannot change this frame mid-execution.
    principal: Option<Address>,
    caller: Option<Caller>,
    is_static: bool,
}

fn address(word: &[u8]) -> Result<Address> {
    if word.len() != 32 || word[..12].iter().any(|b| *b != 0) {
        return Err(Denied);
    }
    word[12..].try_into().map_err(|_| Denied)
}

/// Call before executing callee code, transferring value, or invoking precompiles.
/// Registry lookup must come from the deterministic execution-state snapshot.
pub fn admit_call(policy: Option<&Policy>, c: &CallContext, input: &[u8]) -> Result<Frame> {
    let p = policy.ok_or(Denied)?;
    // Minimal version deliberately denies proxies/delegated code and CALLCODE.
    if !matches!(c.kind, CallKind::Call | CallKind::StaticCall)
        || c.storage_address != p.address
        || c.code_address != p.address
        || c.code_hash != p.code_hash
        || (c.kind == CallKind::StaticCall && !c.is_static)
    {
        return Err(Denied);
    }
    let selector: Selector = input
        .get(..4)
        .ok_or(Denied)?
        .try_into()
        .map_err(|_| Denied)?;
    let m = p.methods.get(&selector).ok_or(Denied)?;
    let len = m
        .args
        .len()
        .checked_mul(32)
        .and_then(|n| n.checked_add(4))
        .ok_or(Denied)?;
    if input.len() != len || (c.query && (!c.is_static || !m.query)) {
        return Err(Denied);
    }
    let mut addresses = Vec::with_capacity(m.args.len());
    for (i, ty) in m.args.iter().enumerate() {
        addresses.push(match ty {
            Arg::Address => Some(address(&input[4 + i * 32..4 + (i + 1) * 32])?),
            Arg::Uint256 => None,
        });
    }
    let arg = |i: usize| addresses.get(i).copied().flatten();
    let allowed = m.any_of.iter().any(|rule| match rule {
        Permit::Public => true,
        Permit::PrincipalArg(i) => c.principal.is_some() && c.principal == arg(*i),
        Permit::CallerArg(i) => c.caller.is_some() && c.caller.map(|v| v.address) == arg(*i),
        Permit::TrustedCaller { address, code_hash } => c
            .caller
            .is_some_and(|v| v.address == *address && v.code_hash == Some(*code_hash)),
    });
    if !allowed {
        return Err(Denied);
    }
    Ok(Frame {
        policy: p.clone(),
        principal: c.principal,
        caller: c.caller,
        is_static: c.is_static,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Audience {
    Public,
    Only(BTreeSet<Address>),
}

#[derive(Clone, Debug)]
pub struct ProtectedLog {
    pub emitter: Address,
    pub topics: Vec<Hash>,
    pub data: Vec<u8>,
    pub policy_version: u64,
    pub audience: Audience,
}

/// Execute from Handler::log using the actual active frame, not RPC metadata.
/// Unknown/malformed events fail closed. This can change contract behavior.
pub fn classify_log(
    f: &Frame,
    emitter: Address,
    topics: Vec<Hash>,
    data: Vec<u8>,
) -> Result<ProtectedLog> {
    if f.is_static || emitter != f.policy.address {
        return Err(Denied);
    }
    let r = f
        .policy
        .events
        .get(topics.first().ok_or(Denied)?)
        .ok_or(Denied)?;
    if topics.len() != r.topics
        || topics.len() > 4
        || r.data_words.checked_mul(32) != Some(data.len())
    {
        return Err(Denied);
    }
    for i in &r.address_topics {
        if *i == 0 {
            return Err(Denied);
        }
        address(topics.get(*i).ok_or(Denied)?)?;
    }
    let audience = match &r.audience {
        EventAudience::Public => Audience::Public,
        EventAudience::Participants(sources) => {
            let mut readers = BTreeSet::new();
            for source in sources {
                let reader = match source {
                    Recipient::TopicAddress(i) => {
                        if !r.address_topics.contains(i) {
                            return Err(Denied);
                        }
                        Some(address(topics.get(*i).ok_or(Denied)?)?)
                    }
                    Recipient::Principal => f.principal,
                    Recipient::Caller => f.caller.map(|v| v.address),
                };
                if let Some(a) = reader {
                    if a != [0; 20] {
                        readers.insert(a);
                    } // Mint/burn zero address is not a reader.
                }
            }
            Audience::Only(readers) // Empty = visible to nobody, never public.
        }
    };
    Ok(ProtectedLog {
        emitter,
        topics,
        data,
        policy_version: f.policy.version,
        audience,
    })
}

/// Labels and logs share one journal. Mirror every EVM substate enter/exit.
#[derive(Default)]
pub struct LogJournal {
    frames: Vec<Vec<ProtectedLog>>,
}
impl LogJournal {
    pub fn enter(&mut self) {
        self.frames.push(Vec::new());
    }
    pub fn emit(
        &mut self,
        f: &Frame,
        emitter: Address,
        topics: Vec<Hash>,
        data: Vec<u8>,
    ) -> Result<()> {
        let log = classify_log(f, emitter, topics, data)?;
        self.frames.last_mut().ok_or(Denied)?.push(log);
        Ok(())
    }
    /// Call with success=false for REVERT, error, fatal, or aborted execution.
    /// Root success returns committed confidential logs to trusted storage only.
    pub fn exit(&mut self, success: bool) -> Result<Vec<ProtectedLog>> {
        let logs = self.frames.pop().ok_or(Denied)?;
        if !success {
            return Ok(Vec::new());
        }
        match self.frames.last_mut() {
            Some(parent) => {
                parent.extend(logs);
                Ok(Vec::new())
            }
            None => Ok(logs),
        }
    }
}

/// RPC supplies a cryptographically verified user, not a requested `from`.
/// Contract readers require a separate authenticated execution/delegation path.
pub fn can_export(log: &ProtectedLog, viewer: Option<Address>) -> bool {
    match &log.audience {
        Audience::Public => true,
        Audience::Only(readers) => viewer.is_some_and(|a| readers.contains(&a)),
    }
}

/// Minimal ERC-20 manifest. Host computes canonical Keccak-256 event signatures.
pub fn erc20_policy(token: Address, code_hash: Hash, transfer: Hash, approval: Hash) -> Policy {
    let mut methods = BTreeMap::new();
    let mut add = |selector, args, any_of, query| {
        methods.insert(
            selector,
            Method {
                args,
                any_of,
                query,
            },
        );
    };
    for selector in [
        [0x06, 0xfd, 0xde, 0x03],
        [0x95, 0xd8, 0x9b, 0x41],
        [0x31, 0x3c, 0xe5, 0x67],
        [0x18, 0x16, 0x0d, 0xdd],
    ] {
        add(selector, vec![], vec![Permit::Public], true);
    }
    add(
        [0x70, 0xa0, 0x82, 0x31],
        vec![Arg::Address],
        vec![Permit::PrincipalArg(0), Permit::CallerArg(0)],
        true,
    );
    add(
        [0xdd, 0x62, 0xed, 0x3e],
        vec![Arg::Address, Arg::Address],
        vec![
            Permit::PrincipalArg(0),
            Permit::PrincipalArg(1),
            Permit::CallerArg(0),
            Permit::CallerArg(1),
        ],
        true,
    );
    for selector in [[0xa9, 0x05, 0x9c, 0xbb], [0x09, 0x5e, 0xa7, 0xb3]] {
        add(
            selector,
            vec![Arg::Address, Arg::Uint256],
            vec![Permit::Public],
            false,
        );
    }
    add(
        [0x23, 0xb8, 0x72, 0xdd],
        vec![Arg::Address, Arg::Address, Arg::Uint256],
        vec![Permit::Public],
        false,
    );
    let mut events = BTreeMap::new();
    for (signature, recipients) in [
        (
            transfer,
            vec![
                Recipient::TopicAddress(1),
                Recipient::TopicAddress(2),
                Recipient::Caller,
            ],
        ),
        (
            approval,
            vec![Recipient::TopicAddress(1), Recipient::TopicAddress(2)],
        ),
    ] {
        events.insert(
            signature,
            EventRule {
                topics: 3,
                data_words: 1,
                address_topics: vec![1, 2],
                audience: EventAudience::Participants(recipients),
            },
        );
    }
    Policy {
        address: token,
        code_hash,
        version: 1,
        methods,
        events,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const ALICE: Address = [1; 20];
    const BOB: Address = [2; 20];
    const ROUTER: Address = [3; 20];
    const TOKEN: Address = [4; 20];
    const CODE: Hash = [5; 32];
    const TRANSFER: Hash = [6; 32]; // Synthetic signatures isolate evaluator tests.
    const APPROVAL: Hash = [7; 32];
    fn policy() -> Policy {
        erc20_policy(TOKEN, CODE, TRANSFER, APPROVAL)
    }
    fn word(a: Address) -> Hash {
        let mut w = [0; 32];
        w[12..].copy_from_slice(&a);
        w
    }
    fn input(selector: Selector, words: &[Hash]) -> Vec<u8> {
        let mut v = selector.to_vec();
        for w in words {
            v.extend(w);
        }
        v
    }
    fn context() -> CallContext {
        CallContext {
            principal: Some(ALICE),
            caller: Some(Caller {
                address: ALICE,
                code_hash: None,
            }),
            storage_address: TOKEN,
            code_address: TOKEN,
            code_hash: CODE,
            kind: CallKind::Call,
            query: false,
            is_static: false,
        }
    }
    fn transfer_frame() -> Frame {
        admit_call(
            Some(&policy()),
            &context(),
            &input([0xa9, 0x05, 0x9c, 0xbb], &[word(BOB), [0; 32]]),
        )
        .unwrap()
    }
    #[test]
    fn owner_access_propagates_but_does_not_grant_other_users_data() {
        let p = policy();
        let mut c = context();
        c.caller = Some(Caller {
            address: ROUTER,
            code_hash: Some([8; 32]),
        });
        assert!(admit_call(
            Some(&p),
            &c,
            &input([0x70, 0xa0, 0x82, 0x31], &[word(ALICE)])
        )
        .is_ok());
        assert!(admit_call(Some(&p), &c, &input([0x70, 0xa0, 0x82, 0x31], &[word(BOB)])).is_err());
        assert!(admit_call(
            Some(&p),
            &c,
            &input([0x70, 0xa0, 0x82, 0x31], &[word(ROUTER)])
        )
        .is_ok());
    }
    #[test]
    fn malformed_unknown_and_changed_code_fail_closed() {
        let p = policy();
        let mut c = context();
        let data = input([0x70, 0xa0, 0x82, 0x31], &[word(ALICE)]);
        assert!(admit_call(None, &c, &data).is_err());
        assert!(admit_call(Some(&p), &c, &[]).is_err());
        assert!(admit_call(Some(&p), &c, &[0xff; 4]).is_err());
        let mut bad = data.clone();
        bad[4] = 1;
        assert!(admit_call(Some(&p), &c, &bad).is_err());
        assert!(admit_call(Some(&p), &c, &data[..35]).is_err());
        c.code_hash = [9; 32];
        assert!(admit_call(Some(&p), &c, &data).is_err());
        c.code_hash = CODE;
        c.kind = CallKind::DelegateCall;
        assert!(admit_call(Some(&p), &c, &data).is_err());
    }
    #[test]
    fn anonymous_zero_is_not_authenticated_and_queries_must_be_static() {
        let p = policy();
        let mut c = context();
        c.principal = None;
        c.caller = None;
        assert!(admit_call(
            Some(&p),
            &c,
            &input([0x70, 0xa0, 0x82, 0x31], &[word([0; 20])])
        )
        .is_err());
        c.query = true;
        assert!(admit_call(Some(&p), &c, &[0x18, 0x16, 0x0d, 0xdd]).is_err());
        c.is_static = true;
        assert!(admit_call(Some(&p), &c, &[0x18, 0x16, 0x0d, 0xdd]).is_ok());
        assert!(admit_call(
            Some(&p),
            &c,
            &input([0xa9, 0x05, 0x9c, 0xbb], &[word(BOB), [0; 32]])
        )
        .is_err());
    }
    #[test]
    fn transfer_event_delivered_only_to_participants() {
        let f = transfer_frame();
        let log = classify_log(
            &f,
            TOKEN,
            vec![TRANSFER, word(ALICE), word(BOB)],
            vec![0; 32],
        )
        .unwrap();
        assert!(can_export(&log, Some(ALICE)));
        assert!(can_export(&log, Some(BOB)));
        assert!(!can_export(&log, Some(ROUTER)));
        assert!(!can_export(&log, None));
        assert!(classify_log(&f, TOKEN, vec![[99; 32]], vec![]).is_err());
        assert!(classify_log(
            &f,
            ROUTER,
            vec![TRANSFER, word(ALICE), word(BOB)],
            vec![0; 32]
        )
        .is_err());
    }
    #[test]
    fn delegated_spend_needs_no_owner_privacy_context_and_labels_spender() {
        let p = policy();
        let mut c = context();
        c.principal = Some(ROUTER);
        c.caller = Some(Caller {
            address: ROUTER,
            code_hash: None,
        });
        let f = admit_call(
            Some(&p),
            &c,
            &input([0x23, 0xb8, 0x72, 0xdd], &[word(ALICE), word(BOB), [0; 32]]),
        )
        .unwrap();
        // Admission is not spending approval: unchanged token code checks allowance.
        let log = classify_log(
            &f,
            TOKEN,
            vec![TRANSFER, word(ALICE), word(BOB)],
            vec![0; 32],
        )
        .unwrap();
        assert!(can_export(&log, Some(ROUTER)));
    }
    #[test]
    fn child_and_parent_reverts_discard_logs_and_labels() {
        let f = transfer_frame();
        let mut j = LogJournal::default();
        let emit = |j: &mut LogJournal| {
            j.emit(
                &f,
                TOKEN,
                vec![TRANSFER, word(ALICE), word(BOB)],
                vec![0; 32],
            )
            .unwrap()
        };
        j.enter();
        j.enter();
        emit(&mut j);
        assert!(j.exit(false).unwrap().is_empty());
        assert!(j.exit(true).unwrap().is_empty());
        j.enter();
        j.enter();
        emit(&mut j);
        assert!(j.exit(true).unwrap().is_empty());
        assert!(j.exit(false).unwrap().is_empty());
        j.enter();
        emit(&mut j);
        assert_eq!(j.exit(true).unwrap().len(), 1);
    }
    #[test]
    fn trusted_caller_grant_requires_exact_executing_code() {
        let mut p = policy();
        let mut c = context();
        p.methods.get_mut(&[0x70, 0xa0, 0x82, 0x31]).unwrap().any_of =
            vec![Permit::TrustedCaller {
                address: ROUTER,
                code_hash: [8; 32],
            }];
        c.caller = Some(Caller {
            address: ROUTER,
            code_hash: Some([9; 32]),
        });
        let data = input([0x70, 0xa0, 0x82, 0x31], &[word(BOB)]);
        assert!(admit_call(Some(&p), &c, &data).is_err());
        c.caller.as_mut().unwrap().code_hash = Some([8; 32]);
        assert!(admit_call(Some(&p), &c, &data).is_ok());
    }

    #[test]
    fn malformed_event_and_static_log_are_rejected() {
        let mut f = transfer_frame();
        let topics = vec![TRANSFER, word(ALICE), word(BOB)];
        assert!(classify_log(&f, TOKEN, topics.clone(), vec![0; 31]).is_err());
        let mut bad_topics = topics.clone();
        bad_topics[1][0] = 1;
        assert!(classify_log(&f, TOKEN, bad_topics, vec![0; 32]).is_err());
        f.is_static = true;
        assert!(classify_log(&f, TOKEN, topics, vec![0; 32]).is_err());
    }
}
