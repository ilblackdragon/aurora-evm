//! Opt-in method and event privacy for code-bound contracts and proxies.
//! The host authenticates identities and protects state/RPC; this module is not a TEE.
use crate::prelude::*;
#[cfg(not(feature = "std"))]
use alloc::vec;
use sha3::{Digest, Keccak256};

pub type Address = [u8; 20];
pub type Hash = [u8; 32];
pub type Selector = [u8; 4];
mod abi;

/// Trusted-host diagnostic only. Contains private execution metadata, including
/// failed calls; never include it in public RPC responses or receipts.
#[derive(Clone, Debug)]
pub struct CallDecision {
    pub storage_address: Address,
    pub code_address: Address,
    pub selector: Option<Selector>,
    pub admitted: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Denied; // Externally expose a single denial, not private details.
type Result<T> = ::core::result::Result<T, Denied>;

#[derive(Clone, Debug)]
pub enum Arg {
    Address,
    Uint256,
    Uint(u16),
    Bool,
    FixedBytes(u8),
    Bytes,
    Array(Box<Self>),
    Tuple(Vec<Self>),
}

#[derive(Clone, Debug)]
pub enum Permit {
    Public,
    PrincipalArg(usize),
    CallerArg(usize),
    Principal(Address),
    // Actual executing caller code, resolved by the host, not EXTCODEHASH(proxy).
    TrustedCaller { address: Address, code_hash: Hash },
}

#[derive(Clone, Debug)]
pub struct Method {
    pub args: Vec<Arg>, // Canonical ABI, including bounded dynamic arrays/tuples/bytes.
    pub any_of: Vec<Permit>, // Empty = deny.
    pub query: bool,    // Eligible for authenticated/static read-only execution.
}

#[derive(Clone, Debug)]
pub enum Recipient {
    TopicAddress(usize), // 1-based for non-anonymous events: topic 0 is signature.
    Principal,
    Caller,
    DataAddress(usize),
}

#[derive(Clone, Debug)]
pub enum EventAudience {
    Public,
    Participants(Vec<Recipient>),
}

#[derive(Clone, Debug)]
pub struct EventRule {
    pub topics: usize,     // Exact topic count including signature.
    pub data_words: usize, // Fixed-size, uint256-word event data in this version.
    pub address_topics: Vec<usize>,
    pub audience: EventAudience,
    /// Optional ABI for dynamic event payloads and non-indexed address readers.
    pub data_args: Option<Vec<Arg>>,
}

#[derive(Clone, Debug)]
pub struct Policy {
    pub address: Address,
    pub code_hash: Hash,
    pub version: u64,
    pub methods: BTreeMap<Selector, Method>,
    pub events: BTreeMap<Hash, EventRule>,
    /// Approved delegate edges within this storage owner's trust boundary.
    pub delegates: Vec<DelegateBinding>,
}

#[derive(Clone, Debug)]
pub struct DelegateBinding {
    pub from_code: Address,
    pub to_code: Address,
    pub code_hash: Hash,
    /// Proxies forward exactly the admitted calldata; linked libraries may
    /// receive new arguments from already-reviewed code on a bound edge.
    pub forward_calldata: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallKind {
    Call,
    StaticCall,
    DelegateCall,
    CallCode,
}

#[derive(Clone, Copy, Debug)]
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
#[derive(Clone, Debug)]
pub struct Frame {
    pub(crate) policy: Rc<Policy>, // Snapshot: policies cannot change this frame mid-execution.
    principal: Option<Address>,
    pub(crate) caller: Option<Caller>,
    is_static: bool,
    pub(crate) code_address: Address,
    pub(crate) code_hash: Hash,
    input_hash: Hash,
}

impl Frame {
    pub(crate) fn delegate(
        &self,
        code_address: Address,
        code_hash: Hash,
        input: &[u8],
        is_static: bool,
    ) -> Result<Self> {
        let input_hash: Hash = Keccak256::digest(input).into();
        if !self.policy.delegates.iter().any(|b| {
            b.from_code == self.code_address
                && b.to_code == code_address
                && b.code_hash == code_hash
                && (!b.forward_calldata || self.input_hash == input_hash)
        }) {
            return Err(Denied);
        }
        Ok(Self {
            policy: self.policy.clone(),
            principal: self.principal,
            caller: self.caller,
            is_static: self.is_static || is_static,
            code_address,
            code_hash,
            input_hash,
        })
    }
}

fn address(word: &[u8]) -> Result<Address> {
    if word.len() != 32 || word[..12].iter().any(|b| *b != 0) {
        return Err(Denied);
    }
    word[12..].try_into().map_err(|_| Denied)
}

/// Call before executing callee code, transferring value, or invoking precompiles.
/// Registry lookup must come from the deterministic execution-state snapshot.
/// # Errors
/// Denies unknown code/methods, invalid ABI, unauthorized identities or query modes.
pub fn admit_call(policy: Option<&Rc<Policy>>, c: &CallContext, input: &[u8]) -> Result<Frame> {
    let p = policy.ok_or(Denied)?;
    // Direct entry admission. Approved delegate edges use Frame::delegate.
    if !matches!(c.kind, CallKind::Call | CallKind::StaticCall)
        || c.storage_address != p.address
        || c.code_address != c.storage_address
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
    if c.query && (!c.is_static || !m.query) {
        return Err(Denied);
    }
    let addresses = abi::validate(&m.args, &input[4..])?;
    let arg = |i: usize| addresses.get(i).copied().flatten();
    let allowed = m.any_of.iter().any(|rule| match rule {
        Permit::Public => true,
        Permit::Principal(a) => c.principal == Some(*a),
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
        code_address: c.code_address,
        code_hash: c.code_hash,
        input_hash: Keccak256::digest(input).into(),
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

/// Execute from `Handler::log` using the actual active frame, not RPC metadata.
/// Unknown/malformed events fail closed. This can change contract behavior.
/// # Errors
/// Denies static, unknown, malformed or incorrectly attributed events.
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
        || (r.data_args.is_none() && r.data_words.checked_mul(32) != Some(data.len()))
    {
        return Err(Denied);
    }
    let data_addresses = r
        .data_args
        .as_ref()
        .map(|args| abi::validate(args, &data))
        .transpose()?;
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
                    Recipient::DataAddress(i) => Some(
                        data_addresses
                            .as_ref()
                            .and_then(|v| v.get(*i))
                            .copied()
                            .flatten()
                            .ok_or(Denied)?,
                    ),
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

/// RPC supplies a cryptographically verified user, not a requested `from`.
/// Contract readers require a separate authenticated execution/delegation path.
#[must_use]
pub fn can_export(log: &ProtectedLog, viewer: Option<Address>) -> bool {
    match &log.audience {
        Audience::Public => true,
        Audience::Only(readers) => viewer.is_some_and(|a| readers.contains(&a)),
    }
}

/// Minimal ERC-20 manifest. Host computes canonical Keccak-256 event signatures.
#[must_use]
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
                data_args: None,
            },
        );
    }
    Policy {
        address: token,
        code_hash,
        version: 1,
        methods,
        events,
        delegates: Vec::new(),
    }
}

/// Immutable, validated policy snapshot for one authenticated root execution.
/// The host must authenticate `principal`; this API does not verify signatures.
#[derive(Clone, Debug)]
pub struct PrivacyConfig {
    pub(crate) policies: BTreeMap<Address, Rc<Policy>>,
    pub(crate) principal: Option<Address>,
    pub(crate) query: bool,
}
impl PrivacyConfig {
    /// Build a bounded policy snapshot. Missing methods/policies deny access.
    /// # Errors
    /// Reject invalid ABI references, oversized policies, or zero principals.
    pub fn new(
        policies: BTreeMap<Address, Policy>,
        principal: Option<Address>,
        query: bool,
    ) -> Result<Self> {
        if policies.len() > 4096 || principal == Some([0; 20]) || (!query && principal.is_none()) {
            return Err(Denied);
        }
        for (key, p) in &policies {
            if *key != p.address
                || p.methods.len() > 128
                || p.events.len() > 64
                || p.delegates.len() > 64
            {
                return Err(Denied);
            }
            for m in p.methods.values() {
                if m.args.len() > 32
                    || !abi::valid_schema(&m.args)
                    || m.any_of.is_empty()
                    || m.any_of.len() > 32
                {
                    return Err(Denied);
                }
                for rule in &m.any_of {
                    if let Permit::PrincipalArg(i) | Permit::CallerArg(i) = rule {
                        if !matches!(m.args.get(*i), Some(Arg::Address)) {
                            return Err(Denied);
                        }
                    }
                }
            }
            for e in p.events.values() {
                if e.data_args
                    .as_ref()
                    .is_some_and(|args| !abi::valid_schema(args))
                {
                    return Err(Denied);
                }
                if e.topics == 0
                    || e.topics > 4
                    || e.data_words > 128
                    || e.address_topics.len() > 3
                    || e.address_topics.iter().any(|i| *i == 0 || *i >= e.topics)
                {
                    return Err(Denied);
                }
                if let EventAudience::Participants(sources) = &e.audience {
                    if sources.len() > 8 {
                        return Err(Denied);
                    }
                    for r in sources {
                        if let Recipient::TopicAddress(i) = r {
                            if !e.address_topics.contains(i) {
                                return Err(Denied);
                            }
                        }
                        if let Recipient::DataAddress(i) = r {
                            if !matches!(
                                e.data_args.as_ref().and_then(|a| a.get(*i)),
                                Some(Arg::Address)
                            ) {
                                return Err(Denied);
                            }
                        }
                    }
                }
            }
        }
        Ok(Self {
            policies: policies.into_iter().map(|(k, p)| (k, Rc::new(p))).collect(),
            principal,
            query,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        erc20_policy([1; 20], [2; 32], [3; 32], [4; 32])
    }

    #[test]
    fn malformed_identity_rule_is_rejected_even_alongside_public_rule() {
        let mut p = policy();
        p.methods.insert(
            [9; 4],
            Method {
                args: vec![Arg::Uint256],
                any_of: vec![Permit::Public, Permit::PrincipalArg(0)],
                query: true,
            },
        );
        assert!(PrivacyConfig::new(BTreeMap::from([(p.address, p)]), Some([5; 20]), true).is_err());
    }

    #[test]
    fn signature_topic_cannot_be_used_as_an_event_recipient() {
        let mut p = policy();
        p.events.get_mut(&[3; 32]).unwrap().audience =
            EventAudience::Participants(vec![Recipient::TopicAddress(0)]);
        assert!(PrivacyConfig::new(BTreeMap::from([(p.address, p)]), Some([5; 20]), true).is_err());
    }

    #[test]
    fn empty_private_audience_never_becomes_public() {
        let log = ProtectedLog {
            emitter: [1; 20],
            topics: Vec::new(),
            data: Vec::new(),
            policy_version: 1,
            audience: Audience::Only(BTreeSet::new()),
        };
        assert!(!can_export(&log, None));
        assert!(!can_export(&log, Some([5; 20])));
    }
}
