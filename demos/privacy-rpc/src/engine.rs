use aurora_evm::{
    backend::{ApplyBackend, MemoryAccount, MemoryBackend, MemoryVicinity},
    executor::stack::{MemoryStackState, StackExecutor, StackSubstateMetadata},
    privacy::{erc20_policy, Arg, Method, Permit, Policy, PrivacyConfig, ProtectedLog},
    Config, CreateScheme,
};
use primitive_types::{H160, U256};
use sha3::{Digest, Keccak256};
use std::collections::{BTreeMap, BTreeSet};

pub const CHAIN_ID: u64 = 1313161556;
pub const GAS: u64 = 2_000_000;
pub type Scope = BTreeMap<[u8; 20], BTreeSet<[u8; 4]>>;
pub fn hash(v: &[u8]) -> [u8; 32] {
    Keccak256::digest(v).into()
}
pub fn selector(v: &str) -> [u8; 4] {
    hash(v.as_bytes())[..4].try_into().unwrap()
}
pub fn address_word(v: H160) -> [u8; 32] {
    let mut w = [0; 32];
    w[12..].copy_from_slice(v.as_bytes());
    w
}
pub fn calldata(sig: &str, words: &[[u8; 32]]) -> Vec<u8> {
    let mut v = selector(sig).to_vec();
    for w in words {
        v.extend(w);
    }
    v
}
pub fn read_selectors() -> BTreeSet<[u8; 4]> {
    [
        "balanceOf(address)",
        "allowance(address,address)",
        "name()",
        "symbol()",
        "decimals()",
        "totalSupply()",
    ]
    .map(selector)
    .into_iter()
    .collect()
}
#[derive(Clone, Default)]
pub struct Engine {
    pub accounts: BTreeMap<H160, MemoryAccount>,
    pub policies: BTreeMap<[u8; 20], Policy>,
}
pub struct Execution {
    pub address: H160,
    pub success: bool,
    pub output: Vec<u8>,
    pub logs: Vec<ProtectedLog>,
}
impl Engine {
    pub fn nonce(&self, who: H160) -> U256 {
        self.accounts.get(&who).map_or(U256::zero(), |v| v.nonce)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        &mut self,
        who: H160,
        to: Option<H160>,
        input: Vec<u8>,
        query: bool,
        private: bool,
        scope: Option<Scope>,
        block: u64,
        gas: u64,
    ) -> Execution {
        let vicinity = MemoryVicinity {
            gas_price: U256::zero(),
            effective_gas_price: U256::zero(),
            origin: who,
            chain_id: CHAIN_ID.into(),
            block_hashes: vec![],
            block_number: block.into(),
            block_coinbase: H160::zero(),
            block_timestamp: block.into(),
            block_difficulty: U256::zero(),
            block_randomness: None,
            block_gas_limit: GAS.into(),
            block_base_fee_per_gas: U256::zero(),
            blob_gas_price: None,
            blob_hashes: vec![],
        };
        let mut backend = MemoryBackend::new(&vicinity, self.accounts.clone());
        let config = Config::shanghai();
        let state = MemoryStackState::new(StackSubstateMetadata::new(gas, &config), &backend);
        let precompiles = BTreeMap::new();
        let mut executor = if private {
            let mut privacy =
                PrivacyConfig::new(self.policies.clone(), Some(who.0), query).unwrap();
            if let Some(scope) = scope {
                privacy = privacy.with_call_scope(scope).unwrap();
            }
            StackExecutor::new_with_privacy(state, &config, &precompiles, privacy)
        } else {
            StackExecutor::new_with_precompiles(state, &config, &precompiles)
        };
        let address =
            to.unwrap_or_else(|| executor.create_address(CreateScheme::Legacy { caller: who }));
        let (reason, output) = if to.is_some() {
            executor.transact_call(who, address, U256::zero(), input, gas, vec![], vec![])
        } else {
            executor.transact_create(who, U256::zero(), input, gas, vec![])
        };
        let logs = executor.protected_logs().to_vec();
        let (changes, ordinary) = executor.into_state().deconstruct();
        let ordinary: Vec<_> = ordinary.into_iter().collect();
        assert!(!private || ordinary.is_empty(), "unlabelled privacy log");
        if !query {
            backend.apply(changes, ordinary, true);
            self.accounts = backend.state().clone();
        }
        Execution {
            address,
            success: reason.is_succeed(),
            output,
            logs,
        }
    }
    pub fn deploy(&mut self, admin: H160, bytecode: &str) -> H160 {
        let r = self.execute(
            admin,
            None,
            hex::decode(bytecode.trim()).unwrap(),
            false,
            false,
            None,
            0,
            GAS,
        );
        assert!(r.success);
        r.address
    }
    pub fn bootstrap() -> (Self, [H160; 2], H160, H160, H160) {
        let mut e = Self::default();
        let admin = H160::from_low_u64_be(0x1000);
        let tokens = [
            e.deploy(
                admin,
                include_str!("../../../evm/tests/fixtures/privacy/Token.bin"),
            ),
            e.deploy(
                admin,
                include_str!("../../../evm/tests/fixtures/privacy/Token.bin"),
            ),
        ];
        let forwarder = e.deploy(
            admin,
            include_str!("../../../evm/tests/fixtures/privacy/Impostor.bin"),
        );
        for token in tokens {
            e.policies.insert(
                token.0,
                erc20_policy(
                    token.0,
                    hash(&e.accounts[&token].code),
                    hash(b"Transfer(address,address,uint256)"),
                    hash(b"Approval(address,address,uint256)"),
                ),
            );
        }
        let mut methods = BTreeMap::new();
        methods.insert(
            selector("pretend(address,address)"),
            Method {
                args: vec![Arg::Address, Arg::Address],
                any_of: vec![Permit::Public],
                query: true,
            },
        );
        e.policies.insert(
            forwarder.0,
            Policy {
                address: forwarder.0,
                code_hash: hash(&e.accounts[&forwarder].code),
                version: 1,
                methods,
                events: BTreeMap::new(),
                delegates: vec![],
            },
        );
        let batch = e.deploy(
            admin,
            include_str!("../../../evm/tests/fixtures/privacy/BatchPayments.bin"),
        );
        let methods = [(
            selector("pay(address,address,address,uint256,uint256)"),
            Method {
                args: vec![
                    Arg::Address,
                    Arg::Address,
                    Arg::Address,
                    Arg::Uint256,
                    Arg::Uint256,
                ],
                any_of: vec![Permit::Public],
                query: false,
            },
        )]
        .into_iter()
        .collect();
        e.policies.insert(
            batch.0,
            Policy {
                address: batch.0,
                code_hash: hash(&e.accounts[&batch].code),
                version: 1,
                methods,
                events: BTreeMap::new(),
                delegates: vec![],
            },
        );
        (e, tokens, forwarder, batch, admin)
    }
}
