#![allow(dead_code)]
//! Real compiled Solidity integration tests. Policies are entirely host-side.
use aurora_evm::{
    backend::{ApplyBackend, MemoryAccount, MemoryBackend, MemoryVicinity},
    executor::stack::{MemoryStackState, StackExecutor, StackSubstateMetadata},
    privacy::{
        can_export, erc20_policy, Arg, EventAudience, EventRule, Method, Permit, Policy,
        PrivacyConfig, ProtectedLog, Recipient,
    },
    Config, CreateScheme, ExitReason,
};
use primitive_types::{H160, U256};
use sha3::{Digest, Keccak256};
use std::collections::BTreeMap;

const GAS: u64 = 10_000_000;
pub fn user(n: u64) -> H160 {
    H160::from_low_u64_be(0x1000 + n)
}
pub fn hash(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}
pub fn selector(signature: &str) -> [u8; 4] {
    hash(signature.as_bytes())[..4].try_into().unwrap()
}
pub fn addr(a: H160) -> [u8; 32] {
    let mut w = [0; 32];
    w[12..].copy_from_slice(a.as_bytes());
    w
}
pub fn uint(n: u64) -> [u8; 32] {
    U256::from(n).to_big_endian()
}
pub fn data(signature: &str, args: &[[u8; 32]]) -> Vec<u8> {
    let mut result = selector(signature).to_vec();
    for word in args {
        result.extend(word);
    }
    result
}

pub struct Outcome {
    pub reason: ExitReason,
    pub output: Vec<u8>,
    pub logs: Vec<ProtectedLog>,
    pub decisions: Vec<aurora_evm::privacy::CallDecision>,
}
impl Outcome {
    pub fn ok(&self) {
        assert!(
            self.reason.is_succeed(),
            "{:?}: {:x?}",
            self.reason,
            self.output
        );
    }
    pub fn denied(&self) {
        assert!(
            !self.reason.is_succeed(),
            "unauthorized execution succeeded"
        );
    }
    pub fn number(&self) -> U256 {
        self.ok();
        U256::from_big_endian(&self.output[..32])
    }
    pub fn visible(&self, viewer: H160) -> Vec<&ProtectedLog> {
        self.logs
            .iter()
            .filter(|log| can_export(log, Some(viewer.0)))
            .collect()
    }
}

#[derive(Default, Clone)]
pub struct Chain {
    pub accounts: BTreeMap<H160, MemoryAccount>,
    pub policies: BTreeMap<[u8; 20], Policy>,
}
impl Chain {
    pub fn run(
        &mut self,
        caller: H160,
        target: Option<H160>,
        input: Vec<u8>,
        private: bool,
        query: bool,
    ) -> (H160, Outcome) {
        self.run_authenticated(caller, target, input, private, query, Some(caller))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_authenticated(
        &mut self,
        caller: H160,
        target: Option<H160>,
        input: Vec<u8>,
        private: bool,
        query: bool,
        principal: Option<H160>,
    ) -> (H160, Outcome) {
        self.run_with_value(
            caller,
            target,
            input,
            private,
            query,
            principal,
            U256::zero(),
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn run_with_value(
        &mut self,
        caller: H160,
        target: Option<H160>,
        input: Vec<u8>,
        private: bool,
        query: bool,
        principal: Option<H160>,
        value: U256,
    ) -> (H160, Outcome) {
        let vicinity = MemoryVicinity {
            gas_price: U256::zero(),
            effective_gas_price: U256::zero(),
            origin: caller,
            chain_id: U256::one(),
            block_hashes: vec![],
            block_number: U256::one(),
            block_coinbase: H160::zero(),
            block_timestamp: U256::one(),
            block_difficulty: U256::zero(),
            block_randomness: None,
            block_gas_limit: U256::from(GAS),
            block_base_fee_per_gas: U256::zero(),
            blob_gas_price: None,
            blob_hashes: vec![],
        };
        let mut backend = MemoryBackend::new(&vicinity, self.accounts.clone());
        let config = Config::shanghai();
        let state = MemoryStackState::new(StackSubstateMetadata::new(GAS, &config), &backend);
        let precompiles = BTreeMap::new();
        let mut executor = if private {
            StackExecutor::new_with_privacy(
                state,
                &config,
                &precompiles,
                PrivacyConfig::new(self.policies.clone(), principal.map(|p| p.0), query).unwrap(),
            )
        } else {
            StackExecutor::new_with_precompiles(state, &config, &precompiles)
        };
        let address =
            target.unwrap_or_else(|| executor.create_address(CreateScheme::Legacy { caller }));
        let (reason, output) = if target.is_some() {
            executor.transact_call(caller, address, value, input, GAS, vec![], vec![])
        } else {
            executor.transact_create(caller, value, input, GAS, vec![])
        };
        let logs = executor.protected_logs().to_vec();
        let decisions = executor.privacy_decisions().to_vec();
        let (changes, raw_logs) = executor.into_state().deconstruct();
        let raw_logs: Vec<_> = raw_logs.into_iter().collect();
        if private {
            assert!(
                raw_logs.is_empty(),
                "private events escaped into ordinary logs"
            );
        }
        if !query {
            backend.apply(changes, raw_logs, true);
            self.accounts = backend.state().clone();
        }
        (
            address,
            Outcome {
                reason,
                output,
                logs,
                decisions,
            },
        )
    }
    pub fn deploy(&mut self, bytecode: &str, args: &[[u8; 32]]) -> H160 {
        let mut code = hex::decode(bytecode.trim()).unwrap();
        for word in args {
            code.extend(word);
        }
        let (address, result) = self.run(user(0), None, code, false, false);
        result.ok();
        address
    }
    pub fn call(&mut self, caller: H160, to: H160, signature: &str, args: &[[u8; 32]]) -> Outcome {
        self.run(caller, Some(to), data(signature, args), true, false)
            .1
    }
    pub fn query(&mut self, caller: H160, to: H160, signature: &str, args: &[[u8; 32]]) -> Outcome {
        self.run(caller, Some(to), data(signature, args), true, true)
            .1
    }
    pub fn bootstrap(&mut self, to: H160, signature: &str, args: &[[u8; 32]]) {
        self.run(user(0), Some(to), data(signature, args), false, false)
            .1
            .ok();
    }
    pub fn code_hash(&self, address: H160) -> [u8; 32] {
        hash(&self.accounts[&address].code)
    }
    pub fn policy(&self, address: H160) -> Policy {
        Policy {
            address: address.0,
            code_hash: self.code_hash(address),
            version: 1,
            methods: BTreeMap::new(),
            events: BTreeMap::new(),
            delegates: Vec::new(),
        }
    }
    pub fn token(&mut self) -> H160 {
        let token = self.deploy(include_str!("../fixtures/privacy/Token.bin"), &[]);
        let p = erc20_policy(
            token.0,
            self.code_hash(token),
            hash(b"Transfer(address,address,uint256)"),
            hash(b"Approval(address,address,uint256)"),
        );
        self.policies.insert(token.0, p);
        token
    }
    pub fn mint(&mut self, token: H160, to: H160, amount: u64) {
        self.bootstrap(token, "mint(address,uint256)", &[addr(to), uint(amount)]);
    }
    pub fn balance(&mut self, token: H160, owner: H160) -> U256 {
        self.query(owner, token, "balanceOf(address)", &[addr(owner)])
            .number()
    }
    pub fn router(&mut self) -> H160 {
        let router = self.deploy(include_str!("../fixtures/privacy/Router.bin"), &[]);
        let mut p = self.policy(router);
        method(
            &mut p,
            "swap(address,address,uint256,uint256,address)",
            vec![
                Arg::Address,
                Arg::Address,
                Arg::Uint256,
                Arg::Uint256,
                Arg::Address,
            ],
            vec![Permit::Public],
            false,
        );
        method(
            &mut p,
            "readBalance(address,address)",
            vec![Arg::Address, Arg::Address],
            vec![Permit::Public],
            true,
        );
        method(
            &mut p,
            "delegateRead(address,address)",
            vec![Arg::Address, Arg::Address],
            vec![Permit::Public],
            false,
        );
        for name in [
            "transferThenRevert(address,address,uint256)",
            "catchTransfer(address,address,uint256)",
        ] {
            method(
                &mut p,
                name,
                vec![Arg::Address, Arg::Address, Arg::Uint256],
                vec![Permit::Public],
                false,
            );
        }
        event(
            &mut p,
            "Done(address)",
            1,
            0,
            EventAudience::Participants(vec![Recipient::TopicAddress(1)]),
        );
        self.policies.insert(router.0, p);
        router
    }
}
pub fn method(p: &mut Policy, name: &str, args: Vec<Arg>, any_of: Vec<Permit>, query: bool) {
    p.methods.insert(
        selector(name),
        Method {
            args,
            any_of,
            query,
        },
    );
}
pub fn event(
    p: &mut Policy,
    name: &str,
    addresses: usize,
    data_words: usize,
    audience: EventAudience,
) {
    p.events.insert(
        hash(name.as_bytes()),
        EventRule {
            topics: addresses + 1,
            data_words,
            address_topics: (1..=addresses).collect(),
            audience,
            data_args: None,
        },
    );
}
pub fn owner() -> Vec<Permit> {
    vec![Permit::PrincipalArg(0), Permit::CallerArg(0)]
}

pub mod upstream;
