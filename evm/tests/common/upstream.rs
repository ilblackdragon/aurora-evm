#![allow(dead_code)]
use super::*;
use aurora_evm::privacy::{DelegateBinding, Policy};
use ethabi::{Contract, ParamType, Token};
use serde_json::Value;

pub fn a(address: H160) -> Token {
    Token::Address(ethabi::Address::from_slice(address.as_bytes()))
}
pub fn n(value: u64) -> Token {
    Token::Uint(value.into())
}
pub fn units(value: u64) -> Token {
    Token::Uint(ethabi::Uint::from(value) * ethabi::Uint::exp10(18))
}
pub fn text(value: &str) -> Token {
    Token::String(value.to_owned())
}
pub fn address_output(o: &Outcome) -> H160 {
    o.ok();
    H160::from_slice(&o.output[12..32])
}
#[derive(Clone)]
pub struct Artifact {
    pub abi: Contract,
    pub bytecode: String,
    pub links: Value,
    pub name: String,
}
#[derive(Clone)]
pub struct Upstream {
    packages: BTreeMap<String, Value>,
    pub instances: BTreeMap<H160, Artifact>,
    pub libraries: BTreeMap<String, H160>,
}
impl Default for Upstream {
    fn default() -> Self {
        let mut packages = BTreeMap::new();
        for (name, contents) in [
            (
                "uni",
                include_str!("../fixtures/upstream/uniswap-v2-core/artifacts.json"),
            ),
            (
                "router",
                include_str!("../fixtures/upstream/uniswap-v2-periphery/artifacts.json"),
            ),
            (
                "aave",
                include_str!("../fixtures/upstream/aave-core-v3/artifacts.json"),
            ),
        ] {
            packages.insert(name.to_owned(), serde_json::from_str(contents).unwrap());
        }
        Self {
            packages,
            instances: BTreeMap::new(),
            libraries: BTreeMap::new(),
        }
    }
}
impl Upstream {
    pub fn artifact(&self, package: &str, name: &str) -> Artifact {
        let value = &self.packages[package][name];
        Artifact {
            abi: Contract::load(serde_json::to_vec(&value["abi"]).unwrap().as_slice()).unwrap(),
            bytecode: value["bytecode"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x")
                .to_owned(),
            links: value["linkReferences"].clone(),
            name: name.to_owned(),
        }
    }
    pub fn deploy(&mut self, chain: &mut Chain, package: &str, name: &str, args: &[Token]) -> H160 {
        let artifact = self.artifact(package, name);
        let mut code = artifact.bytecode.clone();
        for libs in artifact.links.as_object().unwrap().values() {
            for (name, positions) in libs.as_object().unwrap() {
                let address = if let Some(a) = self.libraries.get(name) {
                    *a
                } else {
                    let a = self.deploy(chain, package, name, &[]);
                    self.libraries.insert(name.clone(), a);
                    a
                };
                for position in positions.as_array().unwrap() {
                    let start = usize::try_from(position["start"].as_u64().unwrap()).unwrap() * 2;
                    assert_eq!(position["length"], 20);
                    code.replace_range(start..start + 40, &hex::encode(address));
                }
            }
        }
        let code = hex::decode(code).unwrap();
        let code = if let Some(ctor) = &artifact.abi.constructor {
            ctor.encode_input(code, args).unwrap()
        } else {
            assert!(args.is_empty());
            code
        };
        let (address, result) = chain.run(user(0), None, code, false, false);
        assert!(
            result.reason.is_succeed(),
            "deploy {name}: {:?}",
            result.reason
        );
        self.instances.insert(address, artifact);
        address
    }
    #[allow(clippy::too_many_arguments)]
    pub fn call(
        &self,
        chain: &mut Chain,
        caller: H160,
        target: H160,
        name: &str,
        args: &[Token],
        private: bool,
        query: bool,
    ) -> Outcome {
        let input = self.instances[&target]
            .abi
            .function(name)
            .unwrap()
            .encode_input(args)
            .unwrap();
        chain.run(caller, Some(target), input, private, query).1
    }
    pub fn boot(&self, chain: &mut Chain, target: H160, name: &str, args: &[Token]) -> Outcome {
        let o = self.call(chain, user(0), target, name, args, false, false);
        o.ok();
        o
    }
    pub fn proxy(
        &mut self,
        chain: &mut Chain,
        implementation: H160,
        init: Vec<u8>,
        admin: H160,
    ) -> H160 {
        let proxy = self.deploy(
            chain,
            "aave",
            "InitializableImmutableAdminUpgradeabilityProxy",
            &[a(admin)],
        );
        let abi = &self.instances[&proxy].abi;
        let f = abi
            .functions_by_name("initialize")
            .unwrap()
            .iter()
            .find(|f| f.inputs.len() == 2)
            .unwrap();
        let input = f
            .encode_input(&[a(implementation), Token::Bytes(init)])
            .unwrap();
        chain.run(admin, Some(proxy), input, false, false).1.ok();
        proxy
    }
    pub fn bind_proxy(&self, chain: &mut Chain, proxy: H160, implementation: H160, mut p: Policy) {
        p.address = proxy.0;
        p.code_hash = chain.code_hash(proxy);
        p.delegates.push(DelegateBinding {
            from_code: proxy.0,
            to_code: implementation.0,
            code_hash: chain.code_hash(implementation),
            forward_calldata: true,
        });
        // Linked libraries are callable only through the exact source-code edges
        // emitted by the upstream linker; they are not general forwarding grants.
        self.bind_libraries(chain, &mut p, implementation);
        chain.policies.insert(proxy.0, p);
    }
    fn bind_libraries(&self, chain: &Chain, p: &mut Policy, source: H160) {
        for libs in self.instances[&source].links.as_object().unwrap().values() {
            for name in libs.as_object().unwrap().keys() {
                let target = self.libraries[name];
                p.delegates.push(DelegateBinding {
                    from_code: source.0,
                    to_code: target.0,
                    code_hash: chain.code_hash(target),
                    forward_calldata: false,
                });
                self.bind_libraries(chain, p, target);
            }
        }
    }
}

pub fn arg(ty: &ParamType) -> Arg {
    match ty {
        ParamType::Address => Arg::Address,
        ParamType::Uint(256) => Arg::Uint256,
        ParamType::Uint(bits) => Arg::Uint(u16::try_from(*bits).unwrap()),
        ParamType::Bool => Arg::Bool,
        ParamType::FixedBytes(n) => Arg::FixedBytes(u8::try_from(*n).unwrap()),
        ParamType::Bytes | ParamType::String => Arg::Bytes,
        ParamType::Array(item) => Arg::Array(Box::new(arg(item))),
        ParamType::Tuple(items) => Arg::Tuple(items.iter().map(arg).collect()),
        other => panic!("unsupported upstream ABI type {other}"),
    }
}
// Explicit user-facing disclosure methods in this selected upstream surface.
// Administrative writes retain existing contract authorization; per-method
// matrix tests distinguish public admission from protocol-level authorization.
pub fn policy(chain: &Chain, address: H160, artifact: &Artifact, grants: &[Permit]) -> Policy {
    let mut p = chain.policy(address);
    for f in artifact.abi.functions() {
        let rules = match f.name.as_str() {
            "allowance" | "borrowAllowance" => vec![
                Permit::PrincipalArg(0),
                Permit::PrincipalArg(1),
                Permit::CallerArg(0),
                Permit::CallerArg(1),
            ],
            "balanceOf"
            | "nonces"
            | "scaledBalanceOf"
            | "principalBalanceOf"
            | "getPreviousIndex"
            | "getScaledUserBalanceAndSupply"
            | "getUserStableRate"
            | "getUserLastUpdated"
            | "getUserAccountData"
            | "getUserConfiguration"
            | "getUserEMode" => owner(),
            "getUserReserveData" => vec![Permit::PrincipalArg(1), Permit::CallerArg(1)],
            _ => vec![Permit::Public],
        };
        let mut rules = rules;
        if !matches!(rules[0], Permit::Public) {
            rules.extend_from_slice(grants);
        }
        let query = matches!(
            f.state_mutability,
            ethabi::StateMutability::View | ethabi::StateMutability::Pure
        );
        p.methods.insert(
            f.short_signature(),
            Method {
                args: f.inputs.iter().map(|a| arg(&a.kind)).collect(),
                any_of: rules,
                query,
            },
        );
    }
    for e in artifact.abi.events() {
        let mut address_topics = Vec::new();
        let mut recipients = vec![Recipient::Principal];
        let mut topic = 1;
        let mut data_index = 0;
        let mut data_args = Vec::new();
        for i in &e.inputs {
            let user_field = matches!(
                i.name.as_str(),
                "from"
                    | "to"
                    | "owner"
                    | "spender"
                    | "user"
                    | "onBehalfOf"
                    | "caller"
                    | "recipient"
                    | "liquidator"
                    | "fromUser"
                    | "toUser"
                    | "target"
                    | "delegatee"
                    | "delegator"
            );
            if i.indexed {
                if i.kind == ParamType::Address {
                    address_topics.push(topic);
                    if user_field {
                        recipients.push(Recipient::TopicAddress(topic));
                    }
                }
                topic += 1;
            } else {
                if i.kind == ParamType::Address && user_field {
                    recipients.push(Recipient::DataAddress(data_index));
                }
                data_args.push(arg(&i.kind));
                data_index += 1;
            }
        }
        let public = matches!(e.name.as_str(), "Sync" | "ReserveDataUpdated");
        p.events.insert(
            e.signature().0,
            EventRule {
                topics: topic,
                data_words: 0,
                address_topics,
                audience: if public {
                    EventAudience::Public
                } else {
                    EventAudience::Participants(recipients)
                },
                data_args: Some(data_args),
            },
        );
    }
    p
}

/// Canonical ABI arguments for exhaustive admission tests. Lifecycle tests use
/// economic inputs; these cover every selector even when protocol preconditions
/// deliberately revert (e.g. initializing an already-initialized proxy).
pub fn sample(ty: &ParamType, name: &str, asset: H160) -> Token {
    match ty {
        ParamType::Address => a(
            if matches!(
                name,
                "asset"
                    | "underlyingAsset"
                    | "collateralAsset"
                    | "debtAsset"
                    | "token"
                    | "tokenA"
                    | "tokenB"
            ) {
                asset
            } else {
                user(1)
            },
        ),
        ParamType::Uint(_) => n(if name.contains("Mode") {
            2
        } else if name == "deadline" {
            1000
        } else {
            0
        }),
        ParamType::Bool => Token::Bool(false),
        ParamType::FixedBytes(n) => Token::FixedBytes(vec![0; *n]),
        ParamType::Bytes => Token::Bytes(vec![]),
        ParamType::String => text("matrix"),
        ParamType::Array(_) => Token::Array(vec![]),
        ParamType::Tuple(items) => {
            Token::Tuple(items.iter().map(|t| sample(t, "", asset)).collect())
        }
        other => panic!("unexpected ABI type {other}"),
    }
}

/// Every function is exercised using real deployed bytecode. For public methods,
/// both identities must pass privacy admission, even if native protocol rules
/// reject one/both calls. For private reads, Alice passes and Bob is denied.
pub fn method_matrix(
    base: &Chain,
    u: &Upstream,
    targets: &[H160],
    asset: H160,
) -> Vec<serde_json::Value> {
    let mut report = Vec::new();
    for target in targets {
        let art = &u.instances[target];
        let p = &base.policies[&target.0];
        assert_eq!(
            p.methods.len(),
            art.abi.functions().count(),
            "incomplete ABI policy for {}",
            art.name
        );
        for f in art.abi.functions() {
            let args: Vec<_> = f
                .inputs
                .iter()
                .map(|i| sample(&i.kind, &i.name, asset))
                .collect();
            let input = f.encode_input(&args).unwrap();
            let rule = &p.methods[&f.short_signature()];
            let private = !rule.any_of.iter().any(|r| matches!(r, Permit::Public));
            let mut successes = 0;
            for caller in [user(1), user(2)] {
                let expected = !private || caller == user(1);
                let mut c = base.clone();
                let actual = c.run(caller, Some(*target), input.clone(), true, false).1;
                let first = actual
                    .decisions
                    .first()
                    .unwrap_or_else(|| panic!("missing decision {}::{}", art.name, f.signature()));
                assert_eq!(
                    first.admitted,
                    expected,
                    "{}::{} caller={caller:?}",
                    art.name,
                    f.signature()
                );
                if expected {
                    let baseline = base
                        .clone()
                        .run(caller, Some(*target), input.clone(), false, false)
                        .1;
                    if baseline.reason.is_succeed() {
                        assert!(
                            actual.reason.is_succeed(),
                            "privacy regression {}::{}: {:?}; denied={:?}",
                            art.name,
                            f.signature(),
                            actual.reason,
                            actual
                                .decisions
                                .iter()
                                .filter(|d| !d.admitted)
                                .collect::<Vec<_>>()
                        );
                        assert_eq!(
                            actual.output,
                            baseline.output,
                            "{}::{} output changed",
                            art.name,
                            f.signature()
                        );
                        successes += 1;
                    }
                } else {
                    actual.denied();
                    assert!(actual.output.is_empty());
                    assert!(actual.logs.is_empty());
                }
            }
            report.push(serde_json::json!({"contract":art.name,"method":f.signature(),
                "visibility":if private {"user-or-approved-contract"}else{"public-admission; original authorization applies"},
                "positive_identity_admission":true,"wrong_identity":if private {"denied"}else{"public admission"},
                "successful_runtime_cases":successes,"runtime_cases":2}));
        }
    }
    report
}
