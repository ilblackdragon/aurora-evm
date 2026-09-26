#![cfg(feature = "privacy")]
// Keep protocol lifecycles and deployment sequences reviewable in one place.
#![allow(clippy::too_many_lines)]
mod common;
use aurora_evm::privacy::{Arg, EventAudience, Permit, Recipient};
use common::upstream::*;
use common::*;
use ethabi::{Contract, Token};
use primitive_types::{H160, U256};
use serde_json::json;

fn fixture(abi: &str, name: &str) -> Artifact {
    Artifact {
        abi: Contract::load(abi.as_bytes()).unwrap(),
        bytecode: String::new(),
        links: json!({}),
        name: name.to_owned(),
    }
}
#[test]
fn real_aave_proxy_preserves_user_storage_identity_and_rejects_impostors_and_upgrades() {
    let mut c = Chain::default();
    let mut u = Upstream::default();
    let implementation = c.deploy(include_str!("fixtures/privacy/ProxyData.bin"), &[]);
    let art = fixture(
        include_str!("fixtures/privacy/ProxyData.abi.json"),
        "ProxyData",
    );
    u.instances.insert(implementation, art.clone());
    let init = art
        .abi
        .function("initialize")
        .unwrap()
        .encode_input(&[a(user(1)), n(100)])
        .unwrap();
    let proxy = u.proxy(&mut c, implementation, init, user(0));
    let other_init = art
        .abi
        .function("initialize")
        .unwrap()
        .encode_input(&[a(user(2)), n(700)])
        .unwrap();
    let other = u.proxy(&mut c, implementation, other_init, user(0));
    for address in [proxy, other] {
        let mut p = policy(&c, address, &art, &[]);
        method(
            &mut p,
            "upgradeTo(address)",
            vec![Arg::Address],
            vec![Permit::Principal(user(0).0)],
            false,
        );
        method(
            &mut p,
            "admin()",
            vec![],
            vec![Permit::Principal(user(0).0)],
            true,
        );
        method(
            &mut p,
            "implementation()",
            vec![],
            vec![Permit::Principal(user(0).0)],
            true,
        );
        event(
            &mut p,
            "Upgraded(address)",
            1,
            0,
            EventAudience::Participants(vec![Recipient::Principal]),
        );
        u.bind_proxy(&mut c, address, implementation, p);
    }
    assert_eq!(c.balance(proxy, user(1)), U256::from(100));
    assert_eq!(c.balance(other, user(2)), U256::from(700));
    c.query(user(2), proxy, "balanceOf(address)", &[addr(user(1))])
        .denied();
    c.query(user(1), other, "balanceOf(address)", &[addr(user(2))])
        .denied();
    c.query(user(2), proxy, "admin()", &[]).denied();
    assert_eq!(
        address_output(&c.query(user(0), proxy, "admin()", &[])),
        user(0)
    );
    let transfer = c.call(
        user(1),
        proxy,
        "transfer(address,uint256)",
        &[addr(user(2)), uint(10)],
    );
    transfer.ok();
    assert_eq!(transfer.logs[0].emitter, proxy.0);
    assert_eq!(transfer.visible(user(2)).len(), 1);
    assert!(transfer.visible(user(3)).is_empty());
    assert_eq!(c.balance(proxy, user(2)), U256::from(10));
    assert_eq!(c.balance(other, user(2)), U256::from(700));
    // Tokens held by a proxy belong to the proxy, not to its implementation.
    let token = c.token();
    c.mint(token, proxy, 23);
    assert_eq!(
        c.query(user(1), proxy, "selfBalance(address)", &[addr(token)])
            .number(),
        U256::from(23)
    );
    let malicious = c.deploy(include_str!("fixtures/privacy/Impostor.bin"), &[]);
    let ma = fixture(
        include_str!("fixtures/privacy/Impostor.abi.json"),
        "Impostor",
    );
    c.policies
        .insert(malicious.0, policy(&c, malicious, &ma, &[]));
    for signature in [
        "pretend(address,address)",
        "spoofSuffix(address,address)",
        "delegatedRead(address,address)",
    ] {
        c.call(user(2), malicious, signature, &[addr(proxy), addr(user(1))])
            .denied();
    }
    assert_eq!(
        c.query(
            user(1),
            malicious,
            "pretend(address,address)",
            &[addr(proxy), addr(user(1))]
        )
        .number(),
        U256::from(90)
    );
    let caught = c.query(
        user(2),
        malicious,
        "caught(address,address)",
        &[addr(proxy), addr(user(1))],
    );
    caught.ok();
    assert_eq!(caught.output, vec![0; 64]);
    c.query(
        user(1),
        implementation,
        "balanceOf(address)",
        &[addr(user(1))],
    )
    .denied();
    let evil = c.deploy(include_str!("fixtures/privacy/EvilImplementation.bin"), &[]);
    c.call(user(2), proxy, "upgradeTo(address)", &[addr(evil)])
        .denied();
    c.call(user(0), proxy, "upgradeTo(address)", &[addr(evil)])
        .ok();
    // Address is unchanged; stale implementation hash/edge still blocks access.
    c.query(user(1), proxy, "balanceOf(address)", &[addr(user(1))])
        .denied();
    c.call(
        user(0),
        proxy,
        "upgradeTo(address)",
        &[addr(implementation)],
    )
    .ok();
    assert_eq!(c.balance(proxy, user(1)), U256::from(90));
    let rewriting = c.deploy(
        include_str!("fixtures/privacy/RewritingProxy.bin"),
        &[addr(implementation), addr(user(1))],
    );
    let mut p = policy(&c, rewriting, &art, &[]);
    p.delegates.push(aurora_evm::privacy::DelegateBinding {
        from_code: rewriting.0,
        to_code: implementation.0,
        code_hash: c.code_hash(implementation),
        forward_calldata: true,
    });
    c.policies.insert(rewriting.0, p);
    // The outer argument is authorized, but the proxy substitutes another owner.
    let o = c.query(user(2), rewriting, "balanceOf(address)", &[addr(user(2))]);
    o.denied();
    assert!(o.decisions[0].admitted);
    assert!(!o.decisions[1].admitted);
    // Even explicit approval of another target with the wrong hash must fail.
    c.policies.get_mut(&proxy.0).unwrap().delegates[0].code_hash = [0; 32];
    c.query(user(1), proxy, "balanceOf(address)", &[addr(user(1))])
        .denied();
}

fn register_direct(c: &mut Chain, u: &Upstream, address: H160, grants: &[Permit]) {
    c.policies.insert(
        address.0,
        policy(c, address, &u.instances[&address], grants),
    );
}

#[test]
fn real_uniswap_pair_router_swaps_lp_transfers_and_burns_with_private_balances() {
    let mut c = Chain::default();
    let mut u = Upstream::default();
    let factory = u.deploy(&mut c, "uni", "UniswapV2Factory", &[a(user(0))]);
    let weth = u.deploy(&mut c, "router", "WETH9", &[]);
    let router = u.deploy(
        &mut c,
        "router",
        "UniswapV2Router02",
        &[a(factory), a(weth)],
    );
    let t0 = c.token();
    let t1 = c.token();
    u.boot(&mut c, factory, "createPair", &[a(t0), a(t1)]);
    let pair = address_output(&u.boot(&mut c, factory, "getPair", &[a(t0), a(t1)]));
    u.instances.insert(pair, u.artifact("uni", "UniswapV2Pair"));
    for address in [factory, weth, router, pair] {
        register_direct(&mut c, &u, address, &[]);
    }
    // Real, nonzero WETH deposit/withdraw tests the no-code native CALL path.
    c.accounts.entry(user(1)).or_default().balance = U256::from(100);
    c.run_with_value(
        user(1),
        Some(weth),
        data("deposit()", &[]),
        true,
        false,
        Some(user(1)),
        U256::from(40),
    )
    .1
    .ok();
    assert_eq!(c.balance(weth, user(1)), U256::from(40));
    c.query(user(2), weth, "balanceOf(address)", &[addr(user(1))])
        .denied();
    c.call(user(1), weth, "withdraw(uint256)", &[uint(15)]).ok();
    assert_eq!(c.balance(weth, user(1)), U256::from(25));
    assert_eq!(c.accounts[&user(1)].balance, U256::from(75));
    c.mint(t0, user(1), 100_000);
    c.mint(t1, user(1), 100_000);
    for t in [t0, t1] {
        c.call(
            user(1),
            t,
            "approve(address,uint256)",
            &[addr(router), uint(100_000)],
        )
        .ok();
    }
    let add = u.call(
        &mut c,
        user(1),
        router,
        "addLiquidity",
        &[
            a(t0),
            a(t1),
            n(10000),
            n(10000),
            n(0),
            n(0),
            a(user(1)),
            n(1000),
        ],
        true,
        false,
    );
    add.ok();
    assert_eq!(c.balance(pair, user(1)), U256::from(9000));
    c.query(user(2), pair, "balanceOf(address)", &[addr(user(1))])
        .denied();
    let swap = u.call(
        &mut c,
        user(1),
        router,
        "swapExactTokensForTokens",
        &[
            n(100),
            n(1),
            Token::Array(vec![a(t0), a(t1)]),
            a(user(2)),
            n(1000),
        ],
        true,
        false,
    );
    swap.ok();
    assert_eq!(c.balance(t1, user(2)), U256::from(98));
    assert!(swap
        .visible(user(3))
        .iter()
        .all(|l| l.topics[0] == hash(b"Sync(uint112,uint112)")));
    c.call(
        user(1),
        pair,
        "transfer(address,uint256)",
        &[addr(user(2)), uint(1000)],
    )
    .ok();
    assert_eq!(c.balance(pair, user(2)), U256::from(1000));
    c.call(
        user(2),
        pair,
        "approve(address,uint256)",
        &[addr(router), uint(500)],
    )
    .ok();
    u.call(
        &mut c,
        user(2),
        router,
        "removeLiquidity",
        &[a(t0), a(t1), n(500), n(0), n(0), a(user(2)), n(1000)],
        true,
        false,
    )
    .ok();
    assert_eq!(c.balance(pair, user(2)), U256::from(500));
    let flash = c.deploy(include_str!("fixtures/privacy/FlashImpostor.bin"), &[]);
    let flash_art = fixture(
        include_str!("fixtures/privacy/FlashImpostor.abi.json"),
        "FlashImpostor",
    );
    c.policies
        .insert(flash.0, policy(&c, flash, &flash_art, &[]));
    c.mint(t0, flash, 100);
    c.mint(t1, flash, 100);
    // Actual pair callback: catch the denied victim read, repay, complete the swap.
    c.call(
        user(2),
        flash,
        "attack(address,address,uint256,uint256)",
        &[addr(pair), addr(user(1)), uint(10), uint(0)],
    )
    .ok();
    assert_eq!(
        c.query(user(2), flash, "leaked()", &[]).number(),
        U256::zero()
    );
    assert_eq!(
        c.query(user(2), flash, "leakedLength()", &[]).number(),
        U256::zero()
    );
    c.query(user(2), pair, "balanceOf(address)", &[addr(user(1))])
        .denied();
    let report = method_matrix(&c, &u, &[factory, weth, router, pair], t0);
    println!(
        "Uniswap: {} methods, {} runtime identity cases",
        report.len(),
        report.len() * 2
    );
    assert!(report.len() > 60);
    if let Ok(dir) = std::env::var("AURORA_COVERAGE_DIR") {
        std::fs::write(
            std::path::Path::new(&dir).join("uniswap-methods.json"),
            serde_json::to_vec_pretty(&report).unwrap(),
        )
        .unwrap();
    }
    // A private factory CREATE must fail without panicking or publishing a pair.
    let fresh = c.token();
    u.call(
        &mut c,
        user(1),
        factory,
        "createPair",
        &[a(t0), a(fresh)],
        true,
        false,
    )
    .denied();
    let absent = u.call(
        &mut c,
        user(1),
        factory,
        "getPair",
        &[a(t0), a(fresh)],
        true,
        true,
    );
    assert_eq!(address_output(&absent), H160::zero());
    // The no-code transfer exception never admits a getter on a fake token EOA.
    c.query(user(1), user(4), "balanceOf(address)", &[addr(user(1))])
        .denied();
    // Canonical dynamic path parsing must reject an offset into the calldata head.
    let f = u.instances[&router].abi.function("getAmountsOut").unwrap();
    let mut input = f
        .encode_input(&[n(10), Token::Array(vec![a(t0), a(t1)])])
        .unwrap();
    input[36..68].copy_from_slice(&uint(0));
    c.run(user(1), Some(router), input, true, true).1.denied();
}

struct AaveMarket {
    c: Chain,
    u: Upstream,
    pool: H160,
    config: H160,
    oracle: H160,
    collateral: H160,
    cash: H160,
    collateral_a: H160,
    cash_a: H160,
    variable_debt: H160,
    proxy_impls: Vec<(H160, H160)>,
}
impl AaveMarket {
    fn new() -> Self {
        let mut c = Chain::default();
        let mut u = Upstream::default();
        let provider = u.deploy(
            &mut c,
            "aave",
            "PoolAddressesProvider",
            &[text("privacy-test"), a(user(0))],
        );
        let pool_impl = u.deploy(&mut c, "aave", "Pool", &[a(provider)]);
        u.boot(&mut c, provider, "setPoolImpl", &[a(pool_impl)]);
        let pool = address_output(&u.boot(&mut c, provider, "getPool", &[]));
        let config_impl = u.deploy(&mut c, "aave", "PoolConfigurator", &[]);
        u.boot(
            &mut c,
            provider,
            "setPoolConfiguratorImpl",
            &[a(config_impl)],
        );
        let config = address_output(&u.boot(&mut c, provider, "getPoolConfigurator", &[]));
        u.instances.insert(pool, u.artifact("aave", "Pool"));
        u.instances
            .insert(config, u.artifact("aave", "PoolConfigurator"));
        u.boot(&mut c, provider, "setACLAdmin", &[a(user(0))]);
        let acl = u.deploy(&mut c, "aave", "ACLManager", &[a(provider)]);
        u.boot(&mut c, provider, "setACLManager", &[a(acl)]);
        for role in [
            "addPoolAdmin",
            "addRiskAdmin",
            "addAssetListingAdmin",
            "addEmergencyAdmin",
            "addBridge",
        ] {
            u.boot(&mut c, acl, role, &[a(user(0))]);
        }
        let oracle = u.deploy(&mut c, "aave", "PriceOracle", &[]);
        u.boot(&mut c, provider, "setPriceOracle", &[a(oracle)]);
        let data_provider = u.deploy(&mut c, "aave", "AaveProtocolDataProvider", &[a(provider)]);
        u.boot(&mut c, provider, "setPoolDataProvider", &[a(data_provider)]);
        let strategy = u.deploy(
            &mut c,
            "aave",
            "ZeroReserveInterestRateStrategy",
            &[a(provider)],
        );
        let collateral = u.deploy(
            &mut c,
            "aave",
            "MintableERC20",
            &[text("Collateral"), text("COL"), n(18)],
        );
        let cash = u.deploy(
            &mut c,
            "aave",
            "MintableERC20",
            &[text("Cash"), text("CASH"), n(18)],
        );
        let ai = u.deploy(&mut c, "aave", "AToken", &[a(pool)]);
        let si = u.deploy(&mut c, "aave", "StableDebtToken", &[a(pool)]);
        let vi = u.deploy(&mut c, "aave", "VariableDebtToken", &[a(pool)]);
        let mut proxy_impls = vec![(pool, pool_impl), (config, config_impl)];
        let mut reserves = Vec::new();
        for asset in [collateral, cash] {
            let init = Token::Tuple(vec![
                a(ai),
                a(si),
                a(vi),
                n(18),
                a(strategy),
                a(asset),
                a(user(9)),
                a(H160::zero()),
                text("aToken"),
                text("aT"),
                text("variableDebt"),
                text("vD"),
                text("stableDebt"),
                text("sD"),
                Token::Bytes(vec![]),
            ]);
            u.boot(&mut c, config, "initReserves", &[Token::Array(vec![init])]);
            u.boot(
                &mut c,
                config,
                "configureReserveAsCollateral",
                &[a(asset), n(5000), n(7500), n(11000)],
            );
            u.boot(
                &mut c,
                config,
                "setReserveBorrowing",
                &[a(asset), Token::Bool(true)],
            );
            u.boot(
                &mut c,
                config,
                "setReserveStableRateBorrowing",
                &[a(asset), Token::Bool(true)],
            );
            u.boot(
                &mut c,
                oracle,
                "setAssetPrice",
                &[
                    a(asset),
                    n(if asset == collateral {
                        200_000_000
                    } else {
                        100_000_000
                    }),
                ],
            );
            let out = u.boot(&mut c, pool, "getReserveData", &[a(asset)]);
            let decoded = u.instances[&pool]
                .abi
                .function("getReserveData")
                .unwrap()
                .decode_output(&out.output)
                .unwrap();
            let fields = decoded[0].clone().into_tuple().unwrap();
            let aa = H160(fields[8].clone().into_address().unwrap().0);
            let sd = H160(fields[9].clone().into_address().unwrap().0);
            let vd = H160(fields[10].clone().into_address().unwrap().0);
            for (proxy, implementation, name) in [
                (aa, ai, "AToken"),
                (sd, si, "StableDebtToken"),
                (vd, vi, "VariableDebtToken"),
            ] {
                assert!(!c.accounts[&proxy].code.is_empty());
                u.instances.insert(proxy, u.artifact("aave", name));
                proxy_impls.push((proxy, implementation));
            }
            reserves.push((aa, sd, vd));
        }
        // Install code-bound proxy/library scopes before any private operations.
        for (proxy, implementation) in &proxy_impls {
            let p = policy(&c, *proxy, &u.instances[proxy], &[]);
            u.bind_proxy(&mut c, *proxy, *implementation, p);
        }
        let mut grants = Vec::new();
        for (proxy, _) in &proxy_impls {
            let p = &c.policies[&proxy.0];
            for hash in std::iter::once(p.code_hash).chain(p.delegates.iter().map(|b| b.code_hash))
            {
                grants.push(Permit::TrustedCaller {
                    address: proxy.0,
                    code_hash: hash,
                });
            }
        }
        for (proxy, implementation) in &proxy_impls {
            let p = policy(&c, *proxy, &u.instances[proxy], &grants);
            u.bind_proxy(&mut c, *proxy, *implementation, p);
        }
        // Library implementations remain inaccessible to direct external calls.
        let code_only: Vec<_> = proxy_impls
            .iter()
            .map(|(_, i)| *i)
            .chain(u.libraries.values().copied())
            .collect();
        let addresses: Vec<_> = u.instances.keys().copied().collect();
        for address in addresses {
            if !code_only.contains(&address) && !proxy_impls.iter().any(|(p, _)| *p == address) {
                register_direct(&mut c, &u, address, &grants);
            }
        }
        Self {
            c,
            u,
            pool,
            config,
            oracle,
            collateral,
            cash,
            collateral_a: reserves[0].0,
            cash_a: reserves[1].0,
            variable_debt: reserves[1].2,
            proxy_impls,
        }
    }
    fn call(&mut self, caller: H160, target: H160, name: &str, args: &[Token]) -> Outcome {
        self.u
            .call(&mut self.c, caller, target, name, args, true, false)
    }
    fn query(&mut self, caller: H160, target: H160, name: &str, args: &[Token]) -> Outcome {
        self.u
            .call(&mut self.c, caller, target, name, args, true, true)
    }
    fn fund(&mut self) {
        for (asset, who, amount) in [
            (self.collateral, user(1), 100),
            (self.cash, user(3), 1000),
            (self.cash, user(2), 100),
        ] {
            self.u
                .boot(&mut self.c, asset, "mint", &[a(who), units(amount)]);
            self.call(who, asset, "approve", &[a(self.pool), units(amount)])
                .ok();
        }
        self.call(
            user(3),
            self.pool,
            "supply",
            &[a(self.cash), units(1000), a(user(3)), n(0)],
        )
        .ok();
        self.call(
            user(1),
            self.pool,
            "supply",
            &[a(self.collateral), units(100), a(user(1)), n(0)],
        )
        .ok();
    }
}

#[test]
fn real_aave_supply_borrow_repay_and_liquidation_preserve_private_positions() {
    let mut m = AaveMarket::new();
    m.fund();
    assert_eq!(m.proxy_impls.len(), 8);
    m.query(user(4), m.config, "CONFIGURATOR_REVISION", &[])
        .ok();
    assert_eq!(
        m.query(user(3), m.cash_a, "balanceOf", &[a(user(3))])
            .number(),
        U256::from(1000) * U256::exp10(18)
    );
    m.call(
        user(1),
        m.pool,
        "borrow",
        &[a(m.cash), units(80), n(2), n(0), a(user(1))],
    )
    .ok();
    let debt = m.query(user(1), m.variable_debt, "balanceOf", &[a(user(1))]);
    debt.ok();
    assert_eq!(debt.number(), U256::from(80) * U256::exp10(18));
    for target in [m.variable_debt, m.collateral_a] {
        m.query(user(2), target, "balanceOf", &[a(user(1))])
            .denied();
    }
    for name in ["getUserAccountData", "getUserConfiguration", "getUserEMode"] {
        m.query(user(1), m.pool, name, &[a(user(1))]).ok();
        m.query(user(2), m.pool, name, &[a(user(1))]).denied();
    }
    m.call(
        user(2),
        m.pool,
        "liquidationCall",
        &[
            a(m.collateral),
            a(m.cash),
            a(user(1)),
            units(20),
            Token::Bool(false),
        ],
    )
    .denied();
    m.call(
        user(0),
        m.oracle,
        "setAssetPrice",
        &[a(m.collateral), n(100_000_000)],
    )
    .ok();
    let liquidation = m.call(
        user(2),
        m.pool,
        "liquidationCall",
        &[
            a(m.collateral),
            a(m.cash),
            a(user(1)),
            units(20),
            Token::Bool(false),
        ],
    );
    liquidation.ok();
    let sig = hash(b"LiquidationCall(address,address,address,uint256,uint256,address,bool)");
    for who in [user(1), user(2)] {
        assert!(liquidation.visible(who).iter().any(|l| l.topics[0] == sig));
    }
    assert!(liquidation.visible(user(4)).iter().all(|l| l.topics[0]
        == hash(b"ReserveDataUpdated(address,uint256,uint256,uint256,uint256,uint256)")));
    assert_eq!(
        m.query(user(2), m.collateral, "balanceOf", &[a(user(2))])
            .number(),
        U256::from(22) * U256::exp10(18)
    );
    assert_eq!(
        m.query(user(1), m.variable_debt, "balanceOf", &[a(user(1))])
            .number(),
        U256::from(60) * U256::exp10(18)
    );
    m.query(user(2), m.variable_debt, "balanceOf", &[a(user(1))])
        .denied();
    m.call(user(1), m.cash, "approve", &[a(m.pool), units(60)])
        .ok();
    m.call(
        user(1),
        m.pool,
        "repay",
        &[a(m.cash), units(60), n(2), a(user(1))],
    )
    .ok();
    m.call(
        user(1),
        m.pool,
        "withdraw",
        &[a(m.collateral), units(78), a(user(1))],
    )
    .ok();
    assert_eq!(
        m.query(user(1), m.collateral_a, "balanceOf", &[a(user(1))])
            .number(),
        U256::zero()
    );
}

#[test]
fn every_aave_deployed_method_has_positive_and_wrong_identity_coverage() {
    let mut m = AaveMarket::new();
    m.fund();
    m.call(
        user(1),
        m.pool,
        "borrow",
        &[a(m.cash), units(80), n(2), n(0), a(user(1))],
    )
    .ok();
    // One deployed instance per ABI, including actual proxies and dependencies.
    let mut by_name = std::collections::BTreeMap::new();
    for address in m.c.policies.keys() {
        let a = H160(*address);
        by_name.entry(m.u.instances[&a].name.clone()).or_insert(a);
    }
    let targets: Vec<_> = by_name.values().copied().collect();
    let report = method_matrix(&m.c, &m.u, &targets, m.cash);
    println!(
        "Aave: {} methods, {} runtime identity cases",
        report.len(),
        report.len() * 2
    );
    assert!(report.len() > 250);
    if let Ok(dir) = std::env::var("AURORA_COVERAGE_DIR") {
        std::fs::write(
            std::path::Path::new(&dir).join("aave-methods.json"),
            serde_json::to_vec_pretty(&report).unwrap(),
        )
        .unwrap();
    }
}

#[test]
fn every_real_proxy_admin_method_checks_authenticated_administrator() {
    let mut c = Chain::default();
    let mut u = Upstream::default();
    let implementation = c.deploy(include_str!("fixtures/privacy/ProxyData.bin"), &[]);
    let proxy = u.proxy(
        &mut c,
        implementation,
        data("initialize(address,uint256)", &[addr(user(1)), uint(100)]),
        user(0),
    );
    let art = u.instances[&proxy].clone();
    let mut p = policy(&c, proxy, &art, &[]);
    for method in p.methods.values_mut() {
        method.any_of = vec![Permit::Principal(user(0).0)];
    }
    c.policies.insert(proxy.0, p);
    assert_eq!(art.abi.functions().count(), 5);
    for f in art.abi.functions() {
        let args: Vec<_> = f
            .inputs
            .iter()
            .map(|i| match i.kind {
                ethabi::ParamType::Address => a(implementation),
                ethabi::ParamType::Bytes => Token::Bytes(vec![]),
                _ => panic!("unexpected proxy input"),
            })
            .collect();
        let input = f.encode_input(&args).unwrap();
        let good = c
            .clone()
            .run(user(0), Some(proxy), input.clone(), true, false)
            .1;
        assert!(good.decisions[0].admitted, "{}", f.signature());
        let bad = c
            .clone()
            .run(user(2), Some(proxy), input.clone(), true, false)
            .1;
        assert!(!bad.decisions[0].admitted, "{}", f.signature());
        bad.denied();
        assert!(bad.logs.is_empty());
        assert!(bad.output.is_empty());
        let baseline = c.clone().run(user(0), Some(proxy), input, false, false).1;
        if baseline.reason.is_succeed() {
            good.ok();
            assert_eq!(good.output, baseline.output);
        }
        // Initializing twice and upgradeToAndCall with empty calldata revert natively.
    }
}

#[test]
fn aave_flash_loan_arbitrages_two_real_uniswap_venues_with_private_profit() {
    let mut m = AaveMarket::new();
    m.fund();
    m.call(
        user(0),
        m.config,
        "setReserveFlashLoaning",
        &[a(m.cash), Token::Bool(true)],
    )
    .ok();
    m.call(user(0), m.config, "updateFlashloanPremiumTotal", &[n(9)])
        .ok();
    let lp = user(5);
    let trader = user(2);
    let mut routers = Vec::new();
    let mut pairs = Vec::new();
    for collateral_liquidity in [20_000, 10_000] {
        let factory =
            m.u.deploy(&mut m.c, "uni", "UniswapV2Factory", &[a(user(0))]);
        let weth = m.u.deploy(&mut m.c, "router", "WETH9", &[]);
        let router = m.u.deploy(
            &mut m.c,
            "router",
            "UniswapV2Router02",
            &[a(factory), a(weth)],
        );
        m.u.boot(
            &mut m.c,
            factory,
            "createPair",
            &[a(m.cash), a(m.collateral)],
        );
        let pair =
            address_output(&m.u.boot(&mut m.c, factory, "getPair", &[a(m.cash), a(m.collateral)]));
        m.u.instances
            .insert(pair, m.u.artifact("uni", "UniswapV2Pair"));
        for target in [factory, weth, router, pair] {
            register_direct(&mut m.c, &m.u, target, &[]);
        }
        for (token, amount) in [(m.cash, 10_000), (m.collateral, collateral_liquidity)] {
            m.u.boot(&mut m.c, token, "mint", &[a(lp), units(amount)]);
            m.call(lp, token, "approve", &[a(router), units(amount)])
                .ok();
        }
        m.call(
            lp,
            router,
            "addLiquidity",
            &[
                a(m.cash),
                a(m.collateral),
                units(10_000),
                units(collateral_liquidity),
                n(0),
                n(0),
                a(lp),
                n(1000),
            ],
        )
        .ok();
        routers.push(router);
        pairs.push(pair);
    }
    let receiver = m.c.deploy(
        include_str!("fixtures/privacy/FlashArbitrage.bin"),
        &[
            addr(m.pool),
            addr(routers[0]),
            addr(routers[1]),
            addr(m.cash),
            addr(m.collateral),
        ],
    );
    let art = fixture(
        include_str!("fixtures/privacy/FlashArbitrage.abi.json"),
        "FlashArbitrage",
    );
    m.u.instances.insert(receiver, art.clone());
    let mut p = policy(&m.c, receiver, &art, &[]);
    p.methods
        .get_mut(&selector("run(address,uint256,uint256)"))
        .unwrap()
        .any_of = vec![Permit::PrincipalArg(0)];
    p.methods
        .get_mut(&selector("profits(address)"))
        .unwrap()
        .any_of = vec![Permit::PrincipalArg(0)];
    let callback = selector("executeOperation(address,uint256,uint256,address,bytes)");
    // Only actual code executing in the Aave Pool proxy may enter the callback.
    let pool_policy = &m.c.policies[&m.pool.0];
    p.methods.get_mut(&callback).unwrap().any_of = pool_policy
        .delegates
        .iter()
        .map(|edge| Permit::TrustedCaller {
            address: m.pool.0,
            code_hash: edge.code_hash,
        })
        .collect();
    m.c.policies.insert(receiver.0, p);

    let base = m.c.clone();
    // Both swaps must roll back when profit is insufficient or callback binding is absent.
    for missing_grant in [false, true] {
        m.c = base.clone();
        if missing_grant {
            m.c.policies
                .get_mut(&receiver.0)
                .unwrap()
                .methods
                .get_mut(&callback)
                .unwrap()
                .any_of = vec![Permit::TrustedCaller {
                address: m.pool.0,
                code_hash: [0; 32],
            }];
        }
        let failed = m.call(
            trader,
            receiver,
            "run",
            &[
                a(trader),
                units(100),
                units(if missing_grant { 1 } else { 10_000 }),
            ],
        );
        failed.denied();
        assert!(failed.output.is_empty());
        assert!(failed.logs.is_empty());
        assert_eq!(failed.decisions.iter().any(|d| !d.admitted), missing_grant);
        if missing_grant {
            assert!(failed
                .decisions
                .iter()
                .any(|d| d.selector == Some(callback) && !d.admitted));
        } else {
            let swap_selector =
                selector("swapExactTokensForTokens(uint256,uint256,address[],address,uint256)");
            assert_eq!(
                failed
                    .decisions
                    .iter()
                    .filter(|d| d.selector == Some(swap_selector))
                    .count(),
                2
            );
        }
        for address in [
            m.cash,
            m.collateral,
            m.cash_a,
            m.pool,
            receiver,
            pairs[0],
            pairs[1],
        ] {
            assert_eq!(
                m.c.accounts[&address].storage, base.accounts[&address].storage,
                "rollback {address:?}"
            );
            assert_eq!(
                m.c.accounts[&address].balance,
                base.accounts[&address].balance
            );
        }
    }
    m.c = base;
    let forged = m.call(
        user(4),
        receiver,
        "executeOperation",
        &[
            a(m.cash),
            units(100),
            n(0),
            a(receiver),
            Token::Bytes(vec![]),
        ],
    );
    forged.denied();
    assert!(!forged.decisions[0].admitted);
    m.call(user(4), receiver, "run", &[a(trader), units(100), units(1)])
        .denied();
    // Even a genuine Pool callback cannot spoof this receiver's initiator.
    m.call(
        user(4),
        m.pool,
        "flashLoanSimple",
        &[
            a(receiver),
            a(m.cash),
            units(100),
            Token::Bytes(vec![]),
            n(0),
        ],
    )
    .denied();

    let before = m.query(trader, m.cash, "balanceOf", &[a(trader)]).number();
    // Independent trusted-host observation; never an RPC path exposed to the trader.
    let pool_cash_before =
        m.u.call(
            &mut m.c,
            user(0),
            m.cash,
            "balanceOf",
            &[a(m.cash_a)],
            false,
            true,
        )
        .number();
    let bps = m
        .query(trader, m.pool, "FLASHLOAN_PREMIUM_TOTAL", &[])
        .number();
    let amount = U256::from(100) * U256::exp10(18);
    let premium = (amount * bps + U256::from(5000)) / U256::from(10_000);
    assert!(premium > U256::zero());
    let swap_out = |input: U256, reserve_in: U256, reserve_out: U256| {
        input * U256::from(997) * reserve_out
            / (reserve_in * U256::from(1000) + input * U256::from(997))
    };
    let reserve = U256::from(10_000) * U256::exp10(18);
    let bought = swap_out(amount, reserve, reserve * U256::from(2));
    let proceeds = swap_out(bought, reserve, reserve);
    let expected_profit = proceeds - amount - premium;
    assert!(expected_profit > U256::exp10(18));
    let result = m.call(trader, receiver, "run", &[a(trader), units(100), units(1)]);
    result.ok();
    assert!(result.decisions.iter().all(|d| d.admitted));
    assert!(result
        .decisions
        .iter()
        .any(|d| d.code_address == receiver.0 && d.selector == Some(callback)));
    for router in &routers {
        assert!(result.decisions.iter().any(|d| d.code_address == router.0));
    }
    assert_eq!(
        m.query(trader, receiver, "profits", &[a(trader)]).number(),
        expected_profit
    );
    assert_eq!(
        m.query(trader, m.cash, "balanceOf", &[a(trader)]).number(),
        before + expected_profit
    );
    let pool_cash_after =
        m.u.call(
            &mut m.c,
            user(0),
            m.cash,
            "balanceOf",
            &[a(m.cash_a)],
            false,
            true,
        )
        .number();
    assert_eq!(pool_cash_after, pool_cash_before + premium);
    for token in [m.cash, m.collateral] {
        assert_eq!(
            m.u.call(
                &mut m.c,
                user(0),
                token,
                "balanceOf",
                &[a(receiver)],
                false,
                true
            )
            .number(),
            U256::zero()
        );
    }
    assert_eq!(
        m.query(trader, m.variable_debt, "balanceOf", &[a(trader)])
            .number(),
        U256::zero()
    );
    m.query(user(4), receiver, "profits", &[a(trader)]).denied();
    m.query(user(4), m.cash, "balanceOf", &[a(trader)]).denied();
    m.query(trader, m.cash_a, "balanceOf", &[a(user(3))])
        .denied();
    let profit_event = hash(b"Profit(address,uint256)");
    assert!(result
        .visible(trader)
        .iter()
        .any(|l| l.topics[0] == profit_event));
    assert!(result.visible(user(4)).iter().all(|l| [
        hash(b"Sync(uint112,uint112)"),
        hash(b"ReserveDataUpdated(address,uint256,uint256,uint256,uint256,uint256)"),
    ]
    .contains(&l.topics[0])));
    assert_eq!(
        result
            .logs
            .iter()
            .filter(
                |l| l.topics[0] == hash(b"Swap(address,uint256,uint256,uint256,uint256,address)")
            )
            .count(),
        2
    );
    assert_eq!(
        result
            .logs
            .iter()
            .filter(|l| l.topics[0]
                == hash(b"FlashLoan(address,address,address,uint256,uint8,uint256,uint16)"))
            .count(),
        1
    );
}
