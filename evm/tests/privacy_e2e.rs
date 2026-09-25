#![cfg(feature = "privacy")]
mod common;
use aurora_evm::privacy::{Arg, EventAudience, Permit, Recipient};
use common::*;
use primitive_types::{H160, U256};

#[test]
fn erc20_transfer_receipt_and_delegated_spending_keep_balances_private() {
    let mut chain = Chain::default();
    let token = chain.token();
    let alice = user(1);
    let bob = user(2);
    let spender = user(3);
    let outsider = user(4);
    chain.mint(token, alice, 100);
    let transfer = chain.call(
        alice,
        token,
        "transfer(address,uint256)",
        &[addr(bob), uint(10)],
    );
    transfer.ok();
    assert_eq!(transfer.logs.len(), 1);
    assert_eq!(transfer.visible(alice).len(), 1);
    assert_eq!(transfer.visible(bob).len(), 1);
    assert!(transfer.visible(outsider).is_empty());
    assert_eq!(chain.balance(token, alice), U256::from(90));
    assert_eq!(chain.balance(token, bob), U256::from(10));
    chain
        .query(alice, token, "balanceOf(address)", &[addr(bob)])
        .denied();
    chain
        .query(outsider, token, "balanceOf(address)", &[addr(alice)])
        .denied();
    chain
        .call(
            alice,
            token,
            "approve(address,uint256)",
            &[addr(spender), uint(25)],
        )
        .ok();
    let delegated = chain.call(
        spender,
        token,
        "transferFrom(address,address,uint256)",
        &[addr(alice), addr(bob), uint(20)],
    );
    delegated.ok();
    assert_eq!(delegated.visible(spender).len(), 1);
    assert_eq!(delegated.visible(alice).len(), 1);
    assert_eq!(delegated.visible(bob).len(), 1);
    assert!(delegated.visible(outsider).is_empty());
    chain
        .query(spender, token, "balanceOf(address)", &[addr(alice)])
        .denied();
    assert_eq!(
        chain
            .query(
                spender,
                token,
                "allowance(address,address)",
                &[addr(alice), addr(spender)]
            )
            .number(),
        U256::from(5)
    );
    chain
        .query(
            bob,
            token,
            "allowance(address,address)",
            &[addr(alice), addr(spender)],
        )
        .denied();
    chain
        .call(
            outsider,
            token,
            "transferFrom(address,address,uint256)",
            &[addr(alice), addr(outsider), uint(1)],
        )
        .denied();
    assert_eq!(chain.balance(token, alice), U256::from(70));
    assert_eq!(chain.balance(token, bob), U256::from(30));
}

#[test]
fn nested_getters_and_delegatecall_cannot_bypass_policy() {
    let mut chain = Chain::default();
    let token = chain.token();
    let router = chain.router();
    chain.mint(token, user(1), 100);
    assert_eq!(
        chain
            .query(
                user(1),
                router,
                "readBalance(address,address)",
                &[addr(token), addr(user(1))]
            )
            .number(),
        U256::from(100)
    );
    chain
        .query(
            user(2),
            router,
            "readBalance(address,address)",
            &[addr(token), addr(user(1))],
        )
        .denied();
    chain
        .call(
            user(1),
            router,
            "delegateRead(address,address)",
            &[addr(token), addr(user(1))],
        )
        .denied();
}

#[test]
fn swap_updates_reserves_and_delivers_output_to_unsigned_recipient() {
    let mut chain = Chain::default();
    let a = chain.token();
    let b = chain.token();
    let router = chain.router();
    let pair = chain.deploy(
        include_str!("fixtures/privacy/Pair.bin"),
        &[addr(a), addr(b)],
    );
    chain.mint(a, pair, 1000);
    chain.mint(b, pair, 1000);
    chain.mint(a, user(1), 200);
    chain.bootstrap(pair, "sync()", &[]);
    let mut p = chain.policy(pair);
    method(&mut p, "getReserves()", vec![], vec![Permit::Public], true);
    method(
        &mut p,
        "swap(uint256,address)",
        vec![Arg::Uint256, Arg::Address],
        vec![Permit::Public],
        false,
    );
    event(&mut p, "Sync(uint256,uint256)", 0, 2, EventAudience::Public);
    event(
        &mut p,
        "Swap(address,address,uint256,uint256)",
        2,
        2,
        EventAudience::Participants(vec![Recipient::Principal, Recipient::TopicAddress(2)]),
    );
    chain.policies.insert(pair.0, p);
    chain
        .call(
            user(1),
            a,
            "approve(address,uint256)",
            &[addr(router), uint(200)],
        )
        .ok();
    let result = chain.call(
        user(1),
        router,
        "swap(address,address,uint256,uint256,address)",
        &[addr(pair), addr(a), uint(100), uint(90), addr(user(2))],
    );
    result.ok();
    assert_eq!(chain.balance(a, user(1)), U256::from(100));
    assert_eq!(chain.balance(b, user(2)), U256::from(90));
    let reserves = chain.query(user(3), pair, "getReserves()", &[]);
    reserves.ok();
    assert_eq!(
        U256::from_big_endian(&reserves.output[..32]),
        U256::from(1100)
    );
    assert_eq!(
        U256::from_big_endian(&reserves.output[32..]),
        U256::from(910)
    );
    // Outsiders can see public reserve updates, not private transfers/swap identities.
    assert_eq!(result.visible(user(3)).len(), 1);
    assert_eq!(
        result.visible(user(3))[0].topics[0],
        hash(b"Sync(uint256,uint256)")
    );
    assert!(result
        .visible(user(2))
        .iter()
        .any(|l| l.topics[0] == hash(b"Swap(address,address,uint256,uint256)")));
    // Parent frame is restored after all pair/token calls: Router.Done is Alice's.
    assert!(result
        .visible(user(1))
        .iter()
        .any(|l| l.emitter == router.0));
    let failed = chain.call(
        user(1),
        router,
        "swap(address,address,uint256,uint256,address)",
        &[addr(pair), addr(a), uint(10), uint(800), addr(user(2))],
    );
    failed.denied();
    assert!(failed.logs.is_empty());
    assert_eq!(chain.balance(a, user(1)), U256::from(100));
    assert_eq!(chain.balance(b, user(2)), U256::from(90));
}

#[test]
#[allow(clippy::too_many_lines)] // Keep the full supply/borrow/liquidation lifecycle together.
fn lending_liquidates_without_disclosing_borrower_position_to_liquidator() {
    let mut chain = Chain::default();
    let collateral = chain.token();
    let cash = chain.token();
    let ledger = chain.deploy(include_str!("fixtures/privacy/DebtLedger.bin"), &[]);
    let pool = chain.deploy(
        include_str!("fixtures/privacy/Lending.bin"),
        &[addr(collateral), addr(cash), addr(ledger)],
    );
    chain.bootstrap(ledger, "setController(address)", &[addr(pool)]);
    chain.mint(collateral, user(1), 100);
    chain.mint(cash, pool, 1000);
    chain.mint(cash, user(2), 100);
    let grant = Permit::TrustedCaller {
        address: pool.0,
        code_hash: chain.code_hash(pool),
    };
    let mut p = chain.policy(ledger);
    let mut readers = owner();
    readers.push(grant.clone());
    method(&mut p, "debtOf(address)", vec![Arg::Address], readers, true);
    for name in ["add(address,uint256)", "reduce(address,uint256)"] {
        method(
            &mut p,
            name,
            vec![Arg::Address, Arg::Uint256],
            vec![grant.clone()],
            false,
        );
    }
    chain.policies.insert(ledger.0, p);
    let mut p = chain.policy(pool);
    for name in ["collateralOf(address)", "health(address)"] {
        method(&mut p, name, vec![Arg::Address], owner(), true);
    }
    for name in ["supply(uint256)", "borrow(uint256)", "setPrice(uint256)"] {
        method(
            &mut p,
            name,
            vec![Arg::Uint256],
            vec![Permit::Public],
            false,
        );
    }
    method(
        &mut p,
        "liquidate(address,uint256)",
        vec![Arg::Address, Arg::Uint256],
        vec![Permit::Public],
        false,
    );
    for name in ["Supply(address,uint256)", "Borrow(address,uint256)"] {
        event(
            &mut p,
            name,
            1,
            1,
            EventAudience::Participants(vec![Recipient::TopicAddress(1)]),
        );
    }
    event(
        &mut p,
        "Liquidation(address,address,uint256,uint256)",
        2,
        2,
        EventAudience::Participants(vec![Recipient::TopicAddress(1), Recipient::TopicAddress(2)]),
    );
    chain.policies.insert(pool.0, p);
    chain
        .call(
            user(1),
            collateral,
            "approve(address,uint256)",
            &[addr(pool), uint(100)],
        )
        .ok();
    chain
        .call(user(1), pool, "supply(uint256)", &[uint(100)])
        .ok();
    chain
        .call(user(1), pool, "borrow(uint256)", &[uint(80)])
        .ok();
    assert_eq!(chain.balance(cash, user(1)), U256::from(80));
    assert_eq!(
        chain
            .query(user(1), ledger, "debtOf(address)", &[addr(user(1))])
            .number(),
        U256::from(80)
    );
    chain
        .query(user(2), ledger, "debtOf(address)", &[addr(user(1))])
        .denied();
    chain
        .query(user(2), pool, "health(address)", &[addr(user(1))])
        .denied();
    chain
        .call(
            user(2),
            cash,
            "approve(address,uint256)",
            &[addr(pool), uint(100)],
        )
        .ok();
    let healthy = chain.call(
        user(2),
        pool,
        "liquidate(address,uint256)",
        &[addr(user(1)), uint(40)],
    );
    healthy.denied();
    assert!(healthy.logs.is_empty());
    chain
        .call(user(0), pool, "setPrice(uint256)", &[uint(1)])
        .ok();
    let liquidation = chain.call(
        user(2),
        pool,
        "liquidate(address,uint256)",
        &[addr(user(1)), uint(20)],
    );
    liquidation.ok();
    assert!(liquidation.visible(user(3)).is_empty());
    let signature = hash(b"Liquidation(address,address,uint256,uint256)");
    for participant in [user(1), user(2)] {
        assert!(liquidation
            .visible(participant)
            .iter()
            .any(|l| l.topics[0] == signature));
    }
    assert_eq!(chain.balance(collateral, user(2)), U256::from(22));
    assert_eq!(chain.balance(cash, user(2)), U256::from(80));
    assert_eq!(
        chain
            .query(user(1), ledger, "debtOf(address)", &[addr(user(1))])
            .number(),
        U256::from(60)
    );
    assert_eq!(
        chain
            .query(user(1), pool, "collateralOf(address)", &[addr(user(1))])
            .number(),
        U256::from(78)
    );
    chain
        .query(user(2), pool, "collateralOf(address)", &[addr(user(1))])
        .denied();
    // The position remains liquidatable: 60 debt > 75% of 78 collateral.
    // Removing the grant must block a liquidation that otherwise succeeds.
    chain
        .policies
        .get_mut(&ledger.0)
        .unwrap()
        .methods
        .get_mut(&selector("debtOf(address)"))
        .unwrap()
        .any_of = owner();
    chain
        .call(
            user(2),
            pool,
            "liquidate(address,uint256)",
            &[addr(user(1)), uint(1)],
        )
        .denied();
    chain
        .policies
        .get_mut(&ledger.0)
        .unwrap()
        .methods
        .get_mut(&selector("debtOf(address)"))
        .unwrap()
        .any_of
        .push(grant);
    chain
        .call(
            user(2),
            pool,
            "liquidate(address,uint256)",
            &[addr(user(1)), uint(1)],
        )
        .ok();
}

#[test]
fn unknown_event_reverts_token_state_and_caught_child_logs_do_not_escape() {
    let mut chain = Chain::default();
    let token = chain.token();
    let router = chain.router();
    chain.mint(token, user(1), 100);
    chain.mint(token, router, 20);
    chain
        .call(
            user(1),
            token,
            "approve(address,uint256)",
            &[addr(router), uint(100)],
        )
        .ok();
    let failed = chain.call(
        user(1),
        router,
        "transferThenRevert(address,address,uint256)",
        &[addr(token), addr(user(2)), uint(10)],
    );
    failed.denied();
    assert!(failed.logs.is_empty());
    assert_eq!(chain.balance(token, user(1)), U256::from(100));
    assert_eq!(chain.balance(token, user(2)), U256::zero());
    chain.policies.get_mut(&token.0).unwrap().events.clear();
    let failed = chain.call(
        user(1),
        token,
        "transfer(address,uint256)",
        &[addr(user(2)), uint(10)],
    );
    failed.denied();
    assert!(failed.logs.is_empty());
    assert_eq!(chain.balance(token, user(1)), U256::from(100));
    let caught = chain.call(
        user(1),
        router,
        "catchTransfer(address,address,uint256)",
        &[addr(token), addr(user(2)), uint(10)],
    );
    caught.ok();
    assert_eq!(caught.logs.len(), 1);
    assert_eq!(caught.logs[0].emitter, router.0);
    assert_eq!(chain.balance(token, user(2)), U256::zero());
}

#[test]
fn queries_unknown_selectors_and_code_changes_fail_closed() {
    let mut chain = Chain::default();
    let token = chain.token();
    chain.mint(token, user(1), 100);
    chain
        .query(
            user(1),
            token,
            "transfer(address,uint256)",
            &[addr(user(2)), uint(10)],
        )
        .denied();
    assert_eq!(chain.balance(token, user(1)), U256::from(100));
    // Compiled mint exists and admin is authenticated, but no method grant exists.
    chain
        .call(
            user(0),
            token,
            "mint(address,uint256)",
            &[addr(user(1)), uint(1)],
        )
        .denied();
    let mut malformed = data("balanceOf(address)", &[addr(user(1))]);
    malformed[4] = 1;
    chain
        .run(user(1), Some(token), malformed, true, true)
        .1
        .denied();
    chain.policies.get_mut(&token.0).unwrap().code_hash = [0; 32];
    chain.query(user(1), token, "totalSupply()", &[]).denied();
    chain.policies.clear();
    chain.query(user(1), token, "totalSupply()", &[]).denied();
}

#[test]
fn misclassified_write_method_still_cannot_write_during_query() {
    let mut chain = Chain::default();
    let token = chain.token();
    chain
        .policies
        .get_mut(&token.0)
        .unwrap()
        .methods
        .get_mut(&selector("approve(address,uint256)"))
        .unwrap()
        .query = true;
    let result = chain.query(
        user(1),
        token,
        "approve(address,uint256)",
        &[addr(user(2)), uint(10)],
    );
    result.denied();
    assert!(result.logs.is_empty());
    assert_eq!(
        chain
            .query(
                user(1),
                token,
                "allowance(address,address)",
                &[addr(user(1)), addr(user(2))]
            )
            .number(),
        U256::zero()
    );
}

#[test]
fn reverted_balance_data_is_scrubbed_before_a_caller_can_catch_it() {
    let mut chain = Chain::default();
    let token = chain.token();
    let router = chain.router();
    chain.mint(token, user(1), 12345);
    method(
        chain.policies.get_mut(&token.0).unwrap(),
        "failBalance(address)",
        vec![Arg::Address],
        vec![Permit::Public],
        true,
    );
    method(
        chain.policies.get_mut(&router.0).unwrap(),
        "errorSize(address,address)",
        vec![Arg::Address, Arg::Address],
        vec![Permit::Public],
        true,
    );
    let result = chain.query(user(2), token, "failBalance(address)", &[addr(user(1))]);
    result.denied();
    assert!(result.output.is_empty());
    assert_eq!(
        chain
            .query(
                user(2),
                router,
                "errorSize(address,address)",
                &[addr(token), addr(user(1))]
            )
            .number(),
        U256::zero()
    );
    // Same compiled bytecode leaks the full custom error without enforcement.
    let transparent = chain
        .run(
            user(2),
            Some(token),
            data("failBalance(address)", &[addr(user(1))]),
            false,
            true,
        )
        .1;
    assert_eq!(transparent.output.len(), 36);
    assert_eq!(
        U256::from_big_endian(&transparent.output[4..]),
        U256::from(12345)
    );
}

#[test]
fn authenticated_principal_cannot_be_replaced_by_rpc_from_or_contract_address() {
    let mut chain = Chain::default();
    let token = chain.token();
    let router = chain.router();
    chain.mint(token, user(1), 100);
    chain
        .run_authenticated(
            user(1),
            Some(token),
            data("balanceOf(address)", &[addr(user(1))]),
            true,
            true,
            Some(user(2)),
        )
        .1
        .denied();
    chain
        .run_authenticated(
            user(1),
            Some(token),
            data("balanceOf(address)", &[addr(user(1))]),
            true,
            true,
            None,
        )
        .1
        .denied();
    // Anonymous queries can access genuinely public methods only.
    let public = chain
        .run_authenticated(
            H160::zero(),
            Some(token),
            data("totalSupply()", &[]),
            true,
            true,
            None,
        )
        .1;
    assert_eq!(public.number(), U256::from(100));
    // Host principal API must not be used to impersonate an existing contract.
    chain
        .query(router, token, "balanceOf(address)", &[addr(router)])
        .denied();
    let code = hex::decode(include_str!("fixtures/privacy/Token.bin").trim()).unwrap();
    chain.run(user(1), None, code, true, false).1.denied();
}
