# Experimental method-level privacy

Run existing EVM contracts inside a NEAR TEE private shard, with RPC inside the
trusted boundary. Keep contract bytecode unchanged and enforce access at method
entry and event export. Contracts can compute over **all their own state**;
users choose whether to trust the published code, dependencies and policy.

Field-level visibility is unnecessary for this model: the host hides raw storage,
while existing getters expose public or user-specific results. An authenticated
principal propagates through permitted calls independently of `msg.sender`.
Receiving tokens or repaying another user's debt does not require their signature.

The guarantee is restricted access to protected interfaces, not automatic tracking
of confidential information. Approved code can disclose anything it learns through
an allowed output. Public code makes that trust reviewable, not automatically safe.

## Implementation and use

Enable the `privacy` feature and construct the executor with
`StackExecutor::new_with_privacy(state, config, precompiles, privacy_config)`.
Existing `new_with_precompiles` execution remains unchanged, even when the feature
is compiled in. `privacy::PrivacyConfig::new(policies, principal, query)` validates
and owns an immutable, bounded policy snapshot for one root execution.

This is executor enforcement, not an RPC server, signature verifier, TEE runtime,
or production confidentiality claim. The host must verify the principal, protect
the backend and all tracing, and prevent alternate data-export paths. Only the
trusted host can construct or replace policy snapshots. There is no externally
callable registration method in this execution-library repository.

The implementation lives in [src/privacy.rs](src/privacy.rs), canonical ABI
validation in [src/privacy/abi.rs](src/privacy/abi.rs), and execution hooks in
[src/executor/stack/executor.rs](src/executor/stack/executor.rs). These are the
maintained policy definitions; there is no separate reference evaluator.

## Why method policies

`balanceOf(account)` is a natural disclosure boundary; `totalSupply()` can stay
public without annotating storage slots. The same approach covers computed values
such as account health. It avoids mapping-key recovery, storage-layout manifests,
and changes to `SLOAD`/`SSTORE`. Field metadata would become relevant for selective
raw-state export or general runtime information-flow tracking, neither of which
is implemented here.

Every supported implementation still needs an interface review: events, errors,
other methods, and observable success/failure can disclose data. A protocol grant
must not accidentally authorize a public forwarding method to export private
results. Inherited user authority is deliberately broad: downstream code may query
other contracts' permitted interfaces for that user. Per-request contract/method
scopes could narrow this authority, but are not implemented.

## Enforced rules

- Every admitted contract entry is bound to its address and actual bytecode
  hash. Every selector needs a rule, including public getters. Canonical ABI
  schemas validate static words and bounded dynamic bytes, arrays and tuples
  before permissions; aliasing offsets, dirty padding and suffixes fail.
- Permissions allow public calls, a principal matching an address argument, an
  immediate caller matching an argument, a fixed authenticated principal, or an
  exact contract-address/code-hash grant. The root principal is inherited independently of `msg.sender`.
- The root caller must match the supplied authenticated principal. Anonymous
  queries use `principal = None` and zero caller. A non-empty-code account cannot
  be impersonated as a root EOA. Contract wallets/relayers need a future explicit
  authentication integration.
- Query mode forces EVM static execution throughout the call chain and requires
  methods marked query-compatible. The host must discard query state, including
  transaction bookkeeping; this API currently uses `transact_call` for queries.
- Logs are classified by the active callee's admitted policy. Labels and logs
  reside in `StackSubstateMetadata`, merging only on successful commit and
  disappearing together on revert/discard. Parent frame identity is restored
  with the existing substate stack, including caught child failures.
- All privacy-mode logs, including public ones, use `protected_logs()` rather
  than the ordinary `StackState::log` channel. Copy these logs after root success
  **before** consuming `into_state()`. Persist them in trusted storage atomically
  with state changes. `can_export(log, verified_viewer)` is the audience filter;
  an arbitrary RPC `from` value is not a verified viewer.
- Private event audiences can select indexed/non-indexed addresses, the root
  principal, or the immediate caller. Zero-address placeholders are not recipients. Unknown
  or malformed events fail the emitting frame and roll back its writes.
- Failed contract calls expose no revert bytes in privacy mode, even to a parent
  contract. Success/failure, gas, and permitted outputs remain observable. Source
  code and its allowed interfaces must still be reviewed for disclosure.

Native balance/code introspection remains ordinary EVM behavior; there is no
field-level or general information-flow tracking. Contracts are trusted with all
their own storage and with data returned through permitted dependencies.

## Scope and compatibility

Direct contracts and explicitly bound proxies/linked libraries are supported.
A `DelegateBinding` pins a source-code address, target-code address, and target
runtime hash within one storage owner's policy. Proxy edges additionally require
byte-for-byte forwarding of admitted calldata. Linked-library edges permit new
arguments and therefore trust the reviewed library with **all** proxy storage.
Delegate frames preserve the storage owner's identity, principal, original caller,
and event emitter. Outgoing trusted-caller checks use the storage owner's address
and the actual executing implementation/library hash. Policy review must include
both the implementation and every allowed library, not just the proxy shell.
An upgrade fails closed until its new code binding is authorized. Implementations
are not callable directly unless separately registered. Transparent proxy admins
need explicit selector rules alongside the implementation's rules.

`CALLCODE`, EIP-7702 execution/authorization lists, contract creation, precompiles,
raw `execute` entry, and system calls remain denied. An authenticated empty call
to a no-code, non-precompile account is allowed, including native transfers.
Unknown contracts and fallback/receive calls to executable code fail closed.
Constructors/factory creation are run in trusted bootstrap before installing
policies in tests; do not expose an unprotected bootstrap endpoint in deployment.

Calls add a provisional 200-gas policy fee plus 6 gas per 32 bytes of code hashed.
Event classification adds 200 gas to existing LOG costs. Fees are paid on denied
checks as well. Registry bounds limit schemas/rules/recipients. This schedule
needs benchmarking before a production protocol decision.

Privacy changes ABI admission and failure observability; it does not modify
contract bytecode or `SLOAD`/`SSTORE`. In particular, custom revert data disappears
and noncanonical or extra calldata is rejected. Dynamic ABI payloads are capped
at 64 KiB, arrays at 1,024 elements, and schemas at 256 nodes/eight nesting levels.
Signed integer/fixed-array schemas and fallback policies are not implemented.
`privacy_decisions()` is a trusted-host diagnostic containing private call
metadata, including reverted calls; never publish it in RPC/receipts. Its memory
usage grows with metered calls and needs host transaction resource limits.

An allowance still leaks spendability to its holder. Public pool reserves reveal
net flows. Liquidation success reveals eligibility. No claim is made that method
checks hide these inference channels or prevent trusted code deliberately
returning secrets through an allowed method.

## Contract examples

These are disclosure choices for reviewed contracts, not rules that can safely be
inferred from a method name on arbitrary bytecode. The exact fixture policies and
protocol versions are linked in the [test coverage guide](tests/fixtures/upstream/README.md).

### ERC-20: transfers, receipt and allowances

| Method | Admission rule |
| --- | --- |
| `name`, `symbol`, `decimals`, `totalSupply` | Public |
| `balanceOf(account)` | Principal or immediate caller matches `account` |
| `allowance(owner, spender)` | Principal or immediate caller matches owner or spender |
| `transfer`, `approve`, `transferFrom` | Admit; token code enforces mutation authority |

For `balanceOf(address)`, this means `args = [Arg::Address]` and
`any_of = [Permit::PrincipalArg(0), Permit::CallerArg(0)]`. Public admission does
not grant raw-state access or bypass transaction authentication and token rules.
Token-internal reads of other users' balances remain unrestricted.

When Alice calls `transfer(Bob, 10)`, the token debits Alice and credits Bob without
calling Bob. Bob needs no signature, prior session or claim transaction. Alice
learns the amount and success, not Bob's total balance. The host can retain the
protected event until Bob authenticates, without requiring a pre-registered
recipient encryption key.

For `Alice → Router → Token.transferFrom(Alice, Pool, 20)`, `msg.sender` remains
Router and the token checks its existing allowance. The router need not read
Alice's total balance. Another actor may trigger an approved spender if its code
permits; the allowance authorizes spending but does not grant balance-getter access.
The pool can receive tokens without signing.

The built-in `erc20_policy` assigns `Approval` to owner/spender and `Transfer` to
sender/recipient plus the immediate caller. The delegated spender comes from the
execution frame because the standard event lacks that field. Contract addresses
in event audiences do not authorize their developers to impersonate them at RPC.
Individual application policies must explicitly choose their participant rules.

### Uniswap V2: swaps and liquidity

The tested initial policy keeps token addresses, reserves, cumulative prices and
fee settings public, while LP balances/allowances use user restrictions. Swap,
mint and burn events have participant audiences; reserve `Sync` events are public.

```text
Alice → Router
          Pair.getReserves()
          TokenA.transferFrom(Alice, Pair, input)
          Pair.swap(output, Bob, ...)
            TokenB.transfer(Bob, output)
            TokenA.balanceOf(Pair)
            TokenB.balanceOf(Pair)
            update reserves
```

The pair may read its own token balances. Bob can receive the output without
providing authorization. Event policy must account for the initiating principal
and designated recipient because the pair's immediate caller is often a router.

Public reserves expose net flows and may reveal isolated trade amounts. Hiding
swap events does not provide trade-amount secrecy. A private-reserve design would
also need to restrict token-balance getters, quotes, cumulative prices and related
events, with routers explicitly trusted to read them. Trading would still reveal
price information; that stronger market-privacy model is outside this version.

### Lending and flash-loan arbitrage

Pool, receipt tokens, debt tokens and risk libraries form a reviewed trust group.
User position/health getters admit the user and explicitly approved protocol
callers; reserve totals, rates and risk parameters stay public initially.
Supply/borrow/repay event audiences include the relevant beneficiaries.

Supply uses an allowance and credits a beneficiary. Borrow computes across
collateral and debt contracts before transferring assets. Repayment can reduce
another user's debt without granting the payer unrestricted position access.
Liquidation code can inspect solvency through its protocol grants while the
liquidator's direct position query remains denied. Discovering liquidation targets
is still a product choice: expose eligibility, provide a trusted discovery service,
or allow probing and accept its leakage.

The flash-loan test borrows from Aave, swaps through two Uniswap venues, repays
principal plus premium, then pays profit to the trader. Its receiver callback
admits only code-bound Pool callers and checks the original initiator in Solidity.
The profit getter is owner-only. Insufficient profit or missing callback authority
rolls back both swaps and the loan. These grants allow protocol computation;
they do not grant an arbitrary callback access to another user's private data.

## Host integration still required

The intended deployment includes the TEE shard and RPC inside the trusted
boundary. This repository supplies an executor, not that deployment. In addition
to the executor rules, the host must implement:

- **Authentication and transport:** verify signed transactions/queries, bind the
  principal with replay protection, and encrypt requests and responses to the
  trusted boundary. An RPC `from` value is insufficient. Relayers, contract
  wallets and delegated event viewers require explicit authentication rules.
- **Policy lifecycle:** authenticate registration/update authority, persist
  versioned transaction-affecting policies in deterministic consensus state, and
  define when new snapshots take effect. Coordinate code/policy upgrades
  atomically; broader disclosure is a change to user trust. Factory deployment
  needs a constructor/registration design before enabling private creation.
  `PrivacyConfig::new` validates a supplied snapshot; it does not implement an
  on-chain registration endpoint or persistent registry.
- **Output coverage:** protect raw storage and revealing proofs, calldata,
  receipts, block payloads, log blooms, subscriptions, indexers, debug traces and
  bridge exports. Apply audience filtering before constructing exported results.
  Tracers receive private execution details and must stay inside the boundary.
  A permitted return value is not automatically checked for secret content.
- **Read/simulation semantics:** use authenticated static queries against committed
  state and discard query bookkeeping. Ordinary write-and-discard `eth_call`
  simulation could simulate payment or permission acquisition and retain the
  resulting secret. Gas estimation needs separate review; disallow untrusted
  state/code/block overrides on confidential state.
- **History and resources:** persist state and protected logs atomically, define
  retention and any current viewing entitlements, and bound execution/diagnostic
  resources. Event audiences are currently immutable snapshots; revocable viewing
  grants would require additional retrieval checks. Revocation cannot erase data
  already learned. Metadata and traffic-pattern hiding are separate requirements.

Unchanged bytecode does not imply unchanged tooling. Wallets need authenticated
reads; explorers/indexers need confidential history and event delivery; developers
need policy manifests, dependency review and upgrade tests. Remaining effort is
primarily host integration, output-path review and operational hardening.

## Tests

```sh
cargo test -p aurora-evm --features privacy --test privacy_e2e
cargo test -p aurora-evm --features privacy,tracing,create-fixed,with-serde
cargo check -p aurora-evm --no-default-features --features privacy
```

The integration tests deploy compiled Solidity bytecode, use real nested EVM
calls, apply resulting state, and check participant-filtered events. They cover:

- ERC-20 transfer to an unsigned recipient, approve/transferFrom, allowance
  enforcement, owner-only getters, and participant event access.
- Nested getter and delegatecall bypass attempts; principal spoofing; missing
  method/code bindings; static query enforcement despite incorrect policy tags.
- A constant-product swap with token pulls, pool self-balance reads, reserve
  updates, private participant events, and full rollback after a failed invariant.
- Supply, borrow, price drop, rejection of healthy liquidation, then successful
  liquidation through a code-bound lending-to-ledger grant. The liquidator cannot
  directly read the borrower's debt/health/collateral.
- Unknown-event rollback, caught child failure, parent-frame restoration, and
  revert payload scrubbing before a router can re-export it.

Test-first evidence: all six initial scenarios were run against an inert privacy
configuration and failed (unrestricted getters or ordinary-log leakage). Those
same scenarios passed after the executor hooks were implemented.

`privacy_upstream` additionally deploys unchanged published Uniswap V2 and Aave
V3 bytecode, real Aave proxies and linked libraries. It covers token/LP transfers,
liquidity add/remove, swaps and a malicious flash callback, nonzero WETH
withdrawals, Aave supply/borrow/repay/withdraw and liquidation, and flash-loan
arbitrage across two Uniswap venues. Proxy tests cover
storage isolation, authorized forwarding, wrong principals, direct implementation
calls, altered calldata, upgrades and mismatched runtime hashes.

The ABI matrices execute every function of the selected deployed interfaces with
two identities, assert admission/denial, and compare outputs when an unprotected
baseline succeeds. They **do not** establish successful economic execution for
every method: empty paths, unsigned permits and missing positions can revert
natively. Public methods remain callable by both identities; existing protocol
roles/allowances still apply. See the [upstream fixture guide](tests/fixtures/upstream/README.md) and its
per-method reports for exact scope, versions and known compatibility exclusions.
This is an executor E2E suite, not an HTTP/TEE deployment. The small-model fixtures
remain useful for adversarial rollback tests; their generation instructions are
in the [local fixture guide](tests/fixtures/privacy/README.md).
