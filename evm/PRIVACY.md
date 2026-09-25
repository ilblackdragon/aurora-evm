# Experimental method-level privacy

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

## Enforced rules

- Every admitted contract entry is bound to its address and actual bytecode
  hash. Every selector needs a rule, including public getters. Canonical ABI schemas validate static words and bounded dynamic bytes, arrays,
  and tuples before permissions; aliasing offsets, dirty padding, and suffixes fail.
- Permissions allow public calls, a principal matching an address argument, an
  immediate caller matching an argument, a fixed authenticated principal, or an exact contract-address/code-hash
  grant. The root principal is inherited independently of `msg.sender`.
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
- Private event audiences can select indexed/non-indexed addresses, the root principal, or
  the immediate caller. Zero-address placeholders are not recipients. Unknown
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
withdrawals, Aave supply/borrow/repay/withdraw and liquidation. Proxy tests cover
storage isolation, authorized forwarding, wrong principals, direct implementation
calls, altered calldata, upgrades and mismatched runtime hashes.

The ABI matrices execute every function of the selected deployed interfaces with
two identities, assert admission/denial, and compare outputs when an unprotected
baseline succeeds. They **do not** establish successful economic execution for
every method: empty paths, unsigned permits and missing positions can revert
natively. Public methods remain callable by both identities; existing protocol
roles/allowances still apply. See `tests/fixtures/upstream/README.md` and its
per-method reports for exact scope, versions and known compatibility exclusions.
This is an executor E2E suite, not an HTTP/TEE deployment. The small-model fixtures
remain useful for adversarial rollback tests; their generation instructions are
in `tests/fixtures/privacy/README.md`.
