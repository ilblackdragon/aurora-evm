# Private Aurora EVM with unchanged contract bytecode

Discussion draft for Aurora architecture · 25 September 2026

## Proposal in one page

**Run existing EVM contracts inside NEAR’s TEE private shard, with RPC inside the trusted boundary. Add an Aurora-managed policy for method access and output visibility. Keep contract bytecode unchanged.**

The target is user-to-user and application-to-application confidentiality. Contracts can compute over **all their own state**, including multiple users’ balances. Users choose whether to trust the published code, its dependencies, and its privacy policy.

**We do not need field-level visibility for the initial design.** Hide all raw storage from external users. Expose public or user-specific information through existing getters, with policies checked before execution. This avoids storage-layout annotations, mapping-key recovery, and changes to `SLOAD`/`SSTORE`.

Conceptual host API:

```text
Aurora.registerPrivacyPolicy(evm_address, code_binding, policy)
```

This is a proposed API, not an existing Aurora method. Its policy defines:

- **Methods:** public, authenticated-user/argument match, or approved contract caller.
- **Events:** public or visible to designated participants.
- **External results:** permitted return/error data and transaction metadata.
- **Code binding:** approved implementation versions and policy-update authority.

An authenticated execution principal propagates through nested calls, separately from normal `msg.sender`. Calling authorizes the chain to use that principal’s data through permitted methods. Contracts can also query their own account data; protocol dependencies can receive explicit access.

Enforce method rules on **every external EVM call**, not just RPC entry. Apply output rules across RPC, history, subscriptions, and indexers. Encrypt requests and responses to/from the trusted boundary. Raw storage, proofs revealing storage, and debug traces are unavailable to ordinary users.

**Guarantee:** users cannot directly query another user’s protected interfaces. **Trust boundary:** permitted contract code can disclose information it learns; this is not automatic information-flow confinement. Public source and a code-bound policy make that trust reviewable.

First prototype: ERC-20 with private balances, private transfer events, ordinary transfers and allowances, followed by a Uniswap V2-style swap.

---

## Design details and tradeoffs

### Why methods are enough—and where they are not

An existing `balanceOf(account)` getter is a natural disclosure boundary. Aurora checks who may invoke it; the token’s internal balance reads remain unrestricted. Public values such as `totalSupply()` need no storage visibility declaration.

Method policies also cover computed results such as account health, which may not correspond to one storage field. Unknown selectors and fallback entry points default to denied until explicitly classified. The manifest must describe exact ABI signatures and validated argument decoding.

However, **method access alone is not a complete privacy policy**. Existing bytecode can reveal data in events, errors, other methods, and observable success/failure. Each supported implementation needs an interface review. Open code is reviewable, not automatically safe.

Field metadata is only needed later if we want selective raw-state export, generic storage inspection, or runtime tracking of confidential data. None is required for the proposed getter-based model.

### Execution identity and application trust

Keep three identities distinct: authenticated user, immediate EVM caller, and executing code/storage context. A contract must not be able to overwrite the authenticated principal. Signed queries cannot accept an arbitrary RPC `from` as identity. Relayers and smart accounts require explicit authentication rules.

Inherited user authority is intentionally broad: a downstream dependency could query other contracts’ data for that user. An optional transaction scope can narrow it to specified contracts/methods without introducing field policies.

Approved protocol callers are trusted with returned data. Their own public methods must not provide unrestricted forwarding of private results. Bind these grants to reviewed implementations, not just upgradeable addresses. Delegated execution must be covered by the code binding; arbitrary `DELEGATECALL` targets cannot silently inherit trusted status.

### Policy lifecycle and enforcement

- Authenticate registration and updates; only the designated authority may change policy.
- Activate code and policy together. Cover factory-created contracts and proxies explicitly.
- Make transaction-affecting policies deterministic consensus state.
- Version policies and code bindings; privacy-expanding upgrades are explicit changes to user trust.
- Cover top-level calls, nested calls, precompile paths, and direct host entry points.
- Apply current access entitlement to historical data too; revocation cannot erase information already learned.

### Queries, errors, and metadata

Use authenticated, runtime-enforced static queries against committed state for the first version. Ordinary `eth_call` simulation can execute writes and discard them; it must not let callers simulate payment or permission acquisition and keep the resulting secret. Gas estimation needs a separately reviewed policy. Disable user-supplied state/code/block overrides on confidential state.

Treat detailed errors as outputs. Some token implementations include an account’s balance in insufficient-balance errors. Suppressing such data may change observable error behavior. Success/failure and gas can still reveal information; a party authorized to attempt spending learns something about spendability.

Filtering events alone is insufficient: transaction calldata, receipts, block payloads, log blooms, traces, and public-chain bridge outputs must respect the privacy model. Metadata hiding is a separate, explicit scope; a TEE does not automatically hide traffic patterns.

### Compatibility and effort

Keep bytecode, accounting, and ordinary ABI calls. Change confidential-query authentication, event/history delivery, and possibly error behavior. Standard wallets, explorers, and indexers need adapters; unchanged bytecode does not mean unchanged tooling.

With a working TEE shard and RPC stack, a narrow ERC-20 prototype is plausibly **6–10 weeks**; hardening a supported application set and SDK is a **multi-month project**. These are preliminary planning estimates, not a code audit or delivery commitment. Removing field enforcement reduces VM work; output coverage, proxy policies, and simulation remain substantial.

---

## Example 1: ERC-20

Suggested method policy:

| Method | Admission rule |
|---|---|
| `name`, `symbol`, `decimals`, `totalSupply` | Public |
| `balanceOf(account)` | Authenticated principal is `account`, or immediate caller is `account` |
| `allowance(owner, spender)` | Principal or immediate caller matches owner or spender |
| `transfer`, `approve`, `transferFrom` | Admit; existing token code enforces mutation authority |

“Public” permits invocation; it does not grant raw-state access. These rules apply to nested getter calls too. Token-internal balance/allowance accesses are unrestricted.

### Transfer and receipt

```text
Alice → Token.transfer(Bob, 10)
          read Alice and Bob balances
          debit Alice; credit Bob
          emit Transfer(Alice, Bob, 10)
          return success
```

Bob needs no signature, prior session, or claim transaction. Standard ERC-20 does not call the recipient. Alice learns the amount and success, not Bob’s total balance.

The transfer event is retrievable by Alice and Bob through authenticated RPC. Keep it in the confidential service until Bob connects; do not require a previously registered encryption key. Bob can query his balance and discover incoming transfers. Other users cannot retrieve the event or recover it through full receipts/block data.

### Allowance and `transferFrom`

```text
Alice → Token.approve(Router, 100)
Alice → Router → Token.transferFrom(Alice, Pool, 20)
```

The token sees `Router` as `msg.sender` and checks its existing allowance. It may update the pool’s balance without the pool’s signature. The router need not read Alice’s total balance to spend 20.

A different actor can trigger an approved spender if that spender’s own code permits it. Alice’s live privacy authorization is unnecessary for the debit: the allowance provides spending authority. It does not automatically grant balance-getter access.

Suggested audiences: `Approval` → owner/spender; `Transfer` → sender/recipient and the immediate spender for delegated transfers. The latter comes from execution context, since standard `Transfer` events do not include a spender field. Contract audiences get permitted programmatic access; they do not imply a developer has an EOA right to read everything.

Broad allowances plus spending simulations can expose balance bounds. Detailed errors may expose exact balances. These are disclosure properties of the allowed interface, not failures to label storage.

## Example 2: Uniswap V2-style pool

Initial policy: public token addresses, reserves, cumulative prices, and fee settings; private LP balances/allowances using the ERC-20 rules. Explicit participant audiences for swap/mint/burn events.

```text
Alice → Router
          Pair.getReserves()
          TokenA.transferFrom(Alice, Pair, input)
          Pair.swap(output, recipient, ...)
            TokenB.transfer(recipient, output)
            TokenA.balanceOf(Pair)
            TokenB.balanceOf(Pair)
            update reserves
```

The pair can read its token balances because it is their owner. The recipient can be Bob without his authorization. Event policy must recognize the initiating user and designated recipient; the pair’s immediate caller is often a router.

**Public reserves expose net flows and can reveal isolated trade amounts.** Hiding swap events does not prevent that. This version offers protected user balances and restricted activity access, not strong trade-amount secrecy.

Hiding reserves requires restricting getters, token-balance access, price accumulators, quotes, and associated events consistently. Routers then become trusted readers, and trading still exposes price information. That is a separate, more demanding market-privacy mode.

## Example 3: Lending

A pool, receipt tokens, debt tokens, and risk logic form a reviewed protocol trust group. Give its required methods explicit caller grants.

| Interface/data | Suggested visibility |
|---|---|
| User collateral and debt getters | User plus approved protocol callers |
| Account-health getter | User plus approved risk/liquidation callers |
| Reserve totals, rates, risk parameters | Public initially |
| Supply/borrow/repay events | Defined participants, including on-behalf-of accounts |

Supply transfers assets using the existing allowance and credits a beneficiary. Borrow reads collateral/debt across protocol contracts, records debt, and transfers assets. Repayment can reduce another user’s debt without granting the payer unrestricted access to that user’s position.

Liquidation needs an explicit disclosure choice: expose eligible positions, provide a trusted discovery service, or permit probing and accept the resulting leakage. Public aggregate reserve changes can also reveal isolated user operations.

## Rust policy and executable reference implementation

The companion **[privacy_policy.rs](https://gist.github.com/ilblackdragon/50c97275b2999d6e583c43567819192a#file-privacy_policy-rs)** implements the policy evaluator, ERC-20 manifest, event classification, rollback journal, and RPC audience check. It is dependency-free Rust with executable tests. **It is not yet wired into Aurora or a production security implementation.** Contract bytecode and storage instructions remain unchanged.

### Policy types

The reference uses fixed byte arrays for addresses/hashes and ordered maps for deterministic representation. A production registry would add canonical serialization and authenticated registration. Its essential structure is:

```rust
pub struct Policy {
    pub address: Address,
    pub code_hash: Hash,
    pub version: u64,
    pub methods: BTreeMap<Selector, Method>,
    pub events: BTreeMap<Hash, EventRule>,
}

pub struct Method {
    pub args: Vec<Arg>,             // Address or Uint256; fixed ABI words.
    pub any_of: Vec<Permit>,        // Any matching rule permits entry.
    pub query: bool,                // Allowed in static query mode.
}

pub enum Permit {
    Public,
    PrincipalArg(usize),            // Authenticated principal == address argument.
    CallerArg(usize),               // Immediate caller == address argument.
    TrustedCaller { address: Address, code_hash: Hash },
}
```

For example, the ERC-20 `balanceOf(address)` selector `0x70a08231` has one `Address` argument and `any_of = [PrincipalArg(0), CallerArg(0)]`. `transferFrom` is admitted without granting balance-query access; the token still checks allowance. `Public` means no additional privacy restriction, not permission to mutate state anonymously: transaction authentication and normal EVM authorization still apply.

Event rules specify exact topic/data lengths, which topics encode addresses, and an audience of `Public` or `Participants`. Participant sources are `TopicAddress(index)`, `Principal`, and `Caller`. Topic zero is the event signature. The ERC-20 builder assigns `Transfer` to topics 1/2 plus the immediate caller, and `Approval` to topics 1/2. Zero-address mint/burn placeholders are excluded.

### Actual call check

`admit_call(policy, context, calldata)` returns an admitted `Frame` or a generic `Denied`. It:

1. Requires a policy matching the target address and host-computed executing code hash.
2. Rejects unsupported delegation modes and mismatched code/storage addresses.
3. Looks up the selector; unknown selectors, empty calldata, and malformed inputs fail closed.
4. Validates exact fixed-word calldata length and canonical address encoding before evaluating rules.
5. Requires actual static execution and a query-enabled method for query mode.
6. Evaluates the permitted principal, immediate caller, or address/code-hash grant.
7. Captures the policy version, authenticated principal, caller, and static flag in the admitted frame.

The host constructs the context. Contracts and RPC clients cannot assert the principal or caller code hash. Anonymous queries have **no** authenticated caller identity; address zero is not treated as an authenticated user. Every child inherits root principal/query mode, while its immediate caller and executing code are derived anew by the executor.

### Actual event check and delivery

`classify_log(frame, emitter, topics, data)` rejects logs in static mode, a mismatched emitter, unregistered events, and malformed event encodings. It resolves participant addresses and returns a `ProtectedLog` containing the original log, policy version, and audience. An empty private audience remains private; it never falls back to public.

`LogJournal::emit` stores the log and its label together. Child success merges both into its parent; child failure discards both; a later parent failure also discards successful child logs. Only root success produces committed logs for confidential storage. Do not publish them when `LOG` executes.

`can_export(log, verified_viewer)` permits public logs or a verified participant. A contract address in an audience does not authorize its developer to impersonate it at RPC. Contract viewing/delegation needs a separate authenticated path. The sample uses immutable per-event audiences; if the product adds revocable viewing grants, retrieval must additionally enforce their current validity.

### Wiring into Aurora

These are integration instructions, not an applied executor patch. Source references use inspected Aurora EVM commit `90197c9ce48cfe54f194e872cc712b5a2762ff35`.

| Integration point | Required change |
|---|---|
| `StackExecutor::call_inner` | Resolve actual code and construct trusted context; call `admit_call` before callee execution, value transfer, or precompile dispatch. Return an empty-data EVM failure on denial. Define and meter deterministic policy-check gas. |
| Runtime call dispatch / `Handler::call` | Carry explicit call kind. Current arguments do not safely identify every delegation case. Apply the same policy path to precompile subcalls and host entry points. |
| `TaggedRuntime` and active execution frame | Attach the admitted `Frame`; restore the parent on completion. A single executor-global principal/caller variable is insufficient under nesting/reentrancy. |
| `Handler::log` | Use the active admitted frame and call `LogJournal::emit`; do not also append an unlabelled public copy through the existing `state.log` path. |
| Substate enter/commit/revert | Mirror the log journal exactly, including precompile early exits, failed transfers, and fatal errors. Production should incorporate labels into the existing state journal to avoid two journals drifting apart. |
| Receipt/indexer/RPC export | Persist protected logs inside the trusted boundary; apply `can_export` before returning content or constructing visible blooms/subscriptions. Do not bypass this through full receipts or block payloads. |

For example, the call hook logically performs the following. This is **integration pseudocode**; `Frame` storage and context plumbing must be added to the executor:

```rust,ignore
let frame = match admit_call(registry.lookup(target), &trusted_context, &input) {
    Ok(frame) => frame,
    Err(_) => return Capture::Exit((
        ExitReason::Revert(ExitRevert::Reverted), Vec::new()
    )),
};
// Attach frame to the callee, journal its logs, then execute existing bytecode.
```

Tracing callbacks currently receive call inputs and storage values. They must remain disabled or confined inside the trusted boundary; a call guard does not protect an external tracer.

### Deliberate limits of this reference

- Supports direct contracts and fixed-size method/event encodings. Dynamic ABI arguments, fallback/receive rules, and anonymous events need explicit extensions.
- Rejects `DELEGATECALL`, `CALLCODE`, and resolved EIP-7702 targets with differing code/storage addresses. Proxy support requires a reviewed binding for each storage-owner/code pair and its allowed transitions, not simply removing these checks.
- Constructors, factories, EOAs, system calls, and precompiles need explicit host rules; do not treat missing policy as permission. Deployment needs provisional constructor/event rules before runtime code exists.
- Registration must authenticate authority, bind actual code, validate referenced ABI argument/topic types, reject conflicting entries, bound policy sizes, and assign deterministic costs. The evaluator assumes that registry layer; it does not implement it.
- The sample snapshots an admitted frame's event policy. A production implementation should use a transaction-wide policy snapshot and make updates effective at a defined subsequent boundary.
- Return/error filtering, transaction authentication, encryption, fee accounting, host persistence, and anti-replay are outside this evaluator. In particular, it does not fix balance-bearing ERC-20 errors merely by protecting events.

Run the reference tests with:

```sh
rustc --edition=2021 --test privacy_policy.rs -o /tmp/privacy-policy-tests
/tmp/privacy-policy-tests
```

The tests cover nested user access, foreign-user denial, contract self-access, malformed ABI, code changes/delegation denial, anonymous queries, static-mode requirements, private event audiences, delegated spending, trusted-code grants, and child/parent rollback. They exercise the evaluator, **not** a complete Aurora integration.

## Questions for architecture review

1. Can Aurora enforce the same policy on every call path and every data-export path?
2. Is inherited user authority acceptable initially, or should requests scope permitted contracts/methods from day one?
3. How should proxy/factory deployments bind code, policy, and update authority atomically?
4. Which metadata and simulation outputs will the first version deliberately expose?

## References

- [ERC-20 specification](https://eips.ethereum.org/EIPS/eip-20)
- [OpenZeppelin ERC-20 implementation](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/ERC20.sol)
- [Uniswap V2 pair implementation](https://github.com/Uniswap/v2-core/blob/master/contracts/UniswapV2Pair.sol)
- [Aave Pool interfaces](https://aave.com/docs/aave-v3/smart-contracts/pool)
- [Sapphire authenticated queries](https://docs.oasis.io/build/sapphire/develop/authentication/)
- [Sapphire simulation/security considerations](https://docs.oasis.io/build/sapphire/develop/security/)

Policy syntax and Aurora registration API above are proposals. The cited implementations illustrate interface behavior; adoption requires reviewing and pinning the exact deployed versions.
