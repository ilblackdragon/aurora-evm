# Real protocol privacy fixtures

These tests execute published bytecode, with the original Solidity sources
vendored alongside it. No protocol source or bytecode is patched. Runtime Aave
library addresses are linked using the publisher's link references. Using the
published Uniswap Pair artifact preserves the init-code hash expected by Router02.

| Package | Pinned release | Upstream |
| --- | --- | --- |
| `@uniswap/v2-core` | `1.0.1` | https://github.com/Uniswap/v2-core |
| `@uniswap/v2-periphery` | `1.1.0-beta.0` | https://github.com/Uniswap/v2-periphery |
| `@aave/core-v3` | `1.19.3` | https://github.com/aave/aave-v3-core |

`packages.json` pins npm archive integrity. `SHA256SUMS.json` pins every copied
source, package/license file, and normalized artifact. Preserve the upstream
licenses/SPDX headers when redistributing. Re-fetch and verify using Python 3.12+:

```sh
python3 evm/tests/fixtures/upstream/vendor.py
```

Ordinary tests require neither npm, solc, network downloads, nor a fork provider:

```sh
cargo test -p aurora-evm --features privacy --test privacy_upstream
AURORA_COVERAGE_DIR="$PWD/evm/tests/fixtures/upstream/coverage" \
  cargo test -p aurora-evm --features privacy --test privacy_upstream
```

The second command refreshes the checked-in per-method JSON reports. Fixture
policies in `../../common/upstream.rs` classify each selected ABI function and
event. They are explicit experimental disclosure choices, not production policy
recommendations; the name-based policy generator must not be used to approve
arbitrary newly deployed contracts.

## Exact coverage

| Deployed interface | Methods |
| --- | ---: |
| UniswapV2Factory | 8 |
| UniswapV2Pair (including LP ERC-20) | 27 |
| UniswapV2Router02 | 24 |
| WETH9 | 11 |
| Pool | 46 |
| PoolConfigurator | 29 |
| PoolAddressesProvider | 22 |
| ACLManager | 33 |
| AaveProtocolDataProvider | 19 |
| AToken | 34 |
| StableDebtToken | 33 |
| VariableDebtToken | 30 |
| MintableERC20 | 18 |
| ZeroReserveInterestRateStrategy | 14 |
| PriceOracle | 4 |
| InitializableImmutableAdminUpgradeabilityProxy | 5 |

352 methods have paired identity tests in the reports; five proxy administration
methods have a separate paired admin/outsider test (714 identity cases total).
All 32 user-restricted methods deny the wrong principal. Public methods admit
both principals and retain the protocol's original role/allowance checks.
384 report cases succeed in real bytecode and match unprotected return values.
Other cases check the privacy gate but revert on native protocol preconditions.
No business-success claim is made for those cases. The matrix fails if a baseline
success becomes a privacy failure. Interface enumeration prevents missing selectors.

Additional successful lifecycle tests cover:

- Real Router/Pair add/remove liquidity, token swaps, LP transfers, private balance
  reads and events; actual WETH deposit/withdraw with nonzero native value.
- Actual Uniswap flash-swap callback attempting to read another LP's balance;
  it catches the denial with empty return data, repays, and completes the swap.
- An Aave `flashLoanSimple` borrowing 100 CASH at a configured 9 bps premium,
  buying collateral on one real V2 venue and selling it on another. The receiver
  starts without funds, repays principal plus premium, and transfers the exact
  independently calculated profit to its owner. Both swaps and the loan roll back
  for insufficient profit or missing callback authorization. Forged callbacks,
  wrong initiators, and outsiders reading profits/balances are rejected.
- Actual Aave Pool/Configurator/AToken/debt-token proxies and linked libraries,
  two reserves, supply/borrow/repay/withdraw, failed healthy liquidation, price
  drop and successful liquidation; participant-filtered logs and private positions.
- Shared implementation with isolated proxy storage, proxy-owned token balances,
  direct implementation denial, approved forwarding, forged address suffixes,
  arbitrary delegation, rewritten proxy arguments, wrong code hashes, and upgrades
  that cannot reuse stale policy bindings. Existing model tests cover reverted
  log journaling, revert-data exfiltration, spoofed root identities and static writes.

## Deliberate limitations

This selects Uniswap **V2** and Aave **V3 core**, not V3/V4 Uniswap or every Aave
extension. Vendored interfaces, abstract contracts, libraries and unused mocks
are not all standalone test subjects; linked libraries execute through real Pool
calls. Reserve setup runs in trusted bootstrap before enforcement. Underlying
Uniswap tokens are small local ERC-20 fixtures; Aave uses upstream MintableERC20,
PriceOracle and ZeroReserveInterestRateStrategy to make liquidation deterministic.
No mainnet snapshot, interest accrual or oracle security is simulated.

ABI admission coverage is not exhaustive business/branch coverage. Permit
signature success, ETH Router fallback routes, factory creation while private,
all flashloan modes, stable-rate borrowing and all governance transitions are not
validated successful lifecycles. Creation, precompiles (including ecrecover), and
contract fallback/receive entry remain unsupported and fail closed. Noncanonical
ABI encodings also fail even if Solidity would accept them.

The test policy explicitly trusts the deployed Aave proxy/implementation/library
domain to read positions for solvency and liquidation. It is intentionally broader
than per-operation capabilities. This grants reviewed protocol code access to
private data, not the liquidator or an arbitrary forwarding contract. Pool reserve
updates remain public and therefore disclose aggregate flows. Successful permitted
calls, gas and other inference channels remain visible. This is an in-memory EVM
suite; authenticated RPC, TEE deployment and confidential storage are host work.
