# Privacy EVM integration fixtures

`Contracts.sol` contains ordinary Solidity code with no privacy-specific checks,
opcodes, annotations, or storage layout changes. Host policies are declared in
`../../privacy_e2e.rs`. The same compiled bytecode runs with or without privacy
enforcement. Token `failBalance` deliberately produces a balance-bearing error
to test that revert data cannot be caught and exported by another contract.

The fixtures are intentionally small:

- `Token`: admin mint, ERC-20 transfers, approvals, balances, allowances, events.
- `Pair` / `Router`: one-direction constant-product swaps, no fee, optimistic
  output transfer followed by invariant validation; no LP mint/burn support.
- `DebtLedger` / `Lending`: private positions, 50% maximum borrowing LTV,
  liquidation above 75% LTV, 10% liquidation incentive, integer fixture prices.
  The admin-controlled price replaces an oracle; no interest or production risk
  controls are modeled.

These contracts are not audited and are unsuitable for handling real assets.

Regenerate creation bytecode and ABI files with:

```sh
python3 evm/tests/fixtures/privacy/compile.py
```

The script pins `solc@0.8.30` (commit `73712a01`), optimizer 200 runs, Shanghai EVM,
and disabled metadata bytecode hash. It uses standard JSON and fails on compiler
errors. Generation requires npm/network; ordinary Rust tests use the checked-in
`.bin` files and need neither npm nor Solidity tooling.

`Attacks.sol` adds proxy logic, an address-substituting proxy, an incompatible
upgrade, forwarding/delegatecall impostors, and a malicious Uniswap flash-swap
receiver. These deploy alongside real upstream proxies/protocols in
`../../privacy_upstream.rs`; see `../upstream/README.md` for that suite's scope.

`FlashArbitrage.sol` is an ordinary Aave simple-flash-loan receiver that trades
through two real Uniswap V2 routers and repays before paying profit. Its entry,
callback, profit getter and event visibility are configured entirely in Rust.
