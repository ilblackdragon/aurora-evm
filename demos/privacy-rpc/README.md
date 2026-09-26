# Two-user, two-app privacy RPC demo

A local, runnable vertical slice over the actual Aurora EVM privacy executor:

- Alice and Bob each have a private wallet RPC URL and a separate signing key.
- Payments and Rewards run on distinct browser origins and use different ERC-20s.
- Wallet URLs mint narrow, expiring, read-only app URLs. An app URL identifies the
  user, allowed contracts, browser origin and earliest accessible event block.
- Read scopes apply to nested EVM calls, not just the outer HTTP request.
- Transfers require canonical, chain-bound EIP-155 signed transactions and the
  correct sender/nonce. A URL alone never authorizes spending.
- Protected logs are indexed with state and receipts, filtered per participant
  and app, and delivered through history requests and live WebSocket subscriptions.

This is a loopback-only demo, **not a TEE or production RPC server**. Accounts use
publicly known fixture keys; data lives in memory and resets on restart. Do not
fund these accounts. HTTPS, attestation, durable consensus/storage, key recovery,
production rate limiting and signed session provisioning remain integration work.

## Run

Requires Rust (the repository toolchain), Node 22+, and npm. Dependencies are
locked independently to keep HTTP/browser tooling out of the EVM/no_std workspace.

```sh
cd demos/privacy-rpc
npm ci
cargo run -- --credentials /tmp/aurora-demo.credentials.json
```

The credentials file must not already exist. It is created with mode `0600` on
Unix and contains both users' **test** signing keys and wallet URLs. Secrets are
not printed, embedded in web pages, or placed in browser navigation URLs.

Open the wallet at `http://127.0.0.1:9000`. Copy Alice's or Bob's wallet URL from the
credentials file into the wallet page. Create an app URL, open the corresponding
app, and paste it there. Use separate browser profiles/contexts for the two users.
The wallet page can sign and send transfers after you supply that user's fixture
private key. Tokens use small raw fixture units; the UI displays those units.

Payments runs at port 9001; Rewards at 9002. Set `PORT`, `APP_A_PORT`, and
`APP_B_PORT` to override these (zero allocates an ephemeral port for tests).
No RPC URL or key is saved in localStorage, a cookie, or a URL fragment. Closing
an app clears local state; revoking its URL in the wallet also closes its live feed.

## Run real browser tests

```sh
cd demos/privacy-rpc
npm ci
npx playwright install --with-deps chromium
npm test
```

Tests can alternatively use `CHROME_BIN` or an installed `/usr/bin/google-chrome`.
They launch the Rust HTTP servers, deploy compiled Solidity into the EVM, create
four isolated browser contexts, and exercise the same JS provider as the UI.
No external chain, npm/solc compilation of fixtures, or fake RPC backend is used.
Browser tracing/video/screenshots are disabled to avoid capturing bearer credentials.

Coverage includes:

1. Both users in both apps; wallet-signed transfers and live balances/events;
   direct and nested out-of-scope reads; another user's getter and spoofed `from`;
   browser-origin rejection; read-only write rejection; signature/chain/nonce
   checks; JSON-RPC batch identity isolation; static-query nonce preservation.
2. Offline recipient discovery; two recipients in one transaction; each log's
   audience and receipt projection; filtering before pagination; foreign cursors;
   history bounds; blocked raw storage/proofs/traces; complete state/log rollback
   when the second transfer in a batch fails.
3. Expiry and revocation while idle; wallet URL rotation invalidating children;
   simulated reorgs removing live events, restoring balances and invalidating
   receipts/cursors.

The test process alone enables `--test-controls`, which writes an operator URL
into the credentials file. POSTing to it rolls back the latest simulated block.
Without that flag the operator endpoint is disabled. It is not a user capability.

## RPC profile

POST JSON-RPC to `/rpc/<256-bit random secret>`. Only the secret's hash is stored
in the session registry. Public `/rpc` exposes only `eth_chainId`. No account can
be selected by editing a username or address in the URL.

| Method | Demo behavior |
| --- | --- |
| `eth_accounts` | The URL's authenticated account |
| `eth_call` | Scoped static call at `latest`; optional `from` must match identity; no state overrides |
| `eth_getTransactionCount` | Wallet URL only; own account, latest/pending |
| `eth_sendRawTransaction` | Wallet URL plus matching signature; EIP-155 legacy, zero value/gas price, bounded gas; no CREATE |
| `eth_estimateGas` | Fixed conservative gas bound for allowed targets; **no simulation or success prediction** |
| `eth_getLogs` | Authorized logs; address/topics/block filters; inaccessible addresses are denied |
| `aurora_getEvents` | Filtered pagination with opaque session/filter/chain-epoch-bound cursors |
| `eth_getTransactionReceipt` | Explicit `privacyView` projection with authorized logs; no calldata, bloom or canonical receipt proof |
| `aurora_createReadSession` | Wallet-only app grant; explicit origin/contracts/TTL, optional `historyFrom` |
| `aurora_revokeSession` | Wallet-only revocation of its own child URL |
| `aurora_rotateWalletUrl` | Replaces the wallet credential and invalidates its children |
| WebSocket `/rpc/<secret>/ws` | One `eth_subscribe` logs filter per connection; expiry/revocation checks and reorg `removed` messages |

Unknown methods fail closed. In particular, there is no full-transaction endpoint,
raw storage export, trace endpoint, arbitrary historical execution or state override.
A transaction hash does not authorize access. Global block height and canonical
log indices are visible metadata; this demo does not hide traffic or event gaps.

`eth_getLogs` and receipts apply participant **and** session restrictions, even for
the transaction sender. The index is an in-memory scan with bounded demo history;
a production implementation needs durable indexes. Mutations and index updates
share a mutex. Reorg simulation restores EVM state and index together. The client
subscribes before historical catch-up and applies concurrent additions/removals
onto that snapshot to avoid a history/subscription gap. A lagged subscription is
closed rather than silently losing updates; reconnect and rescan authorized history.

## What a private RPC URL does and does not prove

A secret URL is a bearer capability. Knowledge of it authenticates its holder as
that account **within its scope**. Guessing a URL containing only a public address
would not authenticate anything. Origin checks/CORS stop use from another browser
origin, but do not stop a non-browser holder forging `Origin`; a test explicitly
confirms this limitation. For stronger anti-theft guarantees, bind a URL/session
to a client public key and require per-request proof of possession.

Never put a wallet URL in a dapp's source, a shared RPC config, query string,
analytics, crash report, access log, or public explorer link. Reverse proxies must
redact the credential path. Production endpoints need HTTPS terminating inside the
trusted boundary or encryption to an attested service, no shared response caches,
short app-session lifetimes, rotation and authenticated reissuance/recovery.
This demo has no request logger and sends private responses with `no-store`.

App isolation in this demo is by token contract. Two apps granted the same token
can read the same owner-authorized token data; per-counterparty event restrictions
or app-specific projections require additional scope rules.

This does not make stock wallet portfolio queries automatically compatible.
The included wallet is a local signing fixture; an injected-wallet integration
would use that wallet for transaction signing and this scoped provider for reads.
Smart accounts, delegated signing, typed transactions, persistent sessions,
policy upgrades, fine-grained selector grants and production simulation are future work.
