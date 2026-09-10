# junibark-attest

On-chain spend attestation for charitable giving, on Solana.

## The problem

Donations already settle on-chain, so a donor can confirm their money arrived.
They cannot confirm what happened next.

Every giving platform shows spending as self-reported figures with an uploaded
receipt. A receipt in a database can be edited or replaced at any time, so the
number and the document behind it are both taken on trust. The trust gap in
charitable giving sits entirely after the money arrives.

## What this does

Lets a recipient attest each expense on-chain: the amount, the category, and
the SHA-256 hash of the receipt.

The receipt file itself stays off-chain in ordinary storage, which is cheap.
Its hash does not. That single move means the file cannot be swapped after the
fact: anyone can download the receipt, re-hash it in their browser, and compare
against the chain. Three things become independently checkable, with no trust
in the platform:

1. The money arrived (already true of any on-chain donation)
2. The receipt has not been altered since it was attested
3. Total attested spend against total received

This program moves no money and holds no funds. It is a record, not a vault.

## Deliberately absent

**No admin authority.** The platform cannot write, edit or revoke a recipient's
attestations. If it could, the guarantee would be worth nothing. Two tests in
the suite exist specifically to prove this.

**No escrow.** Holding donor funds against milestones is a different program
with its own custody and refund edge cases. Attestation is the novel half.

## Accounts

**`Cause`** — PDA, seeds `["cause", profile_id_hash]`

| Field | Type | Notes |
| --- | --- | --- |
| `authority` | `Pubkey` | The only key that may attest or revoke here |
| `profile_id_hash` | `[u8; 32]` | SHA-256 of the platform's record id |
| `total_attested_cents` | `u64` | Sum of live attestations |
| `attestation_count` | `u32` | Next index. Never decreases |

**`Attestation`** — PDA, seeds `["attest", cause, index_le]`

| Field | Type | Notes |
| --- | --- | --- |
| `amount_cents` | `u64` | Integer. No floats on-chain |
| `doc_hash` | `[u8; 32]` | SHA-256 of the receipt |
| `category` | `u8` | 0 VetCare, 1 Food, 2 Shelter, 3 Transport, 4 Other |
| `attested_at` | `i64` | From `Clock` |
| `revoked` | `bool` | Soft void, see below |

## Instructions

- `initialize_cause(profile_id_hash)` — one per verified recipient
- `attest_spend(amount_cents, doc_hash, category)` — signed by the authority
- `revoke_attestation(index)` — signed by the authority

### Why revocation exists

Recipients make honest bookkeeping mistakes: a receipt entered twice, a figure
typed wrong. Without a correction path the public ledger stays permanently
wrong, and the first error destroys the trust the program exists to create.

So a revoked attestation keeps its row and its original amount. Only the
running total falls, and `attestation_count` never decreases. The correction is
part of the record, not a deletion from it.

## Build and test

Requires Rust, the Solana CLI, and Anchor.

```bash
anchor build
anchor test --validator legacy
```

`--validator legacy` selects `solana-test-validator`. Anchor 1.x defaults to
`surfpool`, which is a separate install.

Nine tests cover the happy path, input validation, revocation, and two
authority checks that prove a non-owner cannot write to or revoke someone
else's record.

## Status

Early. Built during Colosseum Eternal, September 2026. Devnet only, not
audited, not for mainnet funds yet.

## License

MIT. Use it in any giving platform, not only ours.

## Deployment

| | |
| --- | --- |
| Cluster | devnet |
| Program id | `GLncvCsbvDHdT3844L9mhEYXAGZY1BY7mz3yBawmHFFy` |
| Explorer | https://explorer.solana.com/address/GLncvCsbvDHdT3844L9mhEYXAGZY1BY7mz3yBawmHFFy?cluster=devnet |
| First deployed | 2026-09-10, slot 496066076 |
| Upgrade authority | `624DbdhmBDF2653AgbMbyytu44eA4gFod3kEeTyvFLoN` (a devnet-only key) |

The JuniBark app talks to this program without the Anchor runtime: a small
web3.js client pinned to this repo's IDL builds the three instructions and
decodes the two accounts. A cause's receipt is hashed in the browser before
upload, the cause's verified wallet signs `attest_spend`, and the server reads
the `Attestation` PDA back before recording anything. Anyone can then download
the original receipt, hash it, and compare against the chain from the public
cause page.
