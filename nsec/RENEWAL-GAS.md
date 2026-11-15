# Renewal gas, measured

**Date:** 14 November 2026. **Why:** issue #2's expiry term is bounded below by renewal gas, and that
number did not exist. The issue names the measurement as the first thing to run, because it is the half
of the bound that waits on no document.

**The absence figure does not transfer.** `README.md` gives about 281,000 gas for an NSEC absence
proof. That is a root DNSKEY set plus one root NSEC set. A presence proof walks root DNSKEY, then the
TLD's DS, then the TLD's DNSKEY, then the TXT set. Different chain, different cost.

## Method

Real signatures, no fabrication. `SyntheticChainBuilder.sol` cannot answer this question, because it
signs with `DummyAlgorithm`, which does no crypto and therefore measures parsing rather than
verification.

The chain is live and built by `tools/mkpresence.py` from a validating resolver. A validating
resolver sets the `ad` flag on `_ens.estmcmxci.co`, so the chain is good end to end before any contract
sees it.

Measured against the **deployed mainnet oracle** `0x668ad4467129d49ECbe6274d95197797C0E262AA` on a fork,
by `test/PresenceGas.t.sol`, as `gasleft()` deltas around the external call. Every prefix of the chain is
measured, which isolates each level.

```
forge test --match-path test/PresenceGas.t.sol --fork-url <mainnet> --evm-version osaka -vv
```

## Results

| sets | cumulative | this level | the level |
| --- | --- | --- | --- |
| 1 | 181,996 | 181,996 | root DNSKEY, algorithm 8, 3 keys |
| 2 | 269,903 | 87,907 | `co` DS, signed by root, algorithm 8 |
| 3 | 442,233 | 172,330 | `co` DNSKEY, algorithm 8, 4 keys |
| 4 | 513,240 | 71,007 | `estmcmxci.co` DS, signed by `co`, algorithm 8 |
| 5 | 585,342 | 72,102 | `estmcmxci.co` DNSKEY, algorithm 13, 2 keys |
| 6 | 639,393 | 54,051 | the claim TXT set, algorithm 13, 3 records |

The full chain verifies and returns 328 bytes of records at inception 1794621544.

## The TLD figure, derived

A TLD presence proof is four sets. **Sets 1 to 3 are already exactly that chain's first three**, because
`co` is a real TLD: root DNSKEY, `co` DS, `co` DNSKEY, which is **442,233 gas**.

What remains is the TXT set signed by the TLD's own key.

- **A TLD signing with algorithm 13**: the measured TXT set is 54,051, so the proof is about
  **396,000 gas** (root DNSKEY 181,996, DS 87,907, an algorithm 13 DNSKEY set at about 72,000, TXT
  54,051).
- **A TLD signing with algorithm 8**: the TXT set costs more, because RSA runs through `modexp`. The two
  measured algorithm 8 single-record sets bracket it at 71,007 and 87,907, and a three-record set parses
  more, so about 90,000. That puts the proof at about **530,000 gas**.

**So a renewal costs roughly 400,000 to 530,000 gas, and which end depends on the TLD's own algorithm.**

## What this decides

**Gas does not bound the expiry term from below.** At the base fee observed while measuring, 0.507 gwei,
530,000 gas is about 0.00027 ETH. Even at 10 gwei it is about 0.0053 ETH. A 180 day term means two
renewals a year, so about 0.0005 to 0.011 ETH a year for an operator who pays ICANN at least 25,000 USD
a year in registry fees.

The issue's gas bullet frames this as renewal frequency times about 1,165 delegated gTLDs. That product
is network load rather than a bill, because each operator pays for its own renewal. As a bill to any one
party it does not exist.

**The term is therefore set by operator liveness**, meaning how often an operator can be asked to send a
transaction before one is missed, and by how long an ENS record may be stale. It is not set by cost.

## Two findings that are not about the term

**EIP-7883 made algorithm 8 more expensive.** The same four-set prefix measures 420,652 gas on a
pre-Osaka EVM and 513,240 on Osaka, which is 22 percent more. Osaka reprices `modexp`, which is RSA's
inner loop. DNSSEC verification in ENS got more expensive at that fork, and algorithm 13 is now the cheap
path by a wider margin than before.

**A harness trap worth recording.** Foundry's forked EVM does not provide the EIP-7951 P-256 precompile
at `0x100` unless `--evm-version osaka` is given. Without it the `staticcall` hits an empty account,
succeeds, returns nothing, and `P256Precompile.verify` reads a zero word and reports false. The oracle
then reverts `NoMatchingProof`, which reads as a bad fixture rather than a missing precompile. Mainnet
does have the precompile: a direct call returns 1 for this chain's signature. **An algorithm 13 proof
measured without `--evm-version osaka` will look broken and is not.**

## Reproducing it

```
python3 tools/mkpresence.py                 # writes tools/presence-chain.json from live DNS
python3 - <<'EOF'                           # regenerate the inlined fixture in the test
EOF
forge test --match-path test/PresenceGas.t.sol --fork-url <mainnet> --evm-version osaka -vv
```

`tools/mkpresence.py` builds the chain and `tools/mkfixture.py` holds the SignedSet encoder it reuses,
which is the same encoder the absence fixtures in `test/RootFixtures.sol` were built with. The test
carries the chain inlined as hex, because `foundry.toml` grants no filesystem permissions.

## The fixture expires

The TXT RRSIG expires **16 November 2026 at 03:59 UTC**. After that this harness fails for a reason that
looks exactly like a defect. Re-run `tools/mkpresence.py` first.
