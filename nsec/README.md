# The root absence predicate

A contract that reads a root-signed NSEC record and reports whether a top-level domain has no NS
delegation in the DNS root. It is the release side of the TLD Oracle, and the Oracle's admission side
is described in the repository README.

*12 November 2026.*

## What is here

| Path | What it is |
| --- | --- |
| `src/RootAbsencePredicate.sol` | the predicate, and the calling convention it forces |
| `src/NSECUtils.sol` | the wrap-aware comparator and the RFC 4034 type-bitmap reader, both pure |
| `test/` | 55 tests, including the regressions and the pinned behaviours |
| `UPSTREAM-SOURCES.lock` | sha256 of 18 `ens-contracts` DNSSEC oracle files at `a18fdc0` |
| `verify-sources.sh` | checks a tree against that lock |

`src/contracts/` is not in this repository. It holds the `ens-contracts` DNSSEC oracle sources, which
belong upstream and are pinned here by hash instead of copied.

## No upstream change

The predicate needs no change to `ensdomains/ens-contracts`. It reads `DNSSECImpl` as deployed. The
oracle authenticates the record, and the predicate draws the conclusion the oracle does not draw.

## Build and run

Fetch the oracle sources at the pinned commit, then verify them before you trust a test result.

```sh
mkdir -p src/contracts/utils/LibMem
git clone --filter=blob:none --no-checkout \
  https://github.com/ensdomains/ens-contracts.git /tmp/ens-contracts
git -C /tmp/ens-contracts checkout a18fdc02e06e8005b23462387e26bd6f5db4b0f4 -- \
  contracts/dnssec-oracle contracts/utils/BytesUtils.sol contracts/utils/LibMem/LibMem.sol
cp -R /tmp/ens-contracts/contracts/dnssec-oracle src/contracts/
cp /tmp/ens-contracts/contracts/utils/BytesUtils.sol src/contracts/utils/
cp /tmp/ens-contracts/contracts/utils/LibMem/LibMem.sol src/contracts/utils/LibMem/

./verify-sources.sh src
FOUNDRY_SRC=src forge test
```

`verify-sources.sh` must exit 0. Any other exit means the test results from that tree mean nothing.
The lock covers all 20 files the build compiles: the 18 oracle files, plus
`contracts/utils/BytesUtils.sol` and `contracts/utils/LibMem/LibMem.sol`, which the oracle imports.
Copy only those two. The rest of `contracts/utils` pulls in `ccipRead`, which this build does not use.

`foundry.toml` sets `src = "empty"`, so `FOUNDRY_SRC=src` is required. `libs` points at
`node_modules`, which is not in this repository either.

## The fixtures expire

The RRSIGs in the tests were read from root server 198.41.0.4 on 11 November 2026 and expire on
**24 November 2026 at 05:00 UTC**. The oracle enforces the signature window, so after that date these
tests fail for a reason that looks exactly like a defect in the contract. Check the date first.

## Cost

About 281,000 gas for one proof against a deployed oracle, and about 552,000 for two. Most of that is
the oracle's own verification of the root DNSKEY set, which is RSA work. An absent name needs two
records from the root, so a call that consumes both pays for both.

## The audit

`../nsec-audit/AUDIT.md`, with 58 named inputs that run against this contract.

## Refusals are total

An unusable proof ends the call. It is not skipped so that the others can be read. This applies to
`ProofNotNSEC`, `ProofNotOneRecord` and `RecordNameTooDeep`, which are the three a caller can reach
with ordinary resolver output rather than with a crafted input.

The reason is not strictness for its own sake. If the contract drops part of what it was given, the
contract and the caller no longer agree on what was evaluated. A caller can send five proofs, have
four discarded, and act on the one that remains without knowing. For a release decision that is the
wrong failure: a wrong "not proven" costs a retry, and a wrong "proven" releases a live delegation.

There is a precedent in the oracle this contract reads.
[ens-contracts #583](https://github.com/ensdomains/ens-contracts/pull/583) made `computeRecordHash`
order independent with an XOR, which cancels a duplicate record, so `[b, b, a]` and `[a]` hashed
alike while `getOwnerAddress` read a different owner from each. The fix,
[`44b93cf`](https://github.com/ensdomains/ens-contracts/commit/44b93cf23d), replaced the XOR with a
fold. Tolerating a shape that the signature already fixed is what caused it.

The usability objection is answered by the errors rather than by silence. Each one carries the index
of the proof that failed, so a caller is told which element to remove.
