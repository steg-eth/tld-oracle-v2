# Audit of the root absence predicate

This is the audit of the contract in `../nsec/src`, as shipped. It was done by a team that did not
write the contract and did not read its test suite.

*12 November 2026.*

## What was audited

`RootAbsencePredicate.sol` and `NSECUtils.sol`, compiled against the `ens-contracts` DNSSEC oracle
at `a18fdc02e06e8005b23462387e26bd6f5db4b0f4`. No upstream file is changed. The predicate reads
`DNSSECImpl` as it is deployed.

## Method

A reading of code is not an audit of it. The result is a set of named inputs that run, with controls.

- **58 inputs**, in `inputs/round3/`. All pass.
- **Two positive controls first**, so that a refusal cannot be confused with a harness that refuses
  everything.
- **Each result is tied to the code path that produced it.**
- Inputs are marked as root-signed or synthetic. The root-signed fixtures come from root server
  198.41.0.4 on 11 November 2026.

To rerun them, build a tree the same way the predicate's own is built. `tree/` is not in this
repository, because it is a scratch copy of code that is already here or pinned by hash.

```sh
mkdir -p tree/src tree/empty
cp ../nsec/src/NSECUtils.sol ../nsec/src/RootAbsencePredicate.sol tree/src/
cp ../nsec/foundry.toml tree/
ln -s "$(cd ../nsec && pwd)/node_modules" tree/node_modules
cp -R ../nsec/src/contracts tree/src/contracts   # after ../nsec/README.md's fetch step
../nsec/verify-sources.sh tree/src

cd tree && FOUNDRY_SRC=src FOUNDRY_TEST=../inputs/round3 forge test
```

`verify-sources.sh` must exit 0 first. A test result from a tree that has not passed it means nothing.

## What the audit establishes

**The shape space is enumerated, not sampled.** The predicate holds owner and next-owner names to
one label below the root, so with the apex fixed there are six distinguishable record shapes. All
six are asserted. Two of them cover a name, and both are legitimate NSEC forms.

**The zone apex is authenticated, and the caller cannot influence it.** The predicate passes the
RRSIG signer name that the oracle authenticated, not a constant. The signer check runs before the
comparison, over a signed set that is never reassigned. The apex is inside the signed bytes, so an
edit to it fails: the oracle refuses the record before it does any signature work.

**The checks cost no liveness, measured against the published root zone.** Serial 2026111203, 1437
NSEC records, derived independently of the implementation:

| Measurement | Result |
| --- | --- |
| Owner and next-owner label counts | 0 or 1 only, no exceptions |
| Records with `next == owner` | 0 |
| Records that close the zone | 1, which is `zw. NSEC .` |
| Chain walk | closes after 1437 steps over 1437 distinct records |
| Records covering a name inside their own gap | 1437 of 1437 |
| Live TLDs reported absent, across 2,063,532 evaluations | 0 |

Names deeper than one label do exist in the root, 5907 of them, and they carry glue address records
only, never NSEC. Occlusion below a zone cut keeps the NSEC chain at depth one. This was measured,
not assumed.

**Signature window.** The oracle enforces the RRSIG validity window on the NSEC set itself rather
than on the trust anchor. The predicate takes its time from `block.timestamp` and has no parameter
for it.

## What the audit does not establish

**A forged closing record is out of scope and cannot be closed locally.** A record of the form
`com. NSEC .` is a structurally correct closing record that states the wrong name is last in the
zone. Separating it from the real `zw. NSEC .` needs to know which name is highest in the root, and
that is zone-global state which changes whenever a TLD is added or removed. No condition over an
owner name, a next-owner name, a queried name and a zone apex can express it.

The bound that does hold: such a record needs a valid root signature over a shape that the root does
not publish, and it would release only names above whichever owner it names.

**This is an agent-run audit, not an external review by a third party.** It is reproducible, which
is the property that matters for checking it, and it is not a substitute for review by people who
do not work on this project.

**Open items** concern what a caller must send and how a refusal is reported. None is a path from a
root-signed proof to a wrong answer about a live TLD.

## Tools

The scripts in `scripts/` re-derive the measurements above from the published root zone rather than
from this repository. `verify_pin.py` checks the oracle sources against the pinned commit.
