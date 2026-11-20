# Port map for the `ens-contracts` pull request

*20 November 2026.*

Everything in this directory is laid out at the path it takes in `ensdomains/ens-contracts`. Copy
each file to the matching path in a fork of **`staging`**, which is the default branch.

## Files

| From here | To, in `ens-contracts` | Change |
| --- | --- | --- |
| `contracts/dnssec-oracle/SHA512.sol` | same path | **new** |
| `contracts/dnssec-oracle/algorithms/RSASHA512Algorithm.sol` | same path | **new** |
| `contracts/dnssec-oracle/algorithms/RSAPKCS1Verify.sol` | same path | **modified**, 5 removed and 36 added |
| `deploy/dnssec-oracle/00_deploy_algorithms.ts` | same path | **modified**, 7 added and 0 removed |
| `test/dnssec-oracle/fixtures/algorithms.entry.ts` | **not a file.** Append its contents to the `algorithms` array in `test/dnssec-oracle/fixtures/algorithms.ts` | one entry |

No new test file is needed. `test/dnssec-oracle/TestAlgorithms.test.ts` iterates the fixture array
and runs a valid-signature and an invalid-signature case for each entry, so the new algorithm is
covered by adding the vector.

## What the destination's settings forced

Checked in `hardhat.config.ts` before porting, and each one changed the work.

- **`evmVersion: 'paris'`.** The local copy of this work used the `mcopy` opcode in
  `SHA512._pad`, which is 13% faster over a large message. `mcopy` is a Cancun instruction and does
  not compile for `paris`. **The copy is a byte at a time here.** The documented word-loop
  alternative is faster and **wrong**: it writes up to 31 bytes past the message into the zero
  padding, and it fails the SHA-512 differential test. The reason sits next to the loop.
- **`solidity: '0.8.26'`, and no `viaIR`.** `SHA512.sol` originally failed to compile without the
  IR pipeline, on the stack limit. Extracting the compression function into its own frame fixed it.
  Verified: the suite builds and passes under `paris`, solc 0.8.26, no `viaIR`, optimizer at
  1,000,000 runs.
- **Pragma style.** `SHA512.sol` uses `>=0.8.4` to match `SHA1.sol`, its neighbour.
  `RSASHA512Algorithm.sol` uses `^0.8.4` to match `RSASHA256Algorithm.sol`, its sibling. Imports are
  the bare `import "./X.sol"` form the siblings use, not named imports.

## Verification before sending

The source of truth is `alg10/`, one directory up, which holds the full suite. Both configurations
pass:

```sh
cd ..
forge test --gas-limit 90000000000
FOUNDRY_VIA_IR=false forge test --gas-limit 90000000000 \
    --evm-version paris --use 0.8.26 --optimizer-runs 1000000
```

**39 tests, 0 failures, under each.** The second command is the one that matters: it is the
destination's compiler and EVM version.

The diff on `RSAPKCS1Verify.sol` must stay at 5 removed and 36 added against the pristine upstream
copy:

```sh
diff ../../nsec/src/contracts/dnssec-oracle/algorithms/RSAPKCS1Verify.sol \
     ../src/contracts/dnssec-oracle/algorithms/RSAPKCS1Verify.sol
```

## What is not in the pull request

- The `swiss.` chain fixture and its capture tool. They are the motivation, not evidence upstream
  needs, and a captured chain expires. The vector that ships is RFC 5702 section 6.2, which does
  not.
- The gas harnesses. Their figures belong in the pull request description.
- `audit/AUDIT.md`. Link it; do not vendor it.

## Open findings to declare in the pull request body

Named up front, because a reviewer who finds them otherwise reads them as new. All four are in
`audit/AUDIT.md` with measurements.

- **Pre-existing upstream, unchanged by this work, present identically in `RSASHA1Algorithm` and
  `RSASHA256Algorithm`:** no cap on DNSKEY exponent length, so one key blob can consume a whole
  block of gas and return `false`; signature length is not checked against the modulus, so
  signatures are malleable; `exponentLen + 7` is `uint16` arithmetic and can overflow, which is
  unreachable through `DNSSECImpl`.
- **Introduced by this work and left open:** no RSA key size floor. RFC 5702 section 2.2 requires
  1024 to 4096 bits. The new length guard sets the floor at 752 bits, which is better than before
  and still short of the requirement. The remaining check is per-algorithm, so it belongs in
  `RSASHA512Algorithm.verify` rather than in the shared helper, and it is a behaviour change for
  conforming but small keys.

## What the change fixes beyond adding an algorithm

`recoverAndVerify` derived the digest length as `digestInfo.length == 15 ? 20 : 32`, a two way guess
between SHA-1 and SHA-256. It is correct for every algorithm the oracle registers today, and it
silently returns 32 for any other, so no third hash could ever verify. It is now a parameter.

The same function had no RFC 8017 section 9.2 step 3 length precondition, so a short modulus made
the offset arithmetic underflow and revert where `false` is the answer. The guard added here turns
94 of those reverts into `false` on the existing SHA-1 and SHA-256 paths, verified against the
unmodified upstream copy across 1,713 differential cases with no other change in behaviour.
