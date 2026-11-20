# Pre-submission review of the RSASHA512 algorithm contracts

*20 November 2026.*

## What this is, and what it is not

**This is an internal review, not a third-party audit.** The code and this review come from the
same project. Nobody independent was engaged and nobody was paid. The review was done by a reader
that did not write the code, was given the contracts and not the author's conclusions, and was told
to assume an adversarial attacker.

Read it as the author's own pre-submission pass. It is published because the findings below name a
defect that this work introduces, and because three further findings are pre-existing upstream
behaviour that a reviewer would otherwise read as new.

The precedent for the form is [`../../nsec-audit/AUDIT.md`](../../nsec-audit/AUDIT.md), which audits
the root absence predicate.

## Summary

| | |
| --- | --- |
| Subject | `SHA512.sol`, `RSASHA512Algorithm.sol`, and one change to `RSAPKCS1Verify.sol` |
| Repository | `steg-eth/tld-oracle-v2`, directory `alg10/` |
| Intended destination | `ensdomains/ens-contracts`, branch `staging` |
| Upstream baseline | `RSAPKCS1Verify.sol` confirmed byte-identical to `ens-contracts@staging` |
| Date | 20 November 2026 |
| Method | Manual review, differential testing, exhaustive sweeps |
| Tests added by the review | 29, in addition to the 9 the author wrote |

## Scope

In scope:

- `src/SHA512.sol`, a from-scratch SHA-512. No EVM precompile exists for it.
- `src/RSASHA512Algorithm.sol`, DNSSEC algorithm 10, RFC 5702.
- `src/contracts/dnssec-oracle/algorithms/RSAPKCS1Verify.sol`, one change: `recoverAndVerify` takes
  a `hashLen` parameter in place of deriving the digest length internally, and `verifySHA512` is
  added.

Out of scope: every other file under `src/contracts/`, which is vendored upstream code read as a
dependency.

## Risk classification

| | Impact: High | Impact: Medium | Impact: Low |
| --- | --- | --- | --- |
| **Likelihood: High** | Critical | High | Medium |
| **Likelihood: Medium** | High | Medium | Low |
| **Likelihood: Low** | Medium | Low | Low |

## Issues found

| | |
| --- | --- |
| Critical | 0 |
| High | 1 |
| Medium | 3 |
| Low | 4 |
| **Total** | **8** |

**No signature forgery was found. No input produced a wrong SHA-512 digest. The pre-existing
SHA-1 and SHA-256 paths are unchanged.**

## Summary of findings

| | Finding | Origin | Status |
| --- | --- | --- | --- |
| **H-1** | Missing RFC 8017 length precondition lets a short modulus panic instead of returning false | **This change** | **Resolved** |
| **M-1** | A zero length modulus defeats the length guard and panics | Upstream, widened here | **Resolved** |
| **M-2** | Exponent length is uncapped, so one key blob consumes a whole block of gas | Upstream | Acknowledged |
| **M-3** | SHA-512 costs about 1,530 gas for each byte, which caps a verifiable RRset near 29 KB | **This change** | Open, not fixable upstream |
| **L-1** | No key size floor or ceiling, so a 752 bit modulus verifies | Upstream | Open |
| **L-2** | Signature length is not checked against the modulus, so signatures are malleable | Upstream | Acknowledged |
| **L-3** | `uint16` overflow in the long exponent branch | Upstream | Acknowledged |
| **L-4** | A compiler warning, a pragma mismatch, and diff placement | **This change** | **Resolved** |

"Acknowledged" means the behaviour is pre-existing upstream, is byte-identical in the two sibling
contracts, and is being declared rather than changed. Fixing it in the new contract alone would make
it inconsistent with its siblings.

"Upstream" means the behaviour exists today in `ens-contracts` and in the sibling contracts
`RSASHA1Algorithm` and `RSASHA256Algorithm`. It is reported because the review was asked for it, not
because this work causes it.

---

## H-1. Missing RFC 8017 length precondition lets a short modulus panic instead of returning false

**Origin: this change.**

**Description.** RFC 8017 section 9.2 step 3 requires a length check before any offset arithmetic:
*"If emLen < tLen + 11, output 'intended encoded message length too short' and stop."* No such check
exists. The offsets are computed by subtraction from the end of the recovered block:

`src/contracts/dnssec-oracle/algorithms/RSAPKCS1Verify.sol:83-87`

```solidity
uint256 hashStart = result.length - hashLen;
uint256 digestInfoStart = hashStart - digestInfo.length;
...
if (result[digestInfoStart - 1] != 0x00) {
```

All three are checked subtractions. When the recovered block is shorter than the digest plus the
DigestInfo, they underflow and the call panics.

This behaviour is upstream's. **What this change does is widen it.** The DigestInfo is 19 bytes and
the digest is 64, so `tLen` is 83 and the block must be at least 94 bytes. At `hashLen = 32` the
window where the arithmetic underflows is 50 bytes wide. At 64 it is 82.

Measured, by sweeping every modulus length:

| modulus length | `verifySHA512` | `verifySHA256` |
| --- | --- | --- |
| 0 to 1 | `Panic(0x32)`, array out of bounds | same |
| 2 to 51 | `Panic(0x11)`, underflow | `Panic(0x11)` |
| **52 to 83** | **`Panic(0x11)`** | `false`, correct |
| 84 to 93 | `false`, correct | `false`, correct |
| 94 and above | verifies | verifies |

**Impact.** The panic is reachable through `DNSSECImpl.verifyRRSet` with a DNSKEY blob that an
untrusted caller supplies: flags `0x0100`, protocol 3, algorithm 10, a one byte exponent of 1, and a
32 byte modulus, with the RRSIG key tag set to the blob's own key tag. With an exponent of 1 the
recovered value is the signature itself, so `result[0..1] == 0x00 0x01` passes and the subtraction
underflows.

`DNSSECImpl.verifyWithDS` loops over the DNSKEYs in a submitted set and continues past a key that
fails. A panic ends the loop and the whole proof, and it replaces a typed error with `Panic`. The
control, the same shape with a 128 byte modulus, reverts `NoMatchingProof`, which is correct.

The key tag is not a defence. It is a 16 bit checksum over RDATA that the same caller supplies, and
the RRSIG key tag field is supplied by the caller too.

No value is at risk. The failure is a denial of a proof path, not an acceptance of a bad proof.

**Recommended mitigation.** One guard in `recoverAndVerify`, before the offsets are computed:

```solidity
if (result.length < hashLen + digestInfo.length + 11) {
    return (false, result);
}
```

The guard must sit after the length check and **before** `result[0]` is read. Placed after it, a
zero length result still panics `0x32` and M-1 stays open.

**Resolution, 20 November 2026.** Applied as written. The measured window for `verifySHA512` is now
`false` at every modulus length below 94, with no panic anywhere. `test_F6_acceptanceBoundary`
confirms 94 is still the first accepted length, which is the cross-check on the constant `11`.

The guard also raises the floor for the pre-existing paths, to 46 bytes for `verifySHA1` and 62 for
`verifySHA256`, which turns 94 upstream panics into `false`. Each one was classified and confirmed
to be of that shape and no other: 39 on the SHA-1 path, 55 on SHA-256, and zero divergences of any
other kind across 1,713 differential cases.

**This closes M-1. It does not close L-1.** An earlier version of this report said it closed both.
That was wrong: the guard sets the floor at 94 bytes, which is 752 bits, and RFC 5702 section 2.2
requires 1024. The remaining check is per-algorithm, because section 2.1 gives RSA/SHA-256 a 512 bit
floor and section 2.2 gives RSA/SHA-512 a 1024 bit floor, so it belongs in `RSASHA512Algorithm`
rather than in the shared helper.

---

## M-1. A zero length modulus defeats the length guard and panics

**Origin: upstream, widened here.**

**Description.** `ModexpPrecompile` allocates its output as `new bytes(modulus.length)`. For a zero
length modulus the call succeeds and returns nothing, so the guard at
`RSAPKCS1Verify.sol:70`, `result.length != modulus.length`, compares 0 to 0 and passes. The next
line reads `result[0]` and panics `0x32`.

Two DNSKEY blobs reach it. `0100 030a 01 03` takes the short exponent branch and leaves an empty
modulus. `0100 030a 00 0000` declares a 16 bit exponent length of zero and leaves both the exponent
and the modulus empty. The second panics through `verifyRRSet`.

**Impact.** As H-1: a panic where `false` is correct.

**Recommended mitigation.** The guard in H-1 covers it, because a zero length result is below the
floor.

**Resolution, 20 November 2026.** Closed by H-1's guard. Both triggering blobs now reach the typed
`NoMatchingProof` error instead of `Panic(0x32)`.

---

## M-2. Exponent length is uncapped, so one key blob consumes a whole block of gas

**Origin: upstream.**

**Description.** The long exponent branch reads a 16 bit length and accepts up to 65,535 bytes:

`src/RSASHA512Algorithm.sol:35-37`

```solidity
exponentLen = key.readUint16(5);
exponent = key.substring(7, exponentLen);
modulus = key.substring(exponentLen + 7, key.length - exponentLen - 7);
```

`ModexpPrecompile` forwards all remaining gas and swallows a failure into its success flag. So a
large exponent does not revert, it burns everything available and returns `false`.

Measured at a 30M gas stipend, under the `osaka` pricing this project pins:

| exponent bytes | key blob bytes | gas consumed | returns |
| --- | --- | --- | --- |
| 3 | 136 | 344,471 | false |
| 512 | 647 | 4,397,875 | false |
| 1,024 | 1,159 | 8,594,259 | false |
| 4,096 | 4,231 | 29,539,490, the whole stipend | false |

About 8,400 gas for each exponent byte. RFC 3110 section 2 states: *"For interoperability, the
exponent and modulus are each limited to 4096 bits in length."* That is 512 bytes.

**Impact.** Amplification from about 68,000 gas of calldata to a full block. The same parsing is
byte-identical in `RSASHA1Algorithm` and `RSASHA256Algorithm`, so algorithms 5, 7 and 8 carry it on
the deployed oracle today.

**Recommended mitigation.** A bound of `modulus.length` and `exponent.length` to RFC 3110's 512
bytes. Adding it only to the new contract makes it inconsistent with its three siblings, so this is
a judgement call rather than a defect to fix in isolation.

---

## M-3. SHA-512 costs about 1,530 gas for each byte, which caps a verifiable RRset near 29 KB

**Origin: this change.**

**Description.** SHA-512 has no precompile, so every byte is hashed in the EVM.

| message | gas |
| --- | --- |
| 128 B | 389,776 |
| 1 KiB | 1,754,347 |
| 8 KiB | 12,674,852 |
| 16 KiB | 25,166,270 |
| 32 KiB | 50,180,449 |

The asymptote is about 1,531 gas for each byte, or about 173,300 for each 128 byte block. On the
real `swiss.` chain the algorithm 10 level costs 1,421,329 gas against 166,402 and 122,086 for the
two algorithm 8 levels in the same chain.

**Impact.** Two things belong in the pull request text rather than being found later.

1. A 45M gas block bounds the signed data at roughly 29 KB. DNS permits a larger RRset over TCP. For
   a TLD DNSKEY set this is comfortable. For a large TXT set, or a DNSKEY set during a key
   rollover, it is not, and the failure is a valid proof that cannot be submitted.
2. About 11% of the cost is a byte at a time copy in the padding step, `src/SHA512.sol:101`. The
   tree already holds `LibMem.copy`, which uses `mcopy` at about 0.2 gas for each byte.

**Recommended mitigation.** Replace the copy loop. The 29 KB ceiling is a property of the EVM and is
documented rather than fixed.

**Resolution, 20 November 2026. Partly resolved: the copy is fixed, the ceiling is not.**

The copy now uses the `mcopy` opcode, EIP-5656. **`LibMem.copy` was the obvious choice and it is the
wrong one.** It was prototyped and measured at **280,619 gas for each block against 173,040 for
`mcopy`**, because it is a non-inlinable library call taking three memory pointers and it defeats
the IR pipeline's register allocation for the compression loop. The trap is that small inputs still
get cheaper with it, so the RFC 5702 vector and the `swiss.` chain both improve while a 16 KiB
message regresses by 44%. `mcopy` also reads and writes exactly `len` bytes, where `LibMem.copy` and
a hand written word loop both over-read up to 31 bytes past the source.

Measured after:

| call | before | after |
| --- | --- | --- |
| the algorithm 10 chain level | 1,421,329 | **1,305,092** |
| RFC 5702 vector | 372,057 | **357,451** |
| 16 KiB message | 25,166,270 | **21,778,230** |
| for each 128 byte block | 173,262 | 178,992 |

The per-block figure rises by 3.3% because of L-4's fix, and the totals absorb it. **The 29 KB
ceiling stands** and is a property of the EVM.

**Withdrawn, 20 November 2026, on inspecting the destination repository.** `ens-contracts` compiles
with `evmVersion: 'paris'`. `mcopy` is a Cancun instruction and does not compile there:
*"Error (7755): The 'mcopy' instruction is only available for Cancun-compatible VMs."*

**The documented fallback is wrong, and the test suite caught it.** A word loop that reads and
writes 32 bytes at a time was measured at the same speed as `mcopy` and was believed safe because
its writes stay inside the buffer. It is not safe. It writes up to 31 bytes of source-adjacent
memory past `len`, and those bytes are the zero padding the digest depends on. `m[len] = 0x80`
repairs only byte `len`. Under the upstream compiler settings it **fails the SHA-512 differential
test** at message lengths below 200. Three readers accepted that fallback before a test refused it.

**So the copy stays a byte at a time** and M-3's gas improvement is not available upstream. 16 KiB
returns to 25,166,270 from 21,778,230. The reason is recorded next to the loop so the next reader
does not repeat the attempt. Both files now carry `pragma solidity ^0.8.4`.

---

## L-1. No key size floor or ceiling, so a 752 bit modulus verifies

**Origin: upstream.**

RFC 5702 section 2.2 states: *"The key size of RSA/SHA-512 keys MUST NOT be less than 1024 bits and
MUST NOT be more than 4096 bits."* Neither bound is enforced. Measured, a 94 byte modulus, 752 bits,
verifies. There is no upper bound either.

**Impact.** Low. Key authenticity comes from the DS chain, not from the key size. A short key is a
weak key the parent zone chose to publish.

**Recommended mitigation.** `128 <= modulus.length <= 512`, in `RSASHA512Algorithm.verify` and not
in the shared helper, because the floor differs for each algorithm.

**Status: open, by decision.** H-1's guard raised the floor to 94 bytes, which is 752 bits, so this
is narrower than it was and is not closed. It is a behaviour change for conforming but small keys,
so it is the author's call rather than a defect to close in a cleanup pass.

---

## L-2. Signature length is not checked against the modulus

**Origin: upstream.**

RFC 8017 section 8.2.2 step 1 states: *"If the length of the signature S is not k octets, output
'invalid signature' and stop."* No such check exists. For a 128 byte modulus the same valid
signature verifies at 127 bytes with the leading zero stripped, at 129 to 132 bytes zero extended,
and as `s + n` encoded in 129 bytes.

**Impact.** Low. One valid signature has many accepted encodings. Nothing in `DNSSECImpl` keys off
the signature bytes, so nothing is wrong today. It is a hazard for anything downstream that
deduplicates or caches on a hash of the proof.

---

## L-3. `uint16` overflow in the long exponent branch

**Origin: upstream.**

`src/RSASHA512Algorithm.sol:37`. `exponentLen + 7` is `uint16` arithmetic, because `exponentLen` is
`uint16`. A declared exponent length of `0xFFFF` with a 65,543 byte key blob panics `0x11`.

**Impact.** Low. Unreachable through `DNSSECImpl`, because RDATA length is a 16 bit field and a key
can never exceed 65,535 bytes. Reachable by any direct caller of `verify`. Byte-identical in the two
sibling contracts.

---

## L-4. A compiler warning, a pragma mismatch, and diff placement

**Origin: this change.**

- `src/SHA512.sol:123` emits Solidity warning 3149 on every build. The expression
  `(x >> n) | (x << (64 - n))` sits inside `unchecked`, so `_rotr(x, n)` for `n >= 64` would
  silently return `x >> n` rather than revert. **This is sound today**: every rotation amount in the
  file is in the range 1 to 63, and `n == 0` happens to be correct. It is a trap for the next
  editor, and a warning should not ship into a production repository in a cryptographic file.
- `SHA512.sol` and `RSASHA512Algorithm.sol` use `pragma solidity ^0.8.25`. Every file under
  `contracts/dnssec-oracle/` upstream uses `^0.8.4`.

  **Resolution, 20 November 2026.** `RSASHA512Algorithm.sol` is now `^0.8.4`. **`SHA512.sol` is
  `^0.8.24`, not `^0.8.4`**, because `mcopy` requires that compiler. Declaring `^0.8.4` on a file
  that contains `mcopy` compiles here, where the resolved compiler is 0.8.30, and is a false
  declaration that breaks if upstream resolves lower. A mixed floor already exists in this tree:
  `BytesUtils.sol` is `^0.8.4` and imports `LibMem.sol` at `^0.8.13`.
- `SHA512_DIGEST_INFO` and `verifySHA512` were inserted between `verifySHA1` and `verifySHA256`.
  The upstream diff therefore reads as a rewrite of that region. Appending keeps the diff to four
  lines, which matters in a file this sensitive.

  **Resolution, 20 November 2026.** Moved. The order is now constants, `verifySHA1`, `verifySHA256`,
  `verifySHA512`, `recoverAndVerify`. The diff against the pristine upstream copy is **5 removed and
  36 added lines**, and the 5 removals are only the two call sites that gain a `hashLen` argument,
  the signature line, the `digestInfo.length == 15 ? 20 : 32` ternary, and one comment.

---

## Checked and found sound

Stated plainly, because an audit that reports only findings does not say what it covered.

**SHA-512 is bit exact.** A differential test over *every* message length from 0 to 600 inclusive,
which covers every block boundary in that range, plus 1,000 to 1,010, 4,096 and 16,384. Inputs come
from a generator that Python reproduces byte for byte. Expected digests come from Python's
`hashlib`, which is OpenSSL. All match.

Line by line against FIPS 180-4, each confirmed: the padding is injective; `padded = ((len + 17 +
127) / 128) * 128` is correct at every residue; the `0x80` marker cannot collide with the length
field; the 128 bit length field's high 8 bytes are correctly left zero; `_word` is big-endian; the
four sigma functions and Ch and Maj match section 4.1.3; the working variable rotations match
section 6.4.2; the schedule is fully rewritten each block, so reuse of the array across blocks is
safe; the round constants and the initial hash value are correct, proved by the sweep rather than by
eye; every `unchecked` sits on addition modulo 2^64, where FIPS requires wrapping, and nowhere else.

**The `hashLen` change does not alter the SHA-1 or SHA-256 paths.** 1,713 differential cases against
the pristine upstream copy, 154 of which return true, with **zero divergences**, including identical
revert behaviour. Coverage: every modulus length 0 to 130; well formed blocks; a corrupted padding
byte; a corrupted separator; a corrupted DigestInfo; a wrong hash; each DigestInfo substituted into
the other verifier; exponents 1, 3 and 65537.

**No PKCS#1 v1.5 forgery was found.** The checker is anchored at both ends, with no unchecked region
anywhere in the block. **16,887 forgery attempts, 0 accepted**, across modulus sizes 94, 95, 96,
127, 128, 129 and 256, all with **exponent 1**, which gives the attacker complete control of the
recovered value for no work. That covers the Bleichenbacher 2006 family, DigestInfo length
ambiguity, and parameter field substitution. The DigestInfo is compared by keccak against a fixed
constant, so non-canonical BER variants are refused.

**The DigestInfo constant is correct.** `3051300d060960864801650304020305000440` matches RFC 5702
section 3.2 verbatim and decodes to SEQUENCE(81) { SEQUENCE(13) { OID 2.16.840.1.101.3.4.2.3, NULL
}, OCTET STRING(64) }.

**DNSKEY parsing is in bounds.** The checked subtractions `key.length - exponentLen - 5` and `- 7`
cannot underflow, because `substring`'s bound check on the preceding exponent read runs first and
already guarantees the length. Short keys revert with the typed `OffsetOutOfBoundsError`, not a
panic.

**No conforming key is rejected.** Every modulus length from 128 to 512 bytes behaves correctly and
the RFC 5702 section 6.2 vector passes. The only way a valid proof fails is gas, which is M-3.

**Categories with nothing to report:** signature forgery, a wrong SHA-512 digest for any input, a
regression in the pre-existing verification paths, and a valid signature rejected by a logic error.

## Reproducing

```sh
cd alg10
forge test --gas-limit 90000000000
```

The high gas limit is for the exhaustive sweeps. The review's own tests are the `Audit*.t.sol` files
and `test/upstream/RSAPKCS1VerifyUpstream.sol`, which is the pristine upstream copy used as the
differential reference.
