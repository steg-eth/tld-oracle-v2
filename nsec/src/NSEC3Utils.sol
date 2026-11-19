//SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {SHA1} from "./contracts/dnssec-oracle/SHA1.sol";
import {BytesUtils} from "./contracts/utils/BytesUtils.sol";
import {NSECUtils} from "./NSECUtils.sol";

/// @title NSEC3Utils
/// @notice Readers for DNSSEC NSEC3 records, per RFC 5155.
/// @dev The sibling of `NSECUtils`. The root zone is NSEC, so the shipped `RootAbsencePredicate`
///      reads NSEC. A proof inside a top-level domain's own zone needs whatever that zone uses,
///      and the census of 19 November 2026 counted NSEC3 in 1,308 of the 1,436 names in the
///      root, including all seven EBERO names. See `survey/NSEC3-CENSUS-2026-11-19.md`.
///
///      The ENS DNSSEC oracle authenticates an NSEC3 RRset today and needs no change.
///      `dnssec-oracle/DNSSECImpl.sol` line 15 is about the conclusion the oracle draws, not
///      about what it authenticates. `test/NSEC3FixtureCheck.t.sol` measures that: three
///      captured four-link chains, root DNSKEY to the zone's NSEC3 set, validate through an
///      unmodified `DNSSECImpl`. This library reads what the oracle returns.
///
///      Four parts, in the order a caller uses them.
///
///      1. `ownerHash` and `decodeHashLabel`. An NSEC3 owner name carries the hash of the
///         covered name as a base32hex first label, per RFC 5155 section 3 and RFC 4648
///         section 7. **Decode only.** The next-hashed-owner field inside the rdata is raw
///         bytes, so every comparison here is between two 20-byte hashes and no encoder is
///         needed anywhere.
///      2. `hashName`. The iterated hash of RFC 5155 section 5, over `SHA1.sol`.
///      3. `readRdata`. The record's own parameters, which are read from the record and never
///         assumed. 1,222 of the 1,308 NSEC3 names in the root use zero iterations and no
///         salt, and an operator changes that with one rezone.
///      4. `coversHash`. The hash-order comparator. **Read its note. Its closing-record rule
///         is the opposite of `NSECUtils.coversName`'s, and each rule is wrong in the other's
///         context.**
///
///      The type bitmap is not reimplemented. RFC 5155 section 3.2.1 uses the bitmap format of
///      RFC 4034 section 4.1.2 without change, so `rdataHasType` finds where the bitmap starts
///      and hands it to `NSECUtils.hasType`.
///
///      **The readers are strict, for the reason `NSECUtils` gives.** A malformed record, a bad
///      base32hex character, a truncated rdata, an unsupported hash algorithm, a wrong hash
///      length: each one reverts with a named error. None of them makes a reader report a hash
///      as covered or a type as absent. A record that releases a live top-level domain must not
///      come from a misread byte. A revert is safe. A false is not.
library NSEC3Utils {
    using BytesUtils for bytes;

    /// @dev The only hash algorithm defined for NSEC3, per RFC 5155 section 3.1.1 and the IANA
    ///      "DNSSEC NSEC3 Hash Algorithms" registry. All 1,308 NSEC3 names in the root use it.
    uint8 internal constant HASH_ALGORITHM_SHA1 = 1;

    /// @dev Opt-Out, bit 0 of the flags byte, per RFC 5155 section 3.1.2.1. See `isOptOut`.
    uint8 internal constant FLAG_OPT_OUT = 0x01;

    /// @dev Every flag RFC 5155 defines. The rest "must be zero", per section 3.1.2.
    uint8 internal constant FLAGS_DEFINED = FLAG_OPT_OUT;

    /// @dev The digest length of SHA-1, which is the length of the next-hashed-owner field and
    ///      of a decoded owner label.
    uint256 internal constant SHA1_HASH_LENGTH = 20;

    /// @dev 20 bytes is 160 bits, which is exactly 32 base32hex characters. So an NSEC3 owner
    ///      label has one valid length, and the encoding has no leftover bits and no padding.
    uint256 internal constant OWNER_LABEL_LENGTH = 32;

    /// @dev The iteration ceiling. Decided 19 November 2026. The highest count measured
    ///      anywhere in the root is 20, and RFC 9276 asks signers for zero, so this is headroom
    ///      that lets a zone rezone without becoming unprovable while still bounding gas
    ///      against a zone that publishes an absurd count. Above it, `hashName` and `readRdata`
    ///      revert, which refuses a proof rather than releasing a name on a cheap one.
    ///
    ///      **The bound is large. Measured with `gasleft()` around `hashName` for
    ///      `_ens.desi.`, 19 November 2026: 37,423 gas at zero iterations, 673,615 at 20, and
    ///      4,808,915 at 150.** `SHA1.sol` is pure EVM, about 31,800 gas for each additional
    ///      hash. So the cap bounds one hashed name at roughly 4.8M gas, and a denial hashes up
    ///      to three names. At the counts that exist in the root today, 20 at the most, the
    ///      cost is under 700k for each name. A caller that must bound a transaction rather
    ///      than a hash has to bound the iteration count it accepts, which is lower than this.
    uint256 internal constant MAX_ITERATIONS = 150;

    /// @dev The fixed part of the rdata before the salt: hash algorithm, flags, iterations.
    uint256 internal constant RDATA_SALT_LENGTH_OFFSET = 4;

    /// @dev Hash algorithm, flags, iterations, salt length, an empty salt, hash length, and a
    ///      SHA-1 next-hashed-owner. The shortest rdata RFC 5155 section 3.2 allows, before the
    ///      type bitmap, which may be empty. See `rdataHasType`.
    uint256 internal constant MIN_RDATA_LENGTH = 26;

    /// @dev Type numbers this library names. NSEC3 is the record read here. TXT is the type the
    ///      `_ens.<tld>` question asks about, and it is named so that a caller does not have to
    ///      write the number. NSEC3PARAM is named only to carry the warning on `isOptOut`.
    uint16 internal constant DNSTYPE_TXT = 16;
    uint16 internal constant DNSTYPE_NSEC3 = 50;
    uint16 internal constant DNSTYPE_NSEC3PARAM = 51;

    /// @dev A character in an owner label is not in the base32hex alphabet of RFC 4648
    ///      section 7. Uppercase is included in the refusal, deliberately: see
    ///      `decodeHashLabel`.
    error InvalidBase32HexChar(bytes1 character);

    /// @dev The first label of an NSEC3 owner name is not 32 characters, so it cannot be the
    ///      base32hex form of a 20-byte hash.
    error InvalidHashLabelLength(uint256 length);

    /// @dev The rdata is shorter than the fields it declares. `needed` is the length the fields
    ///      read so far require.
    error TruncatedNSEC3Rdata(uint256 needed, uint256 length);

    /// @dev The record's hash algorithm is not SHA-1. No other algorithm is defined for NSEC3,
    ///      so this is an unreadable record and not an unsupported one.
    error UnsupportedHashAlgorithm(uint8 algorithm);

    /// @dev The flags byte sets a bit RFC 5155 does not define, which section 3.1.2 requires to
    ///      be zero. **Opt-Out is defined and is accepted.** See `readRdata`.
    error UndefinedNSEC3Flags(uint8 flags);

    /// @dev The iteration count is above `MAX_ITERATIONS`.
    error IterationCountTooHigh(uint256 iterations);

    /// @dev The record's hash length field is not 20. The hash algorithm is SHA-1, whose digest
    ///      is 20 bytes, so any other value makes the next-hashed-owner field unreadable.
    error InvalidHashLength(uint8 hashLength);

    /// @notice One NSEC3 record's rdata, read into its fields.
    /// @param hashAlgorithm Always 1, SHA-1. `readRdata` refuses anything else.
    /// @param flags The flags byte. Bit 0 is Opt-Out, and it is accepted and ignored.
    /// @param iterations The additional hash iterations, at most `MAX_ITERATIONS`.
    /// @param salt The salt, which may be empty.
    /// @param nextHashedOwner The next hashed owner name, raw and not base32hex.
    /// @param bitmapOffset The offset of the first type-bitmap window block inside the rdata.
    ///        It equals the rdata length when the bitmap is empty, which is legal. See
    ///        `rdataHasType`.
    struct NSEC3Record {
        uint8 hashAlgorithm;
        uint8 flags;
        uint16 iterations;
        bytes salt;
        bytes20 nextHashedOwner;
        uint256 bitmapOffset;
    }

    // ------------------------------------------------------- the hash-order covering comparator

    /// @notice Does one NSEC3 record deny the existence of the name whose hash is `nameHash`?
    /// @dev The record states that no name exists whose hash sorts between its own owner hash
    ///      and its next-hashed-owner field. Two forms exist, exactly as for NSEC.
    ///
    ///      1. An ordinary gap. `owner < nameHash` and `nameHash < next`.
    ///      2. The record that closes the chain. Its next-hashed-owner sorts at or below its
    ///         own owner hash, per RFC 5155 section 7.1 step 7, and it covers every hash above
    ///         its owner **or** below its next-hashed-owner.
    ///
    ///      **This closing rule is the opposite of `NSECUtils.coversName`'s, and the opposite
    ///      is correct here. Do not make the two agree.** `NSECUtils.coversName` carries a long
    ///      note about a bug: an earlier revision of it took the closing branch whenever
    ///      `next <= owner`, two shapes then read as closing records, and each released live
    ///      names. The fix keys that branch on `next == zoneApex` instead, because in NSEC the
    ///      apex sorts lowest of all names in the zone and so is always the next-owner name of
    ///      the last record.
    ///
    ///      That key does not exist here. NSEC3 owner names are hashes, so the chain is in hash
    ///      order and **the apex has its own NSEC3 record somewhere in that order rather than at
    ///      the start.** There is no apex hash to compare against. The only statement the chain
    ///      makes about its last record is the one in RFC 5155 section 7.1 step 7: its
    ///      next-hashed-owner is the first owner hash of the chain, which sorts at or below it.
    ///      So `next <= owner` is the test, and the shape `next == owner` is a legitimate
    ///      one-record chain rather than the bug `NSECUtils` describes.
    ///
    ///      Measured, 19 November 2026, on the captured fixtures in `test/NSEC3Fixtures.sol`.
    ///      `firmdale` publishes exactly one NSEC3 record, because opt-out hides every
    ///      delegation in the zone, and that record points at itself:
    ///
    ///          ownerhash d4aaf321d0be6248b2f93a433b76cd9bdd56173e
    ///          nexthash  d4aaf321d0be6248b2f93a433b76cd9bdd56173e
    ///
    ///      `hash(_ens.firmdale.)` is `1a5d65c0...`, which sorts **below** the owner hash, and
    ///      `hash(*.firmdale.)` is `6e723733...`, which also sorts below it. Only the wrap-aware
    ///      reading proves either absent. An implementation that ports the NSEC rule reports
    ///      `_ens.firmdale.` as unproven, which is the direction that is safe but useless: it
    ///      fails the one zone of the three that has no second record to fall back on.
    ///
    ///      The form must not over-accept. A record is never read as covering its own
    ///      endpoints. `nameHash == owner` returns false, because that name exists: read the
    ///      record's own type bitmap with `rdataHasType` instead. `nameHash == next` returns
    ///      false in both branches, because that name is the owner of the next record in the
    ///      chain and also exists. `owner == next` is the one-record chain above, and it covers
    ///      every hash except the owner's own.
    ///
    ///      Hash order is the numeric order of the raw 20-byte digests. The chain is published
    ///      in DNS canonical order of the base32hex owner labels, and the two orders are the
    ///      same, because every label is 32 characters long and the base32hex alphabet
    ///      `0123456789abcdefghijklmnopqrstuv` is ascending in ASCII. So comparing the decoded
    ///      hashes as `uint160` is the same comparison the signer made.
    /// @param ownerHashValue The decoded owner hash of the NSEC3 record.
    /// @param nextHashValue The record's next-hashed-owner field.
    /// @param nameHashValue The hash of the queried name, from `hashName`.
    /// @return True if the record denies that a name with that hash exists in the zone.
    function coversHash(
        bytes20 ownerHashValue,
        bytes20 nextHashValue,
        bytes20 nameHashValue
    ) internal pure returns (bool) {
        uint160 ownerValue = uint160(ownerHashValue);
        uint160 nextValue = uint160(nextHashValue);
        uint160 nameValue = uint160(nameHashValue);
        if (nameValue == ownerValue) {
            // The name is the record's own owner name. It exists. Read its type bitmap.
            return false;
        }
        if (nextValue > ownerValue) {
            // An ordinary gap.
            return nameValue > ownerValue && nameValue < nextValue;
        }
        // The record closes the chain, per RFC 5155 section 7.1 step 7. It covers the whole
        // span from its owner hash, round the end of hash order, to its next-hashed-owner.
        return nameValue > ownerValue || nameValue < nextValue;
    }

    /// @notice Does `record` with owner name `ownerName` deny the existence of `name`?
    /// @dev The comparator with the three reads in front of it: decode the owner label, read
    ///      the record's own parameters, hash the queried name with those parameters. This is
    ///      the call a predicate makes.
    ///
    ///      It does not check that `ownerName` sits inside the zone that signed the record.
    ///      A caller must do that with the RRSIG signer name the oracle authenticates, in the
    ///      way `RootAbsencePredicate` does with `ProofNotFromRoot`. A record from another zone
    ///      would otherwise appear to cover a hash in this one.
    /// @param ownerName The owner name of the NSEC3 record, in wire format.
    /// @param rdata The rdata of the NSEC3 record.
    /// @param name The queried name, in wire format, lowercase.
    /// @return True if the record denies that `name` exists in the zone.
    function recordCoversName(
        bytes memory ownerName,
        bytes memory rdata,
        bytes memory name
    ) internal pure returns (bool) {
        NSEC3Record memory record = readRdata(rdata);
        return
            coversHash(
                ownerHash(ownerName),
                record.nextHashedOwner,
                hashNameForRecord(name, record)
            );
    }

    /// @notice Is `name` the name this NSEC3 record is the record for?
    /// @dev A match is the NODATA shape: the name exists, and the record's own type bitmap says
    ///      which types it has. A cover is the NXDOMAIN shape. The two are exclusive, which
    ///      `coversHash` enforces by returning false on its own owner hash.
    /// @param ownerName The owner name of the NSEC3 record, in wire format.
    /// @param rdata The rdata of the NSEC3 record.
    /// @param name The queried name, in wire format, lowercase.
    /// @return True if the record's owner hash is the hash of `name`.
    function recordMatchesName(
        bytes memory ownerName,
        bytes memory rdata,
        bytes memory name
    ) internal pure returns (bool) {
        NSEC3Record memory record = readRdata(rdata);
        return ownerHash(ownerName) == hashNameForRecord(name, record);
    }

    // ----------------------------------------------------------------------- the iterated hash

    /// @notice The NSEC3 hash of `name`, per RFC 5155 section 5.
    /// @dev `IH(salt, x, 0) = SHA1(x || salt)` and `IH(salt, x, k) = SHA1(IH(salt, x, k-1) ||
    ///      salt)`, where `x` is the name in uncompressed, lowercase wire format. So an
    ///      iteration count of zero is one hash, not none. SHA-1 is the only algorithm NSEC3
    ///      defines.
    ///
    ///      The name is held to DNS canonical form by `NSECUtils.requireCanonicalName`, and an
    ///      uppercase letter reverts rather than being folded. RFC 5155 section 5 hashes the
    ///      canonical form, so `_ENS.DESI.` and `_ens.desi.` have the same hash in the zone but
    ///      different hashes under a reader that does not fold. A reader that folded silently
    ///      would also accept a name the caller and the predicate disagree about, which is the
    ///      reason `NSECUtils.requireCanonicalName` refuses instead of rewriting.
    ///
    ///      The count is capped at `MAX_ITERATIONS` and a higher count reverts. The cap is the
    ///      gas bound: each iteration is one more SHA-1 over 20 bytes plus the salt.
    ///
    ///      Self-checked against RFC 5155 Appendix A, whose example zone uses salt `aabbccdd`
    ///      and 12 iterations. `tools/mkhashvectors.py` prints those eight vectors and the
    ///      vectors for the three captured zones, and `test/NSEC3Utils.t.sol` asserts all of
    ///      them.
    /// @param name The name to hash, in wire format, lowercase.
    /// @param salt The salt from the record, which may be empty.
    /// @param iterations The additional iterations from the record.
    /// @return The 20-byte hash.
    function hashName(
        bytes memory name,
        bytes memory salt,
        uint256 iterations
    ) internal pure returns (bytes20) {
        if (iterations > MAX_ITERATIONS) {
            revert IterationCountTooHigh(iterations);
        }
        NSECUtils.requireCanonicalName(name);
        bytes20 digest = SHA1.sha1(abi.encodePacked(name, salt));
        for (uint256 k; k < iterations; ++k) {
            digest = SHA1.sha1(abi.encodePacked(digest, salt));
        }
        return digest;
    }

    /// @notice `hashName`, with the parameters taken from a record that has already been read.
    /// @dev The parameters belong to the record, never to this library. The census is a
    ///      statement about today: 1,222 of 1,308 zones use zero iterations and no salt, and
    ///      one rezone changes that.
    /// @param name The name to hash, in wire format, lowercase.
    /// @param record A record from `readRdata`.
    /// @return The 20-byte hash.
    function hashNameForRecord(
        bytes memory name,
        NSEC3Record memory record
    ) internal pure returns (bytes20) {
        return hashName(name, record.salt, record.iterations);
    }

    // -------------------------------------------------------------------------- the rdata reader

    /// @notice Reads the rdata of an NSEC3 record into its fields, per RFC 5155 section 3.2.
    /// @dev The fields are hash algorithm, flags, iterations, salt length, salt, hash length,
    ///      next hashed owner, then the type bitmap. Every length is read from the record and
    ///      checked against the rdata that is actually there. A field that runs past the end
    ///      reverts with `TruncatedNSEC3Rdata` and never silently yields a short read.
    ///
    ///      **Opt-Out is accepted and the bit is ignored. This is not a missing validation.**
    ///      `desi`, `pars`, `shia`, `tci`, `wed` and `xn--mgbt3dhd` publish NSEC3 records with
    ///      `flags = 1`, which is six of the seven EBERO names this work exists for, so a
    ///      reader that refuses a non-zero flags byte fails on almost every target zone and the
    ///      failure looks like a comparator bug. Accepting it is sound: opt-out narrows what a
    ///      span proves to "no *signed delegation* exists in it, and an unsigned delegation
    ///      may", per RFC 5155 section 6. The name being proven absent here is a TXT name under
    ///      the apex and is never a delegation, so an opt-out span still proves it absent.
    ///
    ///      A bit the RFC does not define is still refused, because RFC 5155 section 3.1.2
    ///      requires the undefined flags to be zero. A zone that sets one becomes unprovable
    ///      instead of being read under a meaning this library does not know, which is the safe
    ///      direction: it refuses a release, it does not grant one.
    ///
    ///      **Never read opt-out from an `NSEC3PARAM` record.** RFC 5155 section 4.1.2 requires
    ///      that record's own flags field to be zero in every zone, so it carries no opt-out
    ///      information at all. The first version of the census measured it there and concluded
    ///      that no top-level domain uses opt-out, which was false.
    /// @param rdata The rdata of an NSEC3 record.
    /// @return record The fields, and the offset where the type bitmap starts.
    function readRdata(
        bytes memory rdata
    ) internal pure returns (NSEC3Record memory record) {
        uint256 length = rdata.length;
        if (length < MIN_RDATA_LENGTH) {
            revert TruncatedNSEC3Rdata(MIN_RDATA_LENGTH, length);
        }

        record.hashAlgorithm = uint8(rdata[0]);
        if (record.hashAlgorithm != HASH_ALGORITHM_SHA1) {
            revert UnsupportedHashAlgorithm(record.hashAlgorithm);
        }

        record.flags = uint8(rdata[1]);
        if ((record.flags & ~FLAGS_DEFINED) != 0) {
            revert UndefinedNSEC3Flags(record.flags);
        }

        record.iterations = rdata.readUint16(2);
        if (uint256(record.iterations) > MAX_ITERATIONS) {
            revert IterationCountTooHigh(record.iterations);
        }

        uint256 saltLength = uint8(rdata[RDATA_SALT_LENGTH_OFFSET]);
        uint256 hashLengthOffset = RDATA_SALT_LENGTH_OFFSET + 1 + saltLength;
        if (length < hashLengthOffset + 1) {
            revert TruncatedNSEC3Rdata(hashLengthOffset + 1, length);
        }
        record.salt = rdata.substring(RDATA_SALT_LENGTH_OFFSET + 1, saltLength);

        uint8 hashLength = uint8(rdata[hashLengthOffset]);
        if (uint256(hashLength) != SHA1_HASH_LENGTH) {
            revert InvalidHashLength(hashLength);
        }
        uint256 bitmapOffset = hashLengthOffset + 1 + SHA1_HASH_LENGTH;
        if (length < bitmapOffset) {
            revert TruncatedNSEC3Rdata(bitmapOffset, length);
        }
        record.nextHashedOwner = rdata.readBytes20(hashLengthOffset + 1);
        record.bitmapOffset = bitmapOffset;
    }

    /// @notice Is the Opt-Out flag set on this record's flags byte?
    /// @dev Bit 0, per RFC 5155 section 3.1.2.1. Reported, never required and never refused.
    ///      A caller that proves a TXT name absent has no use for it, for the reason on
    ///      `readRdata`. A caller that ever proves a *delegation* absent would have to require
    ///      this to be clear.
    ///
    ///      The argument is a flags byte from an NSEC3 record and never from an `NSEC3PARAM`
    ///      record, whose own flags field RFC 5155 section 4.1.2 requires to be zero.
    /// @param flags The flags byte from `readRdata`.
    /// @return True if the record covers zero or more unsigned delegations.
    function isOptOut(uint8 flags) internal pure returns (bool) {
        return (flags & FLAG_OPT_OUT) != 0;
    }

    // ------------------------------------------------------------------- the type bitmap reader

    /// @notice Does the NSEC3 record with this rdata list `dnstype`?
    /// @dev RFC 5155 section 3.2.1 uses the type-bitmap format of RFC 4034 section 4.1.2
    ///      without change, so the bitmap itself is read by `NSECUtils.hasType` and is not
    ///      reimplemented here. This function finds where the bitmap starts, which for NSEC3
    ///      depends on the salt length and the hash length and so has to be read rather than
    ///      assumed. The bitmap runs to the end of the rdata.
    ///
    ///      **An empty bitmap is legal in NSEC3 and reports every type absent. This is the one
    ///      place the two libraries differ in strictness, and it is not an oversight.** An NSEC
    ///      record always lists at least RRSIG and NSEC, so `NSECUtils.hasType` treats a bitmap
    ///      with no bytes as malformed and reverts. An NSEC3 record for an empty non-terminal
    ///      has no types of its own, and RFC 5155 section 7.1 has the signer publish it with no
    ///      window blocks at all. Reverting on that shape would refuse a sound NODATA proof.
    ///      Reporting the types absent is the record's own statement, and the statement is
    ///      signature-covered: `readRdata` has already refused a truncated rdata, so an empty
    ///      bitmap means the signer published one and not that a length byte was misread.
    /// @param rdata The rdata of an NSEC3 record.
    /// @param dnstype The type number to look for.
    /// @return True if the bitmap lists the type.
    function rdataHasType(
        bytes memory rdata,
        uint16 dnstype
    ) internal pure returns (bool) {
        NSEC3Record memory record = readRdata(rdata);
        if (record.bitmapOffset == rdata.length) {
            return false;
        }
        return NSECUtils.hasType(rdata, record.bitmapOffset, dnstype);
    }

    // --------------------------------------------------------------- base32hex, decode only

    /// @notice The owner hash of an NSEC3 record, decoded from its owner name.
    /// @dev The owner name is the base32hex form of the hash, prepended as a single label to
    ///      the zone name, per RFC 5155 section 3. This reads the first label and decodes it.
    ///
    ///      It does not check the rest of the name against the zone. A caller must hold the
    ///      record to the zone that signed it, using the RRSIG signer name that the oracle
    ///      authenticates. `RootAbsencePredicate.ProofNotFromRoot` is the shape of that check.
    /// @param ownerName The owner name of an NSEC3 record, in wire format.
    /// @return The 20-byte owner hash.
    function ownerHash(
        bytes memory ownerName
    ) internal pure returns (bytes20) {
        // Reverts `MalformedName` for a name that is not well formed, uncompressed wire
        // format, which also guarantees that byte 0 exists.
        NSECUtils.requireWireName(ownerName);
        uint256 labelLength = uint8(ownerName[0]);
        if (labelLength != OWNER_LABEL_LENGTH) {
            revert InvalidHashLabelLength(labelLength);
        }
        return _decodeHashLabelAt(ownerName, 1);
    }

    /// @notice Decodes one base32hex NSEC3 hash label.
    /// @dev RFC 4648 section 7, lowercase and unpadded, as RFC 5155 section 1.3 uses it.
    ///      The alphabet is `0123456789abcdefghijklmnopqrstuv`.
    ///
    ///      The label must be exactly 32 characters. 32 characters carry 160 bits, which is the
    ///      whole of a SHA-1 digest with no leftover bits, so there is no partial final group
    ///      to check for non-canonical padding and no other length an NSEC3 label can have.
    ///
    ///      **Uppercase reverts rather than being folded**, although DNS names are
    ///      case-insensitive and `A` and `a` are the same label on the wire. Every zone
    ///      publishes the lowercase form. This mirrors `NSECUtils.requireCanonicalName`, which
    ///      refuses an uppercase name instead of rewriting it, so that the caller and the
    ///      reader cannot disagree about which exact bytes were read. The refusal direction is
    ///      safe: it declines to decode, so it declines to prove.
    ///
    ///      **There is no encoder here and none is needed.** The next-hashed-owner field inside
    ///      the rdata is the raw hash, not base32hex, so every comparison this library makes is
    ///      between a decoded owner hash, a raw next-hashed-owner and a freshly computed
    ///      `hashName`. Nothing ever has to be re-encoded to be compared.
    /// @param label The 32 base32hex characters, without the DNS length byte.
    /// @return The 20-byte hash.
    function decodeHashLabel(
        bytes memory label
    ) internal pure returns (bytes20) {
        if (label.length != OWNER_LABEL_LENGTH) {
            revert InvalidHashLabelLength(label.length);
        }
        return _decodeHashLabelAt(label, 0);
    }

    /// @dev Decodes the 32 base32hex characters at `offset`. The caller has already checked
    ///      that they are there.
    function _decodeHashLabelAt(
        bytes memory data,
        uint256 offset
    ) private pure returns (bytes20) {
        uint256 accumulator;
        for (uint256 i; i < OWNER_LABEL_LENGTH; ++i) {
            accumulator =
                (accumulator << 5) |
                uint256(_base32HexDigit(data[offset + i]));
        }
        // 32 groups of 5 bits is 160 bits exactly, so this narrowing drops nothing.
        return bytes20(uint160(accumulator));
    }

    /// @dev One base32hex character to its 5-bit value. `0` to `9` are 0 to 9 and `a` to `v`
    ///      are 10 to 31. Anything else, uppercase included, reverts.
    function _base32HexDigit(
        bytes1 character
    ) private pure returns (uint256) {
        uint8 value = uint8(character);
        if (value >= 0x30 && value <= 0x39) {
            return uint256(value) - 0x30;
        }
        if (value >= 0x61 && value <= 0x76) {
            return uint256(value) - 0x61 + 10;
        }
        revert InvalidBase32HexChar(character);
    }
}
