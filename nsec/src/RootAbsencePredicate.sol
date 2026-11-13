//SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {DNSSEC} from "./contracts/dnssec-oracle/DNSSEC.sol";
import {RRUtils} from "./contracts/dnssec-oracle/RRUtils.sol";
import {BytesUtils} from "./contracts/utils/BytesUtils.sol";
import {NSECUtils} from "./NSECUtils.sol";

/// @title RootAbsencePredicate
/// @notice Reads root-signed NSEC records and reports whether the DNS root delegates a
///         top-level domain.
/// @dev The signal is the absence of NS, not the absence of DS. `aq.` and `zw.` are live
///      delegations with no DS. A predicate keyed on DS absence releases working country code
///      top-level domains. This contract never reads DS.
///
///      Absence has two forms, and the root returns the form that applies.
///
///      1. The name is not in the zone. One record covers it, either through an ordinary gap or
///         through the record that closes the zone. ICANN removed the delegation of `.doosan`
///         on 2 February 2016, and a live root query for it gives NXDOMAIN with the
///         `domains. NSEC dot.` record.
///      2. The name is in the zone, and its own type bitmap does not list NS.
///
///      This contract holds no state and no roles. The oracle address is immutable. It reads
///      and reports. The authority to act on the report belongs to the consumer.
///
///      **Time.** Every entry point validates the signatures at `block.timestamp`. No entry
///      point takes a time from the caller. A release decision acts now, so the only sound
///      validation time is now. A captured proof therefore stops working when its RRSIG
///      expires, which for the root is about 13 days. An earlier revision took an `at`
///      parameter and passed it straight to the oracle. A caller could then present a
///      November 2026 proof at a 2031 block and get `proven` for a name that the root had
///      delegated again in the years between, which releases a working name. The trust
///      anchors are KSK-2017 and KSK-2024, so the exposed range covered every top-level
///      domain delegated since October 2018. The parameter is gone, not bounded, because its
///      only sound value was `block.timestamp`. For an answer as of an earlier time, call at
///      an earlier block, where the chain supplies the time. A test sets the time with
///      `vm.warp`, which exercises the same path that a consumer uses.
///
///      The ENS DNSSEC oracle is unchanged. Needing no upstream change is the point of this.
///
///      Cost, measured with `gasleft()` against an already deployed oracle, on the `zw.` and
///      apex fixtures of 11 November 2026: 281k gas for a call carrying one proof, and 552k for
///      two. The oracle's own verification of one DNSKEY set plus one NSEC set is 234k of that.
///      Deployment is 1.54M. An earlier revision of this comment said 2.67M for each record.
///      That figure is the whole-test total of the measurement tests, which deploy `DNSSECImpl`
///      and `RSASHA256Algorithm` inside the test.
contract RootAbsencePredicate {
    using RRUtils for *;
    using BytesUtils for bytes;

    /// @notice How the question was answered.
    /// @dev `Unproven` means that no supplied record decides the question.
    ///      `NoName` means that a record denies that the name exists in the root zone.
    ///      `NoNsBit` means that the name is in the zone, and its type bitmap has no NS.
    ///      `Delegated` means that the name is in the zone with NS, so the root still
    ///      delegates it. `Delegated` outranks the other outcomes and cannot be overturned by
    ///      another record in the same call.
    enum Route {
        Unproven,
        NoName,
        NoNsBit,
        Delegated
    }

    /// @notice The result of reading the supplied proofs.
    /// @param proven True only for `NoName` and `NoNsBit`.
    /// @param route How the question was answered.
    /// @param owner The owner name of the record that decided it.
    /// @param next The next-owner name of the record that decided it.
    /// @param inception The RRSIG inception of the record that decided it. A consumer that
    ///        stores a release can use this to refuse an older proof later.
    /// @param apexWildcardDenied True if a supplied record denies the wildcard `*.` at the root
    ///        apex. Reported, not required. See `proveNoDelegation`.
    /// @param records The number of distinct NSEC records read. A record sent twice counts
    ///        once. Records are compared by the bytes the oracle authenticated.
    struct Result {
        bool proven;
        Route route;
        bytes owner;
        bytes next;
        uint32 inception;
        bool apexWildcardDenied;
        uint256 records;
    }

    uint16 internal constant CLASS_INET = 1;

    /// @dev The deepest record name this contract reads. The root's NSEC chain holds the apex,
    ///      with no labels, and one record for each top-level domain, with one label. Nothing
    ///      deeper can appear in it, because a name below a delegation is not authoritative in
    ///      the parent zone and is not in the parent's NSEC chain. Measured on 12 November 2026
    ///      against 198.41.0.4: `net. NSEC netbank.` skips `root-servers.net.`, and
    ///      `arpa. NSEC art.` skips `in-addr.arpa.`.
    uint256 internal constant MAX_RECORD_LABELS = 1;

    /// @notice The DNSSEC oracle. Mainnet `0x668ad4467129d49ECbe6274d95197797C0E262AA` already
    ///         has algorithm 8, digest 2, and the current root trust anchors. No redeploy.
    DNSSEC public immutable oracle;

    /// @dev The oracle address is zero.
    error OracleRequired();

    /// @dev Proof `index` holds no signed sets. An empty chain must not reach the oracle.
    ///      `DNSSEC.verifyRRSet` answers an empty chain with the trust anchors themselves,
    ///      which are DS records, and a caller that iterated that answer would be reading
    ///      unsigned configuration as if it were a proof.
    error EmptyProof(uint256 index);

    /// @dev The last signed set in proof `index` does not cover type NSEC.
    error ProofNotNSEC(uint256 index, uint16 dnstype);

    /// @dev Class is not IN.
    error ProofNotClassINET(uint256 index, uint16 class);

    /// @dev The RRSIG signer name of proof `index` is not the root. Only the root zone can
    ///      answer for its own delegations. Any other zone signs names below a delegation, and
    ///      the closing record of such a zone sorts below a top-level domain, so it would
    ///      otherwise appear to cover one.
    error ProofNotFromRoot(uint256 index, bytes signerName);

    /// @dev The queried name is not one label below the root.
    error NotATopLevelName(bytes name);

    /// @dev A record name in proof `index` is more than one label below the root. Such a record
    ///      cannot come from the root's NSEC chain, and its span is not a span of top-level
    ///      names. `a.com. NSEC com.` would read as a zone-closing record and cover every
    ///      top-level domain above `com.`, and `com. NSEC a.bbb.` would read the same way.
    error RecordNameTooDeep(uint256 index, bytes name);

    /// @dev Proof `index` does not hold exactly one NSEC record. One owner name has exactly one
    ///      NSEC record, per RFC 4035 section 2.3. Two records under one signature would share
    ///      an owner name and could carry different next-owner names, and the second could then
    ///      widen the span of the first.
    error ProofNotOneRecord(uint256 index, uint256 records);

    /// @dev `block.timestamp` does not fit in the `uint32` that the oracle compares against.
    ///      `DNSSECImpl.verifyRRSetAt` narrows its time argument to `uint32`, so a block time
    ///      above that range aliases: `t + 2**32` narrows to `t`, and a November 2026 proof
    ///      would verify at a block in 2106 or later. Refuse instead of aliasing.
    ///
    ///      Inside the `uint32` range the narrowing is the identity, so the guard belongs at
    ///      `2**32` and not lower. Above `2**31` the oracle's own window test is already
    ///      strange, because `RRUtils.serialNumberGte` is RFC 1982 serial arithmetic in
    ///      `int32` and `int32(4294967295)` is `-1`: a 2026 expiration then reads as not yet
    ///      reached, so the refusal at `type(uint32).max` arrives as `SignatureNotValidYet`
    ///      rather than `SignatureExpired`. Either way the proof is refused, and that is the
    ///      oracle's behaviour, not this contract's.
    error TimestampOutOfRange(uint256 timestamp);

    /// @dev `requireNoDelegation` found no proof of absence.
    error AbsenceNotProven(bytes name, Route route);

    /// @param _oracle The DNSSEC oracle to verify against.
    constructor(DNSSEC _oracle) {
        if (address(_oracle) == address(0)) {
            revert OracleRequired();
        }
        oracle = _oracle;
    }

    // ----------------------------------------------------------------------- the entry point

    /// @notice Reads an array of independent root-signed NSEC proofs, and reports whether the
    ///         root delegates `name`.
    /// @dev Each element of `proofs` is a complete chain from the trust anchors to one NSEC
    ///      record. Each chain gets its own oracle verification. Two NSEC records never share
    ///      one chain, because `verifyRRSetAt` folds its input and verifies each set against
    ///      the set before it. An NSEC set cannot act as the proof for the set that follows it,
    ///      so a call that carries two sibling NSEC records is refused by the oracle. For an
    ///      absent name the root returns two records, the covering record and the root's own
    ///      `. NSEC aaa.` record, and they are two proofs here.
    ///
    ///      The verification call is `verifyRRSetAt`, once for each proof. The returned signed
    ///      set carries the authenticated RRSIG signer name, and this contract requires that
    ///      name to be the root. `DNSSEC.verifyRRSet` returns the record bytes only, and the
    ///      signer name is not in them.
    ///
    ///      The queried name must be one label below the root. The span of an NSEC record at a
    ///      delegation point does not deny names below that delegation, so a deeper name needs
    ///      a proof from a deeper zone, which this contract does not read. Each record name is
    ///      held to the same depth, and each proof must hold exactly one NSEC record. Neither
    ///      shape can come from the root. Both are refused rather than ignored, so that an
    ///      input the root cannot have produced fails where it is read.
    ///
    ///      A record that neither matches nor covers the name is read and ignored. It is not an
    ///      error, because the root returns records the caller did not ask about.
    ///
    ///      `apexWildcardDenied` is reported and is not required for `proven`. RFC 4035 section
    ///      5.4 asks a complete NXDOMAIN proof to deny the wildcard as well. A wildcard cannot
    ///      synthesize a delegation, per RFC 4592 section 4.2, so it cannot create the NS that
    ///      this predicate asks about. A consumer that wants the complete form can require the
    ///      flag.
    /// @param name The queried name, in wire format, lowercase, one label, such as `doosan.`.
    /// @param proofs One chain for each NSEC record.
    /// @return result What the records say, as of `block.timestamp`.
    function proveNoDelegation(
        bytes memory name,
        DNSSEC.RRSetWithSignature[][] memory proofs
    ) public view returns (Result memory result) {
        uint256 at = block.timestamp;
        if (at > type(uint32).max) {
            revert TimestampOutOfRange(at);
        }
        if (NSECUtils.requireCanonicalName(name) != 1) {
            revert NotATopLevelName(name);
        }
        bytes memory wildcard = NSECUtils.wildcardName(NSECUtils.ROOT_NAME);
        // One record for each proof, so one fingerprint slot for each proof.
        bytes32[] memory fingerprints = new bytes32[](proofs.length);

        for (uint256 i; i < proofs.length; ++i) {
            DNSSEC.RRSetWithSignature[] memory chain = proofs[i];
            if (chain.length == 0) {
                revert EmptyProof(i);
            }

            // One verification for each record.
            RRUtils.SignedSet[] memory sets = oracle.verifyRRSetAt(chain, at);
            RRUtils.SignedSet memory signedSet = sets[sets.length - 1];

            if (signedSet.typeCovered != NSECUtils.DNSTYPE_NSEC) {
                revert ProofNotNSEC(i, signedSet.typeCovered);
            }
            if (!signedSet.signerName.equals(NSECUtils.ROOT_NAME)) {
                revert ProofNotFromRoot(i, signedSet.signerName);
            }

            // Count distinct records, not reads. The same record sent twice is one record.
            // The fingerprint is over the bytes the oracle authenticated.
            bytes32 fingerprint = keccak256(signedSet.data);
            bool seen;
            for (uint256 j; j < result.records; ++j) {
                if (fingerprints[j] == fingerprint) {
                    seen = true;
                    break;
                }
            }
            if (!seen) {
                fingerprints[result.records] = fingerprint;
                result.records += 1;
            }

            uint256 inProof;
            for (
                RRUtils.RRIterator memory iter = RRUtils.iterateRRs(
                    signedSet.data,
                    0
                );
                !iter.done();
                iter.next()
            ) {
                // The oracle already holds every record in a set to one name, one type, and
                // class IN. These two checks keep this contract's own guarantee local.
                if (iter.dnstype != NSECUtils.DNSTYPE_NSEC) {
                    revert ProofNotNSEC(i, iter.dnstype);
                }
                if (iter.class != CLASS_INET) {
                    revert ProofNotClassINET(i, iter.class);
                }
                inProof += 1;

                bytes memory owner = iter.name();
                if (NSECUtils.requireWireName(owner) > MAX_RECORD_LABELS) {
                    revert RecordNameTooDeep(i, owner);
                }
                bytes memory rdata = iter.rdata();
                (bytes memory next, uint256 bitmapOffset) = NSECUtils
                    .nextOwnerName(rdata);
                if (NSECUtils.requireWireName(next) > MAX_RECORD_LABELS) {
                    revert RecordNameTooDeep(i, next);
                }

                if (RRUtils.compareNames(owner, name) == 0) {
                    // The name is in the root zone. Its own bitmap is the answer.
                    bool nsPresent = NSECUtils.hasType(
                        rdata,
                        bitmapOffset,
                        NSECUtils.DNSTYPE_NS
                    );
                    _decide(
                        result,
                        nsPresent ? Route.Delegated : Route.NoNsBit,
                        owner,
                        next,
                        signedSet.inception
                    );
                } else if (
                    NSECUtils.coversName(
                        owner,
                        next,
                        name,
                        signedSet.signerName
                    )
                ) {
                    // The name is not in the root zone at all.
                    _decide(
                        result,
                        Route.NoName,
                        owner,
                        next,
                        signedSet.inception
                    );
                }

                if (
                    !result.apexWildcardDenied &&
                    NSECUtils.coversName(
                        owner,
                        next,
                        wildcard,
                        signedSet.signerName
                    )
                ) {
                    result.apexWildcardDenied = true;
                }
            }

            // One signature covers one NSEC record. A second record under the same signature
            // shares the owner name of the first and can carry a different next-owner name,
            // which would widen the span. The root cannot publish that shape.
            if (inProof != 1) {
                revert ProofNotOneRecord(i, inProof);
            }
        }

        result.proven =
            result.route == Route.NoName ||
            result.route == Route.NoNsBit;
    }

    /// @notice `proveNoDelegation`, and a revert if the records do not prove absence.
    /// @dev For a consumer that wants the failure to stop the transaction.
    /// @param name The queried name, in wire format.
    /// @param proofs One chain for each NSEC record.
    /// @return result What the records say.
    function requireNoDelegation(
        bytes memory name,
        DNSSEC.RRSetWithSignature[][] memory proofs
    ) external view returns (Result memory result) {
        result = proveNoDelegation(name, proofs);
        if (!result.proven) {
            revert AbsenceNotProven(name, result.route);
        }
    }

    // -------------------------------------------------- the two pure functions, for direct use

    /// @notice The comparator, read in the root zone. See `NSECUtils.coversName`.
    /// @dev Public and pure, so that a test can call it with any three names, and so that it
    ///      can be fuzzed. The zone apex is pinned to the root, which is the only zone this
    ///      contract reads. A record from another zone is reported as covering nothing, which
    ///      is the safe direction for a helper. Use `coversNameInZone` for another zone.
    /// @param owner The owner name of the NSEC record, in wire format.
    /// @param next The next-owner name from the record's rdata, in wire format.
    /// @param name The queried name, in wire format.
    /// @return True if the record denies that `name` exists in the root zone.
    function coversName(
        bytes memory owner,
        bytes memory next,
        bytes memory name
    ) public pure returns (bool) {
        return NSECUtils.coversName(owner, next, name, NSECUtils.ROOT_NAME);
    }

    /// @notice The comparator, read in any zone. See `NSECUtils.coversName`.
    /// @dev The general form, so that the apex rule itself can be fuzzed. The entry point uses
    ///      this form with the RRSIG signer name that the oracle authenticated.
    /// @param owner The owner name of the NSEC record, in wire format.
    /// @param next The next-owner name from the record's rdata, in wire format.
    /// @param name The queried name, in wire format.
    /// @param zoneApex The apex of the zone that signed the record, in wire format.
    /// @return True if the record denies that `name` exists in that zone.
    function coversNameInZone(
        bytes memory owner,
        bytes memory next,
        bytes memory name,
        bytes memory zoneApex
    ) public pure returns (bool) {
        return NSECUtils.coversName(owner, next, name, zoneApex);
    }

    /// @notice The type bitmap reader. See `NSECUtils.hasType`.
    /// @dev Public and pure, so that a synthetic bitmap can be read directly. A name that is
    ///      present in the root with the NS bit clear has no live fixture, so a synthetic
    ///      bitmap is the only way to test that case.
    /// @param typeBitmap The window blocks, per RFC 4034 section 4.1.2.
    /// @param dnstype The type number to look for.
    /// @return True if the bitmap lists the type.
    function hasType(
        bytes memory typeBitmap,
        uint16 dnstype
    ) public pure returns (bool) {
        return NSECUtils.hasType(typeBitmap, 0, dnstype);
    }

    /// @notice Reads the type bitmap of a whole NSEC rdata.
    /// @param rdata The rdata of an NSEC record, which is the next-owner name then the bitmap.
    /// @param dnstype The type number to look for.
    /// @return True if the bitmap lists the type.
    function rdataHasType(
        bytes memory rdata,
        uint16 dnstype
    ) public pure returns (bool) {
        return NSECUtils.rdataHasType(rdata, dnstype);
    }

    /// @notice Reads the next-owner name from the rdata of an NSEC record.
    /// @param rdata The rdata of an NSEC record.
    /// @return next The next-owner name, in wire format.
    /// @return bitmapOffset The offset of the first window block.
    function nextOwnerName(
        bytes memory rdata
    ) public pure returns (bytes memory next, uint256 bitmapOffset) {
        return NSECUtils.nextOwnerName(rdata);
    }

    // ------------------------------------------------------------------------------- internal

    /// @dev Keeps the strongest outcome seen. `Delegated` is a veto. A record that shows NS on
    ///      the name itself cannot be overturned by a record that covers the name.
    function _decide(
        Result memory result,
        Route route,
        bytes memory owner,
        bytes memory next,
        uint32 inception
    ) private pure {
        if (uint8(route) <= uint8(result.route)) {
            return;
        }
        result.route = route;
        result.owner = owner;
        result.next = next;
        result.inception = inception;
    }
}
