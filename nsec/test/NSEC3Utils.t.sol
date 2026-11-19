// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {DNSSEC} from "../src/contracts/dnssec-oracle/DNSSEC.sol";
import {DNSSECImpl} from "../src/contracts/dnssec-oracle/DNSSECImpl.sol";
import {RRUtils} from "../src/contracts/dnssec-oracle/RRUtils.sol";
import {BytesUtils} from "../src/contracts/utils/BytesUtils.sol";
import {NSECUtils} from "../src/NSECUtils.sol";
import {NSEC3Utils} from "../src/NSEC3Utils.sol";
import {NSEC3Fixtures} from "./NSEC3Fixtures.sol";

/// Not a test contract. The external surface of `NSEC3Utils`, so that `try/catch` can observe
/// the revert of an otherwise-internal library call. Same device as
/// `RootAbsencePredicate`'s public pure functions, which `NSECUtilsMalformedBitmap.t.sol`
/// uses for `NSECUtils`. The predicate that will hold these for real is pass 2 and is not in
/// this change.
contract NSEC3UtilsHarness {
    function ownerHash(bytes memory ownerName) external pure returns (bytes20) {
        return NSEC3Utils.ownerHash(ownerName);
    }

    function decodeHashLabel(bytes memory label) external pure returns (bytes20) {
        return NSEC3Utils.decodeHashLabel(label);
    }

    function hashName(
        bytes memory name,
        bytes memory salt,
        uint256 iterations
    ) external pure returns (bytes20) {
        return NSEC3Utils.hashName(name, salt, iterations);
    }

    function readRdata(
        bytes memory rdata
    ) external pure returns (NSEC3Utils.NSEC3Record memory) {
        return NSEC3Utils.readRdata(rdata);
    }

    function coversHash(
        bytes20 ownerHashValue,
        bytes20 nextHashValue,
        bytes20 nameHashValue
    ) external pure returns (bool) {
        return
            NSEC3Utils.coversHash(ownerHashValue, nextHashValue, nameHashValue);
    }

    function recordCoversName(
        bytes memory ownerName,
        bytes memory rdata,
        bytes memory name
    ) external pure returns (bool) {
        return NSEC3Utils.recordCoversName(ownerName, rdata, name);
    }

    function recordMatchesName(
        bytes memory ownerName,
        bytes memory rdata,
        bytes memory name
    ) external pure returns (bool) {
        return NSEC3Utils.recordMatchesName(ownerName, rdata, name);
    }

    function rdataHasType(
        bytes memory rdata,
        uint16 dnstype
    ) external pure returns (bool) {
        return NSEC3Utils.rdataHasType(rdata, dnstype);
    }

    function isOptOut(uint8 flags) external pure returns (bool) {
        return NSEC3Utils.isOptOut(flags);
    }
}

/// `NSEC3Utils`'s own suite. Pass 1 of the NSEC3 work: the four primitives, with no predicate.
///
/// **Two sources of truth, and neither is this library.**
///
///   - `tools/mkhashvectors.py` self-checks 8 of 8 against RFC 5155 Appendix A and then prints
///     the hashes for the three captured zones. Every expected hash below is its output.
///   - `test/NSEC3Fixtures.sol` holds six real NSEC3 records captured on 19 November 2026, and
///     `test/NSEC3FixtureCheck.t.sol` proves all six validate through an unmodified
///     `DNSSECImpl`. Run that file first: a failure there is a bad fixture, not a bad reader.
///
/// Most tests here read the fixture bytes with `RRUtils.readSignedSet`, which parses without
/// verifying, so they keep working after the fixtures' RRSIGs expire on 1 December 2026. The
/// one test that drives the real oracle is marked, and it expires with the fixtures.
contract NSEC3UtilsTest is NSEC3Fixtures {
    using RRUtils for *;
    using BytesUtils for bytes;

    NSEC3UtilsHarness internal harness = new NSEC3UtilsHarness();

    // --------------------------------------------------- RFC 5155 Appendix A, the eight vectors

    bytes internal constant RFC_SALT = hex"aabbccdd";
    uint256 internal constant RFC_ITERATIONS = 12;

    bytes internal constant A0_NAME = hex"076578616d706c6500"; // example.
    bytes20 internal constant A0_HASH =
        hex"065368abeed7ec6e9feba96b8c8bc3e8b791f716";
    bytes internal constant A0_LABEL = "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom";

    bytes internal constant A1_NAME = hex"0161076578616d706c6500"; // a.example.
    bytes20 internal constant A1_HASH =
        hex"196dd8c3306783a8190f52c262d2b7e5e836e7f5";
    bytes internal constant A1_LABEL = "35mthgpgcu1qg68fab165klnsnk3dpvl";

    bytes internal constant A2_NAME = hex"026169076578616d706c6500"; // ai.example.
    bytes20 internal constant A2_HASH =
        hex"84dda71446cd56f0c116a57254baef69d09bce12";
    bytes internal constant A2_LABEL = "gjeqe526plbf1g8mklp59enfd789njgi";

    bytes internal constant A3_NAME = hex"036e7331076578616d706c6500"; // ns1.example.
    bytes20 internal constant A3_HASH =
        hex"174eb2409fe28bcb4887a1836f957f0a8425e27b";
    bytes internal constant A3_LABEL = "2t7b4g4vsa5smi47k61mv5bv1a22bojr";

    bytes internal constant A4_NAME = hex"036e7332076578616d706c6500"; // ns2.example.
    bytes20 internal constant A4_HASH =
        hex"d0093a31dfd7ede41760091876d16a1a3009c8bb";
    bytes internal constant A4_LABEL = "q04jkcevqvmu85r014c7dkba38o0ji5r";

    bytes internal constant A5_NAME = hex"0177076578616d706c6500"; // w.example.
    bytes20 internal constant A5_HASH =
        hex"a23cd75bf90cc4f3ba069b979e04ffc8ee891511";
    bytes internal constant A5_LABEL = "k8udemvp1j2f7eg6jebps17vp3n8i58h";

    bytes internal constant A6_NAME = hex"012a0177076578616d706c6500"; // *.w.example.
    bytes20 internal constant A6_HASH =
        hex"d946bd1d8c17bf6f2dfe2e196b1b2edf13da25d7";
    bytes internal constant A6_LABEL = "r53bq7cc2uvmubfu5ocmm6pers9tk9en";

    bytes internal constant A7_NAME = hex"01780177076578616d706c6500"; // x.w.example.
    bytes20 internal constant A7_HASH =
        hex"593d6419d08c5bc35dca0a4dcb7ed5c131be2525";
    bytes internal constant A7_LABEL = "b4um86eghhds6nea196smvmlo4ors995";

    // -------------------------------------- the three captured zones, from tools/mkhashvectors.py

    /// @dev `desi`, salt none, 0 iterations.
    bytes20 internal constant DESI_ENS_HASH =
        hex"24087ff374e5e9ed0c36c526f79717876a02a2cb";
    bytes20 internal constant DESI_APEX_HASH =
        hex"2a7c80ce15a552767f6173d502b5bcb1cd9bf75f";
    bytes internal constant DESI_WILDCARD = hex"012a046465736900"; // *.desi.
    bytes20 internal constant DESI_WILDCARD_HASH =
        hex"afd11a89995cdb435cfa4ca5c21cd24d4b4908cd";

    /// @dev `firmdale`, salt abbacafe, 20 iterations.
    bytes internal constant FIRMDALE_SALT = hex"abbacafe";
    uint256 internal constant FIRMDALE_ITERATIONS = 20;
    bytes20 internal constant FIRMDALE_ENS_HASH =
        hex"1a5d65c05d68360110db682feb01bb8102d82a87";
    bytes20 internal constant FIRMDALE_APEX_HASH =
        hex"d4aaf321d0be6248b2f93a433b76cd9bdd56173e";
    bytes internal constant FIRMDALE_WILDCARD = hex"012a086669726d64616c6500"; // *.firmdale.
    bytes20 internal constant FIRMDALE_WILDCARD_HASH =
        hex"6e723733aca405ee2df665f26e9eeb6bfcdcd726";

    /// @dev `nowruz`, salt none, 0 iterations.
    bytes20 internal constant NOWRUZ_ENS_HASH =
        hex"2acc2a61ccc55898efd2a8c9620289fc68851b09";
    bytes20 internal constant NOWRUZ_APEX_HASH =
        hex"b4f6a95c4101e77fcbb6a31e915ac7cb315c34b8";
    bytes internal constant NOWRUZ_WILDCARD = hex"012a066e6f7772757a00"; // *.nowruz.
    bytes20 internal constant NOWRUZ_WILDCARD_HASH =
        hex"b9c0c7d58c6bec1cea2d07e83d04b302d08417c6";

    /// @dev The owner hash each fixture record documents in its own `@dev` line. Read here from
    ///      the base32hex owner label, which is what proves the decoder.
    bytes20 internal constant DESI_0_OWNER =
        hex"18c299c9b61df3f7d57a1d80be708c88842057fa";
    bytes20 internal constant DESI_0_NEXT =
        hex"2a7c80ce15a552767f6173d502b5bcb1cd9bf75f";
    bytes20 internal constant DESI_1_OWNER =
        hex"2a7c80ce15a552767f6173d502b5bcb1cd9bf75f";
    bytes20 internal constant DESI_1_NEXT =
        hex"312c0c40bb8c5e0fb9e8bfcc3e5175e7b825c47e";
    bytes20 internal constant DESI_2_OWNER =
        hex"a1df5edfef29be98421c528691cfca9c2940ef25";
    bytes20 internal constant DESI_2_NEXT =
        hex"b58b20176ada8936751378a25d041a959d6f0de2";
    bytes20 internal constant FIRMDALE_0_OWNER =
        hex"d4aaf321d0be6248b2f93a433b76cd9bdd56173e";
    bytes20 internal constant FIRMDALE_0_NEXT =
        hex"d4aaf321d0be6248b2f93a433b76cd9bdd56173e";
    bytes20 internal constant NOWRUZ_0_OWNER =
        hex"083f51b851f9f36354d11f89eeaa2c25ddbb1cbb";
    bytes20 internal constant NOWRUZ_0_NEXT =
        hex"30e66d4c38d3499015e870fcde119a29c42039f2";
    bytes20 internal constant NOWRUZ_1_OWNER =
        hex"b4f6a95c4101e77fcbb6a31e915ac7cb315c34b8";
    bytes20 internal constant NOWRUZ_1_NEXT =
        hex"d1aa93761ffd0e988441654d994dd8570e15682c";

    // ------------------------------------------------------------------------------ helpers

    /// @dev The owner name and rdata of the one NSEC3 record inside a captured set.
    ///      `readSignedSet` parses without verifying, so this is insensitive to the fixture
    ///      expiry. `NSEC3FixtureCheck.t.sol` is the file that attests the same bytes.
    function _rr(
        bytes memory signedSet
    ) internal pure returns (bytes memory owner, bytes memory rdata) {
        RRUtils.SignedSet memory set = RRUtils.readSignedSet(signedSet);
        require(
            set.typeCovered == NSEC3Utils.DNSTYPE_NSEC3,
            "fixture does not cover NSEC3"
        );
        RRUtils.RRIterator memory iter = RRUtils.iterateRRs(set.data, 0);
        require(!iter.done(), "fixture holds no resource record");
        owner = iter.name();
        rdata = iter.rdata();
    }

    /// @dev Builds one NSEC3 rdata, per RFC 5155 section 3.2, so that a shape no live zone
    ///      publishes can still be read.
    function _rdata(
        uint8 algorithm,
        uint8 flags,
        uint16 iterations,
        bytes memory salt,
        uint8 hashLength,
        bytes memory nextHashedOwner,
        bytes memory bitmap
    ) internal pure returns (bytes memory) {
        return
            abi.encodePacked(
                algorithm,
                flags,
                iterations,
                uint8(salt.length),
                salt,
                hashLength,
                nextHashedOwner,
                bitmap
            );
    }

    function _selector(
        bytes memory reason
    ) internal pure returns (bytes4 sel) {
        require(reason.length >= 4, "revert reason too short to carry a selector");
        assembly {
            sel := mload(add(reason, 32))
        }
    }

    /// @dev The rule you get by porting `NSECUtils.coversName` to hashes: its zone-closing
    ///      branch is keyed on `next == zoneApex`, there is no apex hash in an NSEC3 chain, so
    ///      the branch is unreachable and only the ordinary gap survives. Used to show which
    ///      fixtures the port would break. See `test_Hazard1_*`.
    function _portedNsecRule(
        bytes20 ownerHashValue,
        bytes20 nextHashValue,
        bytes20 nameHashValue
    ) internal pure returns (bool) {
        return
            uint160(nameHashValue) > uint160(ownerHashValue) &&
            uint160(nameHashValue) < uint160(nextHashValue);
    }

    // ================================================ RFC 5155 Appendix A: the iterated hash

    /// The eight hash vectors of RFC 5155 Appendix A, salt `aabbccdd` and 12 iterations.
    /// `tools/mkhashvectors.py` self-checks against the same eight before printing anything
    /// else, so a failure here is this library and not the generator.
    function test_RFC5155AppendixA_EightHashVectors() external view {
        require(
            harness.hashName(A0_NAME, RFC_SALT, RFC_ITERATIONS) == A0_HASH,
            "RFC 5155 Appendix A: example."
        );
        require(
            harness.hashName(A1_NAME, RFC_SALT, RFC_ITERATIONS) == A1_HASH,
            "RFC 5155 Appendix A: a.example."
        );
        require(
            harness.hashName(A2_NAME, RFC_SALT, RFC_ITERATIONS) == A2_HASH,
            "RFC 5155 Appendix A: ai.example."
        );
        require(
            harness.hashName(A3_NAME, RFC_SALT, RFC_ITERATIONS) == A3_HASH,
            "RFC 5155 Appendix A: ns1.example."
        );
        require(
            harness.hashName(A4_NAME, RFC_SALT, RFC_ITERATIONS) == A4_HASH,
            "RFC 5155 Appendix A: ns2.example."
        );
        require(
            harness.hashName(A5_NAME, RFC_SALT, RFC_ITERATIONS) == A5_HASH,
            "RFC 5155 Appendix A: w.example."
        );
        require(
            harness.hashName(A6_NAME, RFC_SALT, RFC_ITERATIONS) == A6_HASH,
            "RFC 5155 Appendix A: *.w.example."
        );
        require(
            harness.hashName(A7_NAME, RFC_SALT, RFC_ITERATIONS) == A7_HASH,
            "RFC 5155 Appendix A: x.w.example."
        );
    }

    /// The same eight vectors read the other way: RFC 5155 Appendix A prints each hash as the
    /// base32hex owner label, so decoding the RFC's own label must give the RFC's own hash.
    /// This measures the decoder against the specification and not against the encoder, because
    /// there is no encoder.
    function test_RFC5155AppendixA_EightOwnerLabelsDecode() external view {
        require(harness.decodeHashLabel(A0_LABEL) == A0_HASH, "label: example.");
        require(harness.decodeHashLabel(A1_LABEL) == A1_HASH, "label: a.example.");
        require(harness.decodeHashLabel(A2_LABEL) == A2_HASH, "label: ai.example.");
        require(harness.decodeHashLabel(A3_LABEL) == A3_HASH, "label: ns1.example.");
        require(harness.decodeHashLabel(A4_LABEL) == A4_HASH, "label: ns2.example.");
        require(harness.decodeHashLabel(A5_LABEL) == A5_HASH, "label: w.example.");
        require(harness.decodeHashLabel(A6_LABEL) == A6_HASH, "label: *.w.example.");
        require(harness.decodeHashLabel(A7_LABEL) == A7_HASH, "label: x.w.example.");
    }

    /// An iteration count of zero is one hash, not none, per RFC 5155 section 5. The whole
    /// census rests on this: 1,222 of 1,308 zones publish zero.
    function test_ZeroIterationsIsOneHashOfTheNameAndSalt() external view {
        require(
            harness.hashName(DESI_QNAME, hex"", 0) == DESI_ENS_HASH,
            "zero iterations must still hash once"
        );
    }

    // ============================================ the three captured zones, against the generator

    /// `hash(_ens.desi.)`, `hash(_ens.firmdale.)` and `hash(_ens.nowruz.)`, each with its own
    /// zone's salt and iteration count, against `tools/mkhashvectors.py`.
    function test_ZoneQueryNameHashesMatchTheGenerator() external view {
        require(
            harness.hashName(DESI_QNAME, hex"", 0) == DESI_ENS_HASH,
            "hash(_ens.desi.)"
        );
        require(
            harness.hashName(
                FIRMDALE_QNAME,
                FIRMDALE_SALT,
                FIRMDALE_ITERATIONS
            ) == FIRMDALE_ENS_HASH,
            "hash(_ens.firmdale.)"
        );
        require(
            harness.hashName(NOWRUZ_QNAME, hex"", 0) == NOWRUZ_ENS_HASH,
            "hash(_ens.nowruz.)"
        );
    }

    /// The three apex hashes, which independently reproduce the fixtures' own owner hashes:
    /// hashing the apex name gives the same 20 bytes that decoding the apex record's base32hex
    /// owner label gives. Two unrelated paths, one answer, so neither the hash nor the decoder
    /// can be wrong on its own without this failing.
    function test_ApexHashesReproduceTheFixtureOwnerHashes() external view {
        (bytes memory desiOwner, ) = _rr(DESI_NSEC3_1_SET);
        require(
            harness.hashName(DESI_NAME, hex"", 0) == DESI_APEX_HASH &&
                harness.ownerHash(desiOwner) == DESI_APEX_HASH,
            "desi. apex hash must equal the decoded owner label of its own NSEC3 record"
        );

        (bytes memory firmdaleOwner, ) = _rr(FIRMDALE_NSEC3_0_SET);
        require(
            harness.hashName(
                FIRMDALE_NAME,
                FIRMDALE_SALT,
                FIRMDALE_ITERATIONS
            ) == FIRMDALE_APEX_HASH &&
                harness.ownerHash(firmdaleOwner) == FIRMDALE_APEX_HASH,
            "firmdale. apex hash must equal the decoded owner label of its own NSEC3 record"
        );

        (bytes memory nowruzOwner, ) = _rr(NOWRUZ_NSEC3_1_SET);
        require(
            harness.hashName(NOWRUZ_NAME, hex"", 0) == NOWRUZ_APEX_HASH &&
                harness.ownerHash(nowruzOwner) == NOWRUZ_APEX_HASH,
            "nowruz. apex hash must equal the decoded owner label of its own NSEC3 record"
        );
    }

    /// Every captured record's owner label decodes to the hash its fixture comment documents,
    /// and its next-hashed-owner field reads back raw. Six records, two fields each.
    function test_AllSixFixtureRecordsDecodeToTheirDocumentedHashes() external view {
        _assertRecord(DESI_NSEC3_0_SET, DESI_0_OWNER, DESI_0_NEXT, "desi 0");
        _assertRecord(DESI_NSEC3_1_SET, DESI_1_OWNER, DESI_1_NEXT, "desi 1");
        _assertRecord(DESI_NSEC3_2_SET, DESI_2_OWNER, DESI_2_NEXT, "desi 2");
        _assertRecord(
            FIRMDALE_NSEC3_0_SET,
            FIRMDALE_0_OWNER,
            FIRMDALE_0_NEXT,
            "firmdale 0"
        );
        _assertRecord(NOWRUZ_NSEC3_0_SET, NOWRUZ_0_OWNER, NOWRUZ_0_NEXT, "nowruz 0");
        _assertRecord(NOWRUZ_NSEC3_1_SET, NOWRUZ_1_OWNER, NOWRUZ_1_NEXT, "nowruz 1");
    }

    function _assertRecord(
        bytes memory signedSet,
        bytes20 wantOwner,
        bytes20 wantNext,
        string memory label
    ) internal view {
        (bytes memory owner, bytes memory rdata) = _rr(signedSet);
        require(
            harness.ownerHash(owner) == wantOwner,
            string.concat(label, ": owner label does not decode to its documented hash")
        );
        NSEC3Utils.NSEC3Record memory record = harness.readRdata(rdata);
        require(
            record.nextHashedOwner == wantNext,
            string.concat(label, ": next-hashed-owner does not match")
        );
        require(
            record.hashAlgorithm == NSEC3Utils.HASH_ALGORITHM_SHA1,
            string.concat(label, ": hash algorithm must be SHA-1")
        );
    }

    // ==================================================== hazard 1: the closing rule inverts

    /// **HAZARD 1. THE INVERTED CLOSING RULE. DO NOT MAKE THIS AGREE WITH `NSECUtils`.**
    ///
    /// `NSECUtils.coversName` rejects `next <= owner` as the zone-closing test and keys that
    /// branch on `next == zoneApex`, because in NSEC the shape `com. NSEC com.` released live
    /// names. For NSEC3 the rejected rule is the correct one: owner names are hashes, the chain
    /// is in hash order, and the apex has its own NSEC3 record somewhere inside that order
    /// rather than at the start, so there is no apex hash to key on. RFC 5155 section 7.1
    /// step 7 says the last record's next-hashed-owner is the first owner hash of the chain,
    /// which sorts at or below it.
    ///
    /// `firmdale` publishes exactly one NSEC3 record, `nexthash == ownerhash`, and
    /// `hash(_ens.firmdale.)` sorts BELOW the owner hash. Only the wrap-aware reading proves it
    /// absent. A future reader who "fixes" `coversHash` to match `NSECUtils.coversName` fails
    /// this test and no other.
    function test_Hazard1_InvertedClosingRule_FirmdaleSelfPointingRecordCoversAHashBelowItsOwner()
        external
        view
    {
        (bytes memory owner, bytes memory rdata) = _rr(FIRMDALE_NSEC3_0_SET);
        NSEC3Utils.NSEC3Record memory record = harness.readRdata(rdata);

        require(
            harness.ownerHash(owner) == record.nextHashedOwner,
            "firmdale's one record must point at itself, or this test proves nothing"
        );
        require(
            uint160(FIRMDALE_ENS_HASH) < uint160(FIRMDALE_0_OWNER),
            "hash(_ens.firmdale.) must sort BELOW the owner hash, or this test proves nothing"
        );
        require(
            harness.recordCoversName(owner, rdata, FIRMDALE_QNAME),
            "INVERTED CLOSING RULE: next <= owner closes an NSEC3 chain and covers every hash "
            "above owner OR below next. This is the OPPOSITE of NSECUtils.coversName and it is "
            "correct here. Do not port the NSEC rule."
        );
    }

    /// The same hazard, stated as the delta. Porting `NSECUtils.coversName`'s rule breaks
    /// `firmdale` and nothing else: four of the six real covering cases are ordinary gaps and
    /// survive the port, and `firmdale`'s two do not.
    function test_Hazard1_ThePortedNsecRuleBreaksOnlyFirmdale() external view {
        // firmdale: the wrap-aware rule covers, the ported rule does not.
        require(
            harness.coversHash(
                FIRMDALE_0_OWNER,
                FIRMDALE_0_NEXT,
                FIRMDALE_ENS_HASH
            ) &&
                !_portedNsecRule(
                    FIRMDALE_0_OWNER,
                    FIRMDALE_0_NEXT,
                    FIRMDALE_ENS_HASH
                ),
            "firmdale _ens: the ported NSEC rule must be the one that fails"
        );
        require(
            harness.coversHash(
                FIRMDALE_0_OWNER,
                FIRMDALE_0_NEXT,
                FIRMDALE_WILDCARD_HASH
            ) &&
                !_portedNsecRule(
                    FIRMDALE_0_OWNER,
                    FIRMDALE_0_NEXT,
                    FIRMDALE_WILDCARD_HASH
                ),
            "firmdale wildcard: the ported NSEC rule must be the one that fails"
        );

        // The four ordinary gaps, where both rules agree. These are the tests that would still
        // pass after a bad port, which is why the two above carry the warning.
        require(
            harness.coversHash(DESI_0_OWNER, DESI_0_NEXT, DESI_ENS_HASH) &&
                _portedNsecRule(DESI_0_OWNER, DESI_0_NEXT, DESI_ENS_HASH),
            "desi _ens is an ordinary gap and both rules must cover it"
        );
        require(
            harness.coversHash(DESI_2_OWNER, DESI_2_NEXT, DESI_WILDCARD_HASH) &&
                _portedNsecRule(DESI_2_OWNER, DESI_2_NEXT, DESI_WILDCARD_HASH),
            "desi wildcard is an ordinary gap and both rules must cover it"
        );
        require(
            harness.coversHash(NOWRUZ_0_OWNER, NOWRUZ_0_NEXT, NOWRUZ_ENS_HASH) &&
                _portedNsecRule(NOWRUZ_0_OWNER, NOWRUZ_0_NEXT, NOWRUZ_ENS_HASH),
            "nowruz _ens is an ordinary gap and both rules must cover it"
        );
        require(
            harness.coversHash(
                NOWRUZ_1_OWNER,
                NOWRUZ_1_NEXT,
                NOWRUZ_WILDCARD_HASH
            ) &&
                _portedNsecRule(
                    NOWRUZ_1_OWNER,
                    NOWRUZ_1_NEXT,
                    NOWRUZ_WILDCARD_HASH
                ),
            "nowruz wildcard is an ordinary gap and both rules must cover it"
        );
    }

    /// `firmdale`'s one record does the work of three: it matches the closest encloser, which
    /// is the apex, and it covers both `_ens.firmdale.` and `*.firmdale.`. RFC 5155 sections
    /// 8.4 and 8.5 allow up to three records in a denial, and this zone needs one.
    function test_FirmdaleOneRecordMatchesTheApexAndCoversBothOtherNames() external view {
        (bytes memory owner, bytes memory rdata) = _rr(FIRMDALE_NSEC3_0_SET);
        require(
            harness.recordMatchesName(owner, rdata, FIRMDALE_NAME),
            "the record must match the apex, which is the closest encloser"
        );
        require(
            harness.recordCoversName(owner, rdata, FIRMDALE_QNAME),
            "the record must cover _ens.firmdale."
        );
        require(
            harness.recordCoversName(owner, rdata, FIRMDALE_WILDCARD),
            "the record must cover *.firmdale."
        );
    }

    /// `desi` returns three records and uses all three roles: one matches the apex, one covers
    /// `_ens.desi.`, one covers `*.desi.`. **The record count is not fixed** and a reader that
    /// assumes one is wrong.
    function test_DesiThreeRecordDenialUsesAllThreeRoles() external view {
        (bytes memory owner0, bytes memory rdata0) = _rr(DESI_NSEC3_0_SET);
        (bytes memory owner1, bytes memory rdata1) = _rr(DESI_NSEC3_1_SET);
        (bytes memory owner2, bytes memory rdata2) = _rr(DESI_NSEC3_2_SET);

        require(DESI_NSEC3_COUNT == 3, "desi must be the three-record zone");
        require(
            harness.recordCoversName(owner0, rdata0, DESI_QNAME),
            "record 0 must cover _ens.desi."
        );
        require(
            harness.recordMatchesName(owner1, rdata1, DESI_NAME),
            "record 1 must match the desi. apex"
        );
        require(
            harness.recordCoversName(owner2, rdata2, DESI_WILDCARD),
            "record 2 must cover *.desi."
        );
        // Each record decides only its own span.
        require(
            !harness.recordCoversName(owner1, rdata1, DESI_QNAME) &&
                !harness.recordCoversName(owner2, rdata2, DESI_QNAME),
            "no other desi record may cover _ens.desi."
        );
    }

    /// `nowruz` returns two records, and the apex record covers the wildcard as well. Three
    /// zones, three counts: three, one and two.
    function test_NowruzTwoRecordDenialCoversEnsAndTheWildcard() external view {
        (bytes memory owner0, bytes memory rdata0) = _rr(NOWRUZ_NSEC3_0_SET);
        (bytes memory owner1, bytes memory rdata1) = _rr(NOWRUZ_NSEC3_1_SET);

        require(NOWRUZ_NSEC3_COUNT == 2, "nowruz must be the two-record zone");
        require(
            harness.recordCoversName(owner0, rdata0, NOWRUZ_QNAME),
            "record 0 must cover _ens.nowruz."
        );
        require(
            harness.recordMatchesName(owner1, rdata1, NOWRUZ_NAME),
            "record 1 must match the nowruz. apex"
        );
        require(
            harness.recordCoversName(owner1, rdata1, NOWRUZ_WILDCARD),
            "record 1 must also cover *.nowruz."
        );
    }

    /// The comparator must not over-accept. An ordinary gap does not wrap, so a hash below the
    /// owner hash of a non-closing record is not covered by it. This is the NSEC3 form of the
    /// `com.` control on the `zw.` closing record in `RootAbsencePredicate.t.sol`.
    function test_OrdinaryGapDoesNotWrap() external view {
        require(
            !harness.coversHash(
                bytes20(hex"4000000000000000000000000000000000000000"),
                bytes20(hex"8000000000000000000000000000000000000000"),
                bytes20(hex"1000000000000000000000000000000000000000")
            ),
            "an ordinary gap must not cover a hash below its owner"
        );
        require(
            !harness.coversHash(
                bytes20(hex"4000000000000000000000000000000000000000"),
                bytes20(hex"8000000000000000000000000000000000000000"),
                bytes20(hex"f000000000000000000000000000000000000000")
            ),
            "an ordinary gap must not cover a hash above its next-hashed-owner"
        );
    }

    /// Neither endpoint is ever covered, in either branch. A name whose hash equals an owner
    /// hash exists: the caller must read that record's type bitmap instead.
    function test_ComparatorNeverCoversItsOwnEndpoints() external view {
        bytes20 low = bytes20(hex"2000000000000000000000000000000000000000");
        bytes20 high = bytes20(hex"9000000000000000000000000000000000000000");
        require(
            !harness.coversHash(low, high, low) &&
                !harness.coversHash(low, high, high),
            "ordinary gap must not cover its own endpoints"
        );
        require(
            !harness.coversHash(high, low, high) &&
                !harness.coversHash(high, low, low),
            "closing record must not cover its own endpoints"
        );
        require(
            !harness.coversHash(low, low, low),
            "a one-record chain must not cover its own owner hash"
        );
        require(
            harness.coversHash(low, low, high),
            "a one-record chain must cover every other hash"
        );
    }

    // ================================================= hazard 2: opt-out is accepted, not rejected

    /// **HAZARD 2. `flags = 1` IS ACCEPTED AND THE BIT IS IGNORED.**
    ///
    /// `desi`, `pars`, `shia`, `tci`, `wed` and `xn--mgbt3dhd` all publish NSEC3 records with
    /// Opt-Out set, which is six of the seven EBERO names this work exists for. A reader that
    /// refuses a non-zero flags byte fails on almost all of them, and the failure reads as a
    /// comparator bug. Opt-Out only narrows a span to "no signed delegation here", RFC 5155
    /// section 6, and `_ens.<tld>` is a TXT name and never a delegation.
    function test_Hazard2_OptOutRecordWithFlagsOneIsAccepted() external view {
        (bytes memory owner, bytes memory rdata) = _rr(DESI_NSEC3_0_SET);
        NSEC3Utils.NSEC3Record memory record = harness.readRdata(rdata);
        require(record.flags == 1, "the desi fixture must carry flags = 1");
        require(harness.isOptOut(record.flags), "flags = 1 must read as Opt-Out");
        require(
            harness.recordCoversName(owner, rdata, DESI_QNAME),
            "an opt-out record must still prove a TXT name absent"
        );

        (bytes memory firmdaleOwner, bytes memory firmdaleRdata) = _rr(
            FIRMDALE_NSEC3_0_SET
        );
        require(
            harness.readRdata(firmdaleRdata).flags == 1,
            "the firmdale fixture must carry flags = 1"
        );
        require(
            harness.recordCoversName(
                firmdaleOwner,
                firmdaleRdata,
                FIRMDALE_QNAME
            ),
            "an opt-out record must still prove a TXT name absent"
        );
    }

    /// `nowruz` is the one EBERO zone with Opt-Out clear, so the bit is read and not assumed.
    function test_NowruzHasOptOutClear() external view {
        (, bytes memory rdata) = _rr(NOWRUZ_NSEC3_0_SET);
        NSEC3Utils.NSEC3Record memory record = harness.readRdata(rdata);
        require(record.flags == 0, "the nowruz fixture must carry flags = 0");
        require(!harness.isOptOut(record.flags), "flags = 0 must not read as Opt-Out");
    }

    /// A flag RFC 5155 section 3.1.2 does not define is still refused, because that section
    /// requires it to be zero. The refusal declines a proof, so it cannot release a name.
    function test_UndefinedFlagBitIsRefused() external view {
        bytes memory rdata = _rdata(
            1,
            0x02,
            0,
            hex"",
            20,
            abi.encodePacked(DESI_0_NEXT),
            hex"0006200000000012"
        );
        (bool reverted, bytes4 sel) = _tryReadRdata(rdata);
        require(reverted, "CONTROL FAILED: an undefined flag bit must be refused");
        require(
            sel == NSEC3Utils.UndefinedNSEC3Flags.selector,
            "expected UndefinedNSEC3Flags"
        );
    }

    // ============================================================ parameters, read not assumed

    /// The parameters come from the record. `firmdale` is the counter-example to the modal set:
    /// 20 iterations and a four-byte salt, against the 1,222 zones that publish neither.
    function test_ParametersAreReadFromTheRecord() external view {
        (, bytes memory firmdaleRdata) = _rr(FIRMDALE_NSEC3_0_SET);
        NSEC3Utils.NSEC3Record memory firmdale = harness.readRdata(firmdaleRdata);
        require(firmdale.iterations == 20, "firmdale must declare 20 iterations");
        require(
            keccak256(firmdale.salt) == keccak256(FIRMDALE_SALT),
            "firmdale must declare salt abbacafe"
        );

        (, bytes memory desiRdata) = _rr(DESI_NSEC3_0_SET);
        NSEC3Utils.NSEC3Record memory desi = harness.readRdata(desiRdata);
        require(desi.iterations == 0, "desi must declare 0 iterations");
        require(desi.salt.length == 0, "desi must declare no salt");

        // Hashing firmdale's name with the modal parameters instead of its own gives the wrong
        // hash, which is what makes reading them from the record load-bearing.
        require(
            harness.hashName(FIRMDALE_QNAME, hex"", 0) != FIRMDALE_ENS_HASH,
            "the modal parameters must NOT reproduce firmdale's hash"
        );
    }

    // ============================================================ the iteration cap, 150 and 151

    /// 150 is the cap and is accepted. The result is also not the 12-iteration vector, which
    /// shows the loop really ran the count it was given.
    function test_IterationCount150Accepted() external view {
        bytes20 digest = harness.hashName(A0_NAME, RFC_SALT, 150);
        require(digest != bytes20(0), "150 iterations must be accepted");
        require(digest != A0_HASH, "150 iterations must not equal the 12-iteration vector");
    }

    function test_IterationCount151Rejected() external view {
        bool reverted;
        bytes4 sel;
        try harness.hashName(A0_NAME, RFC_SALT, 151) {
            reverted = false;
        } catch (bytes memory reason) {
            reverted = true;
            sel = _selector(reason);
        }
        require(reverted, "CONTROL FAILED: 151 iterations must be refused");
        require(
            sel == NSEC3Utils.IterationCountTooHigh.selector,
            "expected IterationCountTooHigh"
        );
    }

    function test_RecordDeclaring150IterationsAccepted() external view {
        bytes memory rdata = _rdata(
            1,
            1,
            150,
            hex"",
            20,
            abi.encodePacked(DESI_0_NEXT),
            hex"0006200000000012"
        );
        require(
            harness.readRdata(rdata).iterations == 150,
            "a record declaring 150 iterations must be read"
        );
    }

    function test_RecordDeclaring151IterationsRejected() external view {
        bytes memory rdata = _rdata(
            1,
            1,
            151,
            hex"",
            20,
            abi.encodePacked(DESI_0_NEXT),
            hex"0006200000000012"
        );
        (bool reverted, bytes4 sel) = _tryReadRdata(rdata);
        require(
            reverted,
            "CONTROL FAILED: a record declaring 151 iterations must be refused"
        );
        require(
            sel == NSEC3Utils.IterationCountTooHigh.selector,
            "expected IterationCountTooHigh"
        );
    }

    // ================================================ malformed input reverts, never returns false

    /// A character outside the base32hex alphabet of RFC 4648 section 7. `w` is the first
    /// letter past the alphabet's `v`.
    function test_BadBase32HexCharacterReverts() external view {
        (bool reverted, bytes4 sel) = _tryDecode(
            "0p9mhaveqvm6t7vbl5lop2u3t2rp3tow"
        );
        require(reverted, "CONTROL FAILED: 'w' is not a base32hex character");
        require(
            sel == NSEC3Utils.InvalidBase32HexChar.selector,
            "expected InvalidBase32HexChar"
        );
    }

    /// Uppercase is refused rather than folded, for `NSECUtils.requireCanonicalName`'s reason:
    /// the caller and the reader must agree on which exact bytes were read.
    function test_UppercaseOwnerLabelReverts() external view {
        (bool reverted, bytes4 sel) = _tryDecode(
            "0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM"
        );
        require(reverted, "CONTROL FAILED: an uppercase owner label must be refused");
        require(
            sel == NSEC3Utils.InvalidBase32HexChar.selector,
            "expected InvalidBase32HexChar"
        );
    }

    /// An owner label that is not 32 characters cannot be a 20-byte hash.
    function test_OwnerLabelOfTheWrongLengthReverts() external view {
        (bool reverted, bytes4 sel) = _tryDecode("0p9mhaveqvm6t7vbl5lop2u3t2rp3to");
        require(reverted, "CONTROL FAILED: a 31-character label must be refused");
        require(
            sel == NSEC3Utils.InvalidHashLabelLength.selector,
            "expected InvalidHashLabelLength"
        );
    }

    /// An owner name whose first label is an ordinary DNS label, not a hash label. A record
    /// shaped like this cannot come from an NSEC3 chain.
    function test_OwnerNameWithoutAHashLabelReverts() external view {
        bool reverted;
        bytes4 sel;
        try harness.ownerHash(DESI_NAME) {
            reverted = false;
        } catch (bytes memory reason) {
            reverted = true;
            sel = _selector(reason);
        }
        require(reverted, "CONTROL FAILED: desi. is not an NSEC3 owner name");
        require(
            sel == NSEC3Utils.InvalidHashLabelLength.selector,
            "expected InvalidHashLabelLength"
        );
    }

    /// A name that is not well formed uncompressed wire format. Reuses `NSECUtils`' own guard,
    /// so it reverts with `NSECUtils.MalformedName`.
    function test_MalformedOwnerNameReverts() external view {
        bool reverted;
        bytes4 sel;
        // A label length of 4 with only two bytes after it.
        try harness.ownerHash(hex"046465") {
            reverted = false;
        } catch (bytes memory reason) {
            reverted = true;
            sel = _selector(reason);
        }
        require(reverted, "CONTROL FAILED: a malformed owner name must revert");
        require(sel == NSECUtils.MalformedName.selector, "expected MalformedName");
    }

    /// An rdata shorter than the fields RFC 5155 section 3.2 requires.
    function test_TruncatedRdataReverts() external view {
        // Everything except the last byte of the next-hashed-owner field.
        (bool reverted, bytes4 sel) = _tryReadRdata(
            hex"010100000014d4aaf321d0be6248b2f93a433b76cd9bdd5617"
        );
        require(reverted, "CONTROL FAILED: a truncated rdata must revert");
        require(
            sel == NSEC3Utils.TruncatedNSEC3Rdata.selector,
            "expected TruncatedNSEC3Rdata"
        );
    }

    /// A salt length that claims more bytes than the rdata holds must revert, not read past the
    /// end and not stop reading early. Same failure mode as `NSECUtils.hasType`'s length byte.
    function test_SaltLengthOverrunningTheRdataReverts() external view {
        bytes memory rdata = abi.encodePacked(
            hex"01010000", // algorithm, flags, iterations
            uint8(64), // a salt length of 64
            hex"abbacafe", // but only four bytes of salt, then a 20-byte hash
            uint8(20),
            abi.encodePacked(FIRMDALE_0_NEXT)
        );
        (bool reverted, bytes4 sel) = _tryReadRdata(rdata);
        require(reverted, "CONTROL FAILED: an overrunning salt length must revert");
        require(
            sel == NSEC3Utils.TruncatedNSEC3Rdata.selector,
            "expected TruncatedNSEC3Rdata"
        );
    }

    /// A hash length that is not 20. SHA-1 is the only algorithm NSEC3 defines, so no other
    /// length can be read, and a short read would leave part of the next-hashed-owner in the
    /// type bitmap.
    function test_WrongHashLengthReverts() external view {
        bytes memory rdata = _rdata(
            1,
            1,
            0,
            hex"",
            16, // sixteen, not twenty
            abi.encodePacked(DESI_0_NEXT),
            hex"0006200000000012"
        );
        (bool reverted, bytes4 sel) = _tryReadRdata(rdata);
        require(reverted, "CONTROL FAILED: a hash length of 16 must revert");
        require(
            sel == NSEC3Utils.InvalidHashLength.selector,
            "expected InvalidHashLength"
        );
    }

    /// A hash algorithm other than SHA-1. None is defined, so the record is unreadable.
    function test_UnsupportedHashAlgorithmReverts() external view {
        bytes memory rdata = _rdata(
            2,
            1,
            0,
            hex"",
            20,
            abi.encodePacked(DESI_0_NEXT),
            hex"0006200000000012"
        );
        (bool reverted, bytes4 sel) = _tryReadRdata(rdata);
        require(reverted, "CONTROL FAILED: hash algorithm 2 must revert");
        require(
            sel == NSEC3Utils.UnsupportedHashAlgorithm.selector,
            "expected UnsupportedHashAlgorithm"
        );
    }

    /// An uppercase query name must revert rather than hash to a different gap from the one the
    /// zone signed. `NSECUtils.requireCanonicalName` is the guard.
    function test_UppercaseQueryNameReverts() external view {
        bool reverted;
        bytes4 sel;
        // _ENS.DESI.
        try harness.hashName(hex"045f454e53044445534900", hex"", 0) {
            reverted = false;
        } catch (bytes memory reason) {
            reverted = true;
            sel = _selector(reason);
        }
        require(reverted, "CONTROL FAILED: an uppercase query name must revert");
        require(
            sel == NSECUtils.MalformedName.selector ||
                sel == NSECUtils.NonCanonicalName.selector,
            "expected NonCanonicalName or MalformedName"
        );
    }

    // ========================================= the type bitmap, read by NSECUtils without change

    /// RFC 5155 section 3.2.1 uses RFC 4034 section 4.1.2's bitmap format unchanged, so the
    /// bitmap is read by `NSECUtils.hasType`. The fixtures carry three different bitmaps, and
    /// none of them lists TXT, which is the type the `_ens.<tld>` question asks about.
    function test_TypeBitmapsAreReadByNSECUtils() external view {
        (, bytes memory desi) = _rr(DESI_NSEC3_0_SET);
        require(
            harness.rdataHasType(desi, NSECUtils.DNSTYPE_NS) &&
                harness.rdataHasType(desi, NSECUtils.DNSTYPE_DS) &&
                harness.rdataHasType(desi, NSECUtils.DNSTYPE_RRSIG),
            "desi 0 is a delegation and must list NS, DS and RRSIG"
        );
        require(
            !harness.rdataHasType(desi, NSEC3Utils.DNSTYPE_TXT),
            "desi 0 must not list TXT"
        );

        (, bytes memory firmdale) = _rr(FIRMDALE_NSEC3_0_SET);
        require(
            harness.rdataHasType(firmdale, NSEC3Utils.DNSTYPE_NSEC3PARAM),
            "the firmdale apex record must list NSEC3PARAM"
        );
        require(
            !harness.rdataHasType(firmdale, NSEC3Utils.DNSTYPE_TXT),
            "the firmdale apex must not list TXT"
        );

        (, bytes memory nowruz) = _rr(NOWRUZ_NSEC3_0_SET);
        require(
            harness.rdataHasType(nowruz, NSECUtils.DNSTYPE_NS) &&
                !harness.rdataHasType(nowruz, NSECUtils.DNSTYPE_DS),
            "nowruz 0 lists NS and not DS"
        );
    }

    /// An NSEC3 record with no type bitmap reports every type absent, and does not revert.
    /// RFC 5155 section 7.1 has the signer publish that shape for an empty non-terminal, which
    /// genuinely has no types of its own. This is the one place `NSEC3Utils` is less strict
    /// than `NSECUtils`, whose NSEC records always list at least RRSIG and NSEC.
    function test_EmptyNSEC3BitmapReportsEveryTypeAbsent() external view {
        bytes memory rdata = _rdata(
            1,
            0,
            0,
            hex"",
            20,
            abi.encodePacked(DESI_0_NEXT),
            hex""
        );
        require(
            harness.readRdata(rdata).bitmapOffset == rdata.length,
            "the bitmap offset must land at the end of the rdata"
        );
        require(
            !harness.rdataHasType(rdata, NSEC3Utils.DNSTYPE_TXT) &&
                !harness.rdataHasType(rdata, NSECUtils.DNSTYPE_NS),
            "an empty NSEC3 bitmap must report every type absent"
        );
    }

    /// A bitmap that is present and malformed still reverts, through `NSECUtils.hasType`. The
    /// empty case above must not be read as a licence to ignore a bad block.
    function test_MalformedBitmapStillRevertsThroughTheNSEC3Reader() external view {
        bytes memory rdata = _rdata(
            1,
            0,
            0,
            hex"",
            20,
            abi.encodePacked(DESI_0_NEXT),
            hex"0005000000" // window 0, length 5, but only three data bytes
        );
        bool reverted;
        bytes4 sel;
        try harness.rdataHasType(rdata, NSECUtils.DNSTYPE_NS) {
            reverted = false;
        } catch (bytes memory reason) {
            reverted = true;
            sel = _selector(reason);
        }
        require(reverted, "CONTROL FAILED: a malformed bitmap must revert");
        require(
            sel == NSECUtils.TruncatedTypeBitmap.selector,
            "expected NSECUtils.TruncatedTypeBitmap"
        );
    }

    // ======================================== the authenticated bytes, once, end to end

    /// The same reading, on bytes an unmodified `DNSSECImpl` has authenticated, for all three
    /// zones. Everything above parses the fixtures without verifying, so this is the one test
    /// that proves the library reads what the oracle actually returns.
    ///
    /// **This test expires with the fixtures, on 1 December 2026**, exactly as
    /// `NSEC3FixtureCheck.t.sol` does. Refresh with `python3 tools/mkchain.py --sol`.
    function test_AllThreeZonesDenyEnsThroughTheRealOracle() external {
        require(
            _deniedByOracle(
                DESI_NAME,
                DESI_QNAME,
                DESI_DS_SET,
                DESI_DS_SIG,
                DESI_DNSKEY_SET,
                DESI_DNSKEY_SIG,
                DESI_NSEC3_0_SET,
                DESI_NSEC3_0_SIG
            ),
            "_ens.desi. must be proven absent from authenticated bytes"
        );
        require(
            _deniedByOracle(
                FIRMDALE_NAME,
                FIRMDALE_QNAME,
                FIRMDALE_DS_SET,
                FIRMDALE_DS_SIG,
                FIRMDALE_DNSKEY_SET,
                FIRMDALE_DNSKEY_SIG,
                FIRMDALE_NSEC3_0_SET,
                FIRMDALE_NSEC3_0_SIG
            ),
            "_ens.firmdale. must be proven absent from authenticated bytes"
        );
        require(
            _deniedByOracle(
                NOWRUZ_NAME,
                NOWRUZ_QNAME,
                NOWRUZ_DS_SET,
                NOWRUZ_DS_SIG,
                NOWRUZ_DNSKEY_SET,
                NOWRUZ_DNSKEY_SIG,
                NOWRUZ_NSEC3_0_SET,
                NOWRUZ_NSEC3_0_SIG
            ),
            "_ens.nowruz. must be proven absent from authenticated bytes"
        );
    }

    function _deniedByOracle(
        bytes memory zone,
        bytes memory qname,
        bytes memory dsSet,
        bytes memory dsSig,
        bytes memory keySet,
        bytes memory keySig,
        bytes memory n3Set,
        bytes memory n3Sig
    ) internal returns (bool) {
        DNSSECImpl oracle = _realOracle();
        RRUtils.SignedSet[] memory sets = oracle.verifyRRSetAt(
            _chain4(dsSet, dsSig, keySet, keySig, n3Set, n3Sig),
            AT
        );
        RRUtils.SignedSet memory last = sets[sets.length - 1];
        require(
            last.signerName.equals(zone),
            "the NSEC3 set must be signed by the zone itself"
        );
        RRUtils.RRIterator memory iter = RRUtils.iterateRRs(last.data, 0);
        require(!iter.done(), "the authenticated set holds no record");
        return
            NSEC3Utils.recordCoversName(iter.name(), iter.rdata(), qname);
    }

    // ------------------------------------------------------------------------- revert plumbing

    function _tryDecode(
        bytes memory label
    ) internal view returns (bool reverted, bytes4 sel) {
        try harness.decodeHashLabel(label) {
            reverted = false;
        } catch (bytes memory reason) {
            reverted = true;
            sel = _selector(reason);
        }
    }

    function _tryReadRdata(
        bytes memory rdata
    ) internal view returns (bool reverted, bytes4 sel) {
        try harness.readRdata(rdata) {
            reverted = false;
        } catch (bytes memory reason) {
            reverted = true;
            sel = _selector(reason);
        }
    }
}
