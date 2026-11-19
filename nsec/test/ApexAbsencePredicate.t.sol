// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {DNSSEC} from "../src/contracts/dnssec-oracle/DNSSEC.sol";
import {DNSSECImpl} from "../src/contracts/dnssec-oracle/DNSSECImpl.sol";
import {RRUtils} from "../src/contracts/dnssec-oracle/RRUtils.sol";
import {BytesUtils} from "../src/contracts/utils/BytesUtils.sol";
import {NSECUtils} from "../src/NSECUtils.sol";
import {NSEC3Utils} from "../src/NSEC3Utils.sol";
import {ApexAbsencePredicate} from "../src/ApexAbsencePredicate.sol";
import {NSEC3Fixtures} from "./NSEC3Fixtures.sol";
import {SyntheticChainBuilder} from "./SyntheticChainBuilder.sol";

/// Not a test contract. Builds NSEC3 records, which `SyntheticChainBuilder` does not: that file
/// is NSEC only and is pass 1's, so it is inherited and not changed. The DNSKEY half of a
/// synthetic chain is reused from it without change, through `_zoneKeyChain`.
///
/// `DummyAlgorithm.verify` and `DummyDigest.verify` always return true, so a chain built here
/// validates end to end through the real, unmodified `DNSSECImpl` on field consistency alone,
/// with no cryptography. That is the point: it lets a test build a chain the *oracle* fully
/// accepts, so that when the *predicate* still refuses it, the refusal is attributable to the
/// predicate's own check and not to a signature failure.
///
/// Nothing produced here is signed by any real zone, and nothing it says is a statement about
/// what any top-level domain publishes. The real-fixture tests are the ones that measure that.
abstract contract NSEC3ChainBuilder is SyntheticChainBuilder {
    uint16 internal constant DNSTYPE_NSEC3 = 50;

    /// One NSEC3 rdata, per RFC 5155 section 3.2. The hash algorithm is 1 and the hash length
    /// is 20, which are the only values the library reads; the malformed cases are pass 1's.
    function _nsec3Rdata(
        uint8 flags,
        uint16 iterations,
        bytes memory salt,
        bytes20 nextHashedOwner,
        bytes memory bitmap
    ) internal pure returns (bytes memory) {
        return
            abi.encodePacked(
                uint8(1),
                flags,
                iterations,
                uint8(salt.length),
                salt,
                uint8(20),
                nextHashedOwner,
                bitmap
            );
    }

    /// One NSEC3 record owned by `owner`, signed by `signerName`. The caller chooses the signer
    /// and the label count independently of the owner, which is exactly the degree of freedom a
    /// forged proof needs and a correct predicate must close off.
    function _nsec3Record(
        bytes memory owner,
        bytes memory rdata,
        bytes memory signerName,
        uint8 labels,
        uint16 keytag
    ) internal pure returns (DNSSEC.RRSetWithSignature memory) {
        bytes memory rr = abi.encodePacked(
            owner,
            uint16(DNSTYPE_NSEC3),
            uint16(1), // class IN
            SYNTH_TTL,
            uint16(rdata.length),
            rdata
        );
        return
            DNSSEC.RRSetWithSignature(
                abi.encodePacked(
                    _nsec3SigPrefix(signerName, labels, keytag),
                    rr
                ),
                hex"00"
            );
    }

    /// Two NSEC3 records sharing one owner name and one signature. DNS permits it, because an
    /// RRset is every record sharing a name, type and class and `DNSSECImpl.validateRRs` asks
    /// only for that. RFC 5155 section 7.1 adds one NSEC3 RR for each hashed owner name, so the
    /// shape cannot come from a zone, and the second record's next-hashed-owner could widen the
    /// span of the first. `ProofNotOneRecord` closes the gap.
    function _twoNsec3RecordsOneSignature(
        bytes memory owner,
        bytes memory rdata1,
        bytes memory rdata2,
        bytes memory signerName,
        uint8 labels,
        uint16 keytag
    ) internal pure returns (DNSSEC.RRSetWithSignature memory) {
        bytes memory rr1 = abi.encodePacked(
            owner,
            uint16(DNSTYPE_NSEC3),
            uint16(1),
            SYNTH_TTL,
            uint16(rdata1.length),
            rdata1
        );
        bytes memory rr2 = abi.encodePacked(
            owner,
            uint16(DNSTYPE_NSEC3),
            uint16(1),
            SYNTH_TTL,
            uint16(rdata2.length),
            rdata2
        );
        return
            DNSSEC.RRSetWithSignature(
                abi.encodePacked(
                    _nsec3SigPrefix(signerName, labels, keytag),
                    rr1,
                    rr2
                ),
                hex"00"
            );
    }

    function _nsec3SigPrefix(
        bytes memory signerName,
        uint8 labels,
        uint16 keytag
    ) private pure returns (bytes memory) {
        return
            abi.encodePacked(
                uint16(DNSTYPE_NSEC3),
                uint8(DUMMY_ALGO_ID),
                labels,
                SYNTH_TTL,
                SYNTH_EXPIRATION,
                SYNTH_INCEPTION,
                keytag,
                signerName
            );
    }

    /// The wire-format owner name of an NSEC3 record: the 32-character base32hex hash label,
    /// then the zone. There is no encoder in Solidity and none is needed, so every label below
    /// comes from `tools/mkhashvectors.py`'s `b32hex`.
    function _ownerName(
        bytes memory label,
        bytes memory zone
    ) internal pure returns (bytes memory) {
        require(label.length == 32, "an NSEC3 hash label is 32 characters");
        return abi.encodePacked(uint8(32), label, zone);
    }
}

/// `ApexAbsencePredicate`'s own suite. Pass 2 of the NSEC3 work.
///
/// **Run `test/NSEC3FixtureCheck.t.sol` first.** It proves the six captured NSEC3 chains
/// validate through an unmodified `DNSSECImpl`, so a failure there is a bad fixture and a
/// failure here is the predicate. That separation is why the two files are separate.
///
/// Every expected hash below comes from `tools/mkhashvectors.py`, which self-checks 8 of 8
/// against RFC 5155 Appendix A before printing anything. Nothing here is checked against the
/// contract's own output.
///
/// **The real-fixture tests expire on 1 December 2026**, with the fixtures. After that they
/// fail on signature expiry, which looks exactly like a defect in the predicate and is not one.
/// Refresh with `python3 tools/mkchain.py --sol`. The synthetic tests do not expire.
contract ApexAbsencePredicateTest is NSEC3Fixtures, NSEC3ChainBuilder {
    using RRUtils for *;
    using BytesUtils for bytes;

    // ---------------------------------------------------- hashes, from tools/mkhashvectors.py

    bytes20 internal constant DESI_ENS_HASH =
        hex"24087ff374e5e9ed0c36c526f79717876a02a2cb";
    bytes20 internal constant DESI_APEX_HASH =
        hex"2a7c80ce15a552767f6173d502b5bcb1cd9bf75f";
    bytes20 internal constant FIRMDALE_ENS_HASH =
        hex"1a5d65c05d68360110db682feb01bb8102d82a87";
    bytes20 internal constant FIRMDALE_APEX_HASH =
        hex"d4aaf321d0be6248b2f93a433b76cd9bdd56173e";
    bytes20 internal constant NOWRUZ_ENS_HASH =
        hex"2acc2a61ccc55898efd2a8c9620289fc68851b09";
    bytes20 internal constant NOWRUZ_APEX_HASH =
        hex"b4f6a95c4101e77fcbb6a31e915ac7cb315c34b8";

    // ------------------------------------------------------- the synthetic zones bar. and baz.

    bytes internal constant BAR_NAME = hex"0362617200"; // bar.
    bytes internal constant BAR_ENS = hex"045f656e730362617200"; // _ens.bar.
    bytes internal constant BAZ_NAME = hex"0362617a00"; // baz.
    bytes internal constant SUB_BAR_NAME = hex"037375620362617200"; // sub.bar.

    /// @dev hash(_ens.bar.), salt none, 0 iterations.
    bytes20 internal constant BAR_ENS_HASH =
        hex"d35cd2e26a5a94d81692a613c79f0ac22c7c0e14";
    bytes internal constant BAR_ENS_LABEL =
        "qded5ojabaadg5kiko9sf7oao8m7o3gk";

    /// @dev hash(_ens.bar.), salt f00d, 0 iterations. The salt changes the hash, which is what
    ///      the parameter cache control turns on.
    bytes internal constant SALT_F00D = hex"f00d";
    bytes20 internal constant BAR_ENS_HASH_F00D =
        hex"05c86e27b6c6e273fbc40d63c347cee52b7bdd03";
    bytes internal constant BAR_ENS_LABEL_F00D =
        "0n46s9tmorh77uu41lhs6huesklnnn83";

    /// @dev hash(_ens.bar.), salt none, at the predicate's cap and one above it.
    bytes20 internal constant BAR_ENS_HASH_IT20 =
        hex"88dd3f6026455e592149e9bd233d19022bad6098";
    bytes20 internal constant BAR_ENS_HASH_IT21 =
        hex"ef705c10d33ab517648bd11e28d04069f4471c59";

    /// @dev The lowest and highest hashes, as a base32hex label and as raw bytes. A record from
    ///      the bottom of hash order to the top is an ordinary gap that covers everything
    ///      between, which isolates a test from the wrap rule.
    bytes internal constant ZERO_LABEL =
        "00000000000000000000000000000000";
    bytes20 internal constant MAX_HASH =
        hex"ffffffffffffffffffffffffffffffffffffffff";

    /// @dev A type bitmap listing A and not TXT, per RFC 4034 section 4.1.2: window 0, length 1,
    ///      and bit 1 set.
    bytes internal constant BITMAP_A_ONLY = hex"000140";

    /// @dev A type bitmap listing TXT, which is type 16: window 0, length 3, and bit 16 set,
    ///      which is the top bit of the third data byte.
    bytes internal constant BITMAP_WITH_TXT = hex"0003000080";

    // ------------------------------------- the root's own NSEC, for the changed-check control

    /// @dev `zw. NSEC .`, root-signed, read from 198.41.0.4 on 17 November 2026 and carried in
    ///      `RootFixtures.sol`. Copied rather than inherited, because `RootFixtures` and
    ///      `NSEC3Fixtures` declare the same names and cannot both be a base of one contract.
    ///      Its RRSIG runs to 30 November 2026 20:00 UTC, so `AT` is inside it, and
    ///      `ROOT_DNSKEY_SET` from `NSEC3Fixtures` is the same root key set that signs it.
    bytes internal constant ROOT_NSEC_SET =
        hex"002f0801000151806b0dd5c06afca430223b00027a7700002f0001000151800009000006200000000003";
    bytes internal constant ROOT_NSEC_SIG =
        hex"3363004eb8ccac9a3429fc9b44ec50b15ccd0230c68fe6de0453a7fe3b87ab9be315f2988c91c9b3b98379395ae403ce7333c2705367236a1cbbac3dcb85fb585c35ab9739a3fe715998c5ec193cb6b0e809591585df096eaa7556b722dc019e8e39944e985aa5413809d52aace533ae4b0d4fc2abe8a43cb28bac7918fec63704a9d1e9458430ad9fefed547ff92805227ab43f0969084962d2290b1abb66f5f567526bc5a0336174ace9cec82988aa42ed511c0ace38df92252b10229919fe956a75d36fff2c029367192dbebdac13e52fbf6a05e44651c297f323a0f50185a60d5f177716a304801239a88d8e6a7a84ed4242003fc528b4b5ad4198d8fed9";

    // ------------------------------------------------------------------------------- plumbing

    function _predicate() internal returns (ApexAbsencePredicate) {
        return new ApexAbsencePredicate(_realOracle());
    }

    function _selector(bytes memory reason) internal pure returns (bytes4 sel) {
        require(reason.length >= 4, "revert reason too short to carry a selector");
        assembly {
            sel := mload(add(reason, 32))
        }
    }

    function _desiChain(
        bytes memory n3Set,
        bytes memory n3Sig
    ) internal pure returns (DNSSEC.RRSetWithSignature[] memory) {
        return
            _chain4(
                DESI_DS_SET,
                DESI_DS_SIG,
                DESI_DNSKEY_SET,
                DESI_DNSKEY_SIG,
                n3Set,
                n3Sig
            );
    }

    function _firmdaleChain()
        internal
        pure
        returns (DNSSEC.RRSetWithSignature[] memory)
    {
        return
            _chain4(
                FIRMDALE_DS_SET,
                FIRMDALE_DS_SIG,
                FIRMDALE_DNSKEY_SET,
                FIRMDALE_DNSKEY_SIG,
                FIRMDALE_NSEC3_0_SET,
                FIRMDALE_NSEC3_0_SIG
            );
    }

    function _nowruzChain(
        bytes memory n3Set,
        bytes memory n3Sig
    ) internal pure returns (DNSSEC.RRSetWithSignature[] memory) {
        return
            _chain4(
                NOWRUZ_DS_SET,
                NOWRUZ_DS_SIG,
                NOWRUZ_DNSKEY_SET,
                NOWRUZ_DNSKEY_SIG,
                n3Set,
                n3Sig
            );
    }

    function _p1(
        DNSSEC.RRSetWithSignature[] memory c0
    ) internal pure returns (DNSSEC.RRSetWithSignature[][] memory proofs) {
        proofs = new DNSSEC.RRSetWithSignature[][](1);
        proofs[0] = c0;
    }

    function _p2(
        DNSSEC.RRSetWithSignature[] memory c0,
        DNSSEC.RRSetWithSignature[] memory c1
    ) internal pure returns (DNSSEC.RRSetWithSignature[][] memory proofs) {
        proofs = new DNSSEC.RRSetWithSignature[][](2);
        proofs[0] = c0;
        proofs[1] = c1;
    }

    function _p3(
        DNSSEC.RRSetWithSignature[] memory c0,
        DNSSEC.RRSetWithSignature[] memory c1,
        DNSSEC.RRSetWithSignature[] memory c2
    ) internal pure returns (DNSSEC.RRSetWithSignature[][] memory proofs) {
        proofs = new DNSSEC.RRSetWithSignature[][](3);
        proofs[0] = c0;
        proofs[1] = c1;
        proofs[2] = c2;
    }

    function _desiAllThree()
        internal
        pure
        returns (DNSSEC.RRSetWithSignature[][] memory)
    {
        return
            _p3(
                _desiChain(DESI_NSEC3_0_SET, DESI_NSEC3_0_SIG),
                _desiChain(DESI_NSEC3_1_SET, DESI_NSEC3_1_SIG),
                _desiChain(DESI_NSEC3_2_SET, DESI_NSEC3_2_SIG)
            );
    }

    function _nowruzBoth()
        internal
        pure
        returns (DNSSEC.RRSetWithSignature[][] memory)
    {
        return
            _p2(
                _nowruzChain(NOWRUZ_NSEC3_0_SET, NOWRUZ_NSEC3_0_SIG),
                _nowruzChain(NOWRUZ_NSEC3_1_SET, NOWRUZ_NSEC3_1_SIG)
            );
    }

    /// One synthetic proof in the zone `bar.`, with its own fresh oracle and predicate.
    function _barProof(
        bytes memory ownerLabel,
        bytes memory rdata
    )
        internal
        returns (
            ApexAbsencePredicate predicate,
            DNSSEC.RRSetWithSignature[][] memory proofs
        )
    {
        (
            DNSSECImpl oracle,
            DNSSEC.RRSetWithSignature memory dnskeySet,
            uint16 keytag
        ) = _zoneKeyChain(BAR_NAME, 1);
        predicate = new ApexAbsencePredicate(oracle);
        DNSSEC.RRSetWithSignature[]
            memory chain = new DNSSEC.RRSetWithSignature[](2);
        chain[0] = dnskeySet;
        chain[1] = _nsec3Record(
            _ownerName(ownerLabel, BAR_NAME),
            rdata,
            BAR_NAME,
            2,
            keytag
        );
        proofs = _p1(chain);
    }

    // =========================================== the three captured zones, end to end

    /// Required case: `_ens.desi.` proven absent through the real oracle. `desi` is an EBERO
    /// zone, publishes three NSEC3 records with Opt-Out set, zero iterations and no salt, and
    /// uses all three roles of RFC 5155 section 8.4: one record covers the queried name, one
    /// matches the apex, one covers the wildcard.
    function test_DesiEnsIsProvenAbsentThroughTheRealOracle() external {
        ApexAbsencePredicate predicate = _predicate();
        vm.warp(AT);
        ApexAbsencePredicate.Result memory result = predicate.proveAbsence(
            DESI_QNAME,
            _desiAllThree()
        );
        require(result.proven, "_ens.desi. must be proven absent");
        require(
            result.route == ApexAbsencePredicate.Route.NoName,
            "expected NoName: the name is not in the zone"
        );
        require(result.records == 3, "all three desi records must be read");
        require(result.nameHash == DESI_ENS_HASH, "hash(_ens.desi.)");
        require(
            result.apexMatched,
            "the closest encloser, the desi. apex, must be matched"
        );
        require(result.wildcardDenied, "*.desi. must be denied");
        require(result.optOut, "the deciding desi record sets Opt-Out");
        require(DESI_NSEC3_COUNT == 3, "desi must be the three-record zone");
    }

    /// Required case: `_ens.firmdale.` proven absent, and **hazard 1 end to end**. `firmdale`
    /// publishes exactly one NSEC3 record, because Opt-Out hides every delegation, and that
    /// record points at itself. `hash(_ens.firmdale.)` sorts below the owner hash, so only the
    /// wrap-aware NSEC3 closing rule proves it absent. An implementation that ported
    /// `NSECUtils.coversName`'s rule, which keys the closing branch on the apex, reports this
    /// one Unproven and passes the other two zones.
    ///
    /// It is also the single-record case the scope document names: one record matches the apex
    /// **and** covers both the queried name and the wildcard, so one record answers all three
    /// obligations of RFC 5155 section 8.4.
    function test_FirmdaleOneSelfPointingRecordProvesTheNameAndTheWildcard()
        external
    {
        ApexAbsencePredicate predicate = _predicate();
        vm.warp(AT);
        ApexAbsencePredicate.Result memory result = predicate.proveAbsence(
            FIRMDALE_QNAME,
            _p1(_firmdaleChain())
        );
        require(result.proven, "_ens.firmdale. must be proven absent");
        require(
            result.route == ApexAbsencePredicate.Route.NoName,
            "expected NoName from the self-pointing record"
        );
        require(FIRMDALE_NSEC3_COUNT == 1, "firmdale must be the one-record zone");
        require(result.records == 1, "one record must do all the work");
        require(
            result.ownerHash == FIRMDALE_APEX_HASH &&
                result.nextHash == FIRMDALE_APEX_HASH,
            "the record must point at itself, which is hazard 1's shape"
        );
        require(
            result.apexMatched,
            "the same record matches the firmdale. apex"
        );
        require(
            result.wildcardDenied,
            "the same record must also deny *.firmdale."
        );
        require(result.nameHash == FIRMDALE_ENS_HASH, "hash(_ens.firmdale.)");
        require(
            uint160(result.nameHash) < uint160(result.ownerHash),
            "the premise of hazard 1: the queried hash sorts BELOW the owner hash"
        );
    }

    /// Required case: `_ens.nowruz.` proven absent. Two records, Opt-Out clear, so neither the
    /// record count nor the flag is assumed anywhere.
    function test_NowruzEnsIsProvenAbsentThroughTheRealOracle() external {
        ApexAbsencePredicate predicate = _predicate();
        vm.warp(AT);
        ApexAbsencePredicate.Result memory result = predicate.proveAbsence(
            NOWRUZ_QNAME,
            _nowruzBoth()
        );
        require(result.proven, "_ens.nowruz. must be proven absent");
        require(
            result.route == ApexAbsencePredicate.Route.NoName,
            "expected NoName"
        );
        require(NOWRUZ_NSEC3_COUNT == 2, "nowruz must be the two-record zone");
        require(result.records == 2, "both nowruz records must be read");
        require(result.nameHash == NOWRUZ_ENS_HASH, "hash(_ens.nowruz.)");
        require(result.apexMatched, "the nowruz. apex must be matched");
        require(result.wildcardDenied, "*.nowruz. must be denied");
        require(!result.optOut, "nowruz has Opt-Out clear");
    }

    /// `requireAbsence` is the release path. All three zones must pass it, and the three
    /// counts, three, one and two, must all work.
    function test_RequireAbsenceSucceedsForAllThreeZones() external {
        ApexAbsencePredicate predicate = _predicate();
        vm.warp(AT);
        require(
            predicate.requireAbsence(DESI_QNAME, _desiAllThree()).proven,
            "desi"
        );
        require(
            predicate
                .requireAbsence(FIRMDALE_QNAME, _p1(_firmdaleChain()))
                .proven,
            "firmdale"
        );
        require(
            predicate.requireAbsence(NOWRUZ_QNAME, _nowruzBoth()).proven,
            "nowruz"
        );
    }

    /// The covering record alone is enough for `proven`, and the other two obligations are then
    /// reported false. The flags describe the proof's completeness; they do not gate the answer.
    function test_TheCoveringRecordAloneProvesAndReportsTheRestFalse() external {
        ApexAbsencePredicate predicate = _predicate();
        vm.warp(AT);
        ApexAbsencePredicate.Result memory result = predicate.proveAbsence(
            DESI_QNAME,
            _p1(_desiChain(DESI_NSEC3_0_SET, DESI_NSEC3_0_SIG))
        );
        require(result.proven, "desi record 0 covers _ens.desi. on its own");
        require(result.records == 1, "one record read");
        require(
            !result.apexMatched && !result.wildcardDenied,
            "the other two obligations are unanswered and must report false"
        );
    }

    /// The same record sent twice is one record. `records` counts the distinct authenticated
    /// byte strings, not the reads.
    function test_TheSameRecordSentTwiceCountsOnce() external {
        ApexAbsencePredicate predicate = _predicate();
        vm.warp(AT);
        ApexAbsencePredicate.Result memory result = predicate.proveAbsence(
            DESI_QNAME,
            _p2(
                _desiChain(DESI_NSEC3_0_SET, DESI_NSEC3_0_SIG),
                _desiChain(DESI_NSEC3_0_SET, DESI_NSEC3_0_SIG)
            )
        );
        require(result.proven, "still proven");
        require(result.records == 1, "two reads of one record is one record");
    }

    // ======================================================= NODATA: the name exists, no TXT

    /// Required case: a record that **matches** the queried name, whose bitmap does not list
    /// TXT. That is the NODATA shape of RFC 5155 section 8.5, and it means the commitment is
    /// gone just as surely as NXDOMAIN does. No captured zone publishes `_ens.<tld>` at all, so
    /// there is no live fixture for this shape and a synthetic record is the only way to reach
    /// it. The record is signed by `bar.` and the owner label is the base32hex form of
    /// `hash(_ens.bar.)` from `tools/mkhashvectors.py`, so the match is a real hash match.
    function test_NodataMatchingRecordWithoutTxtIsProven() external {
        (
            ApexAbsencePredicate predicate,
            DNSSEC.RRSetWithSignature[][] memory proofs
        ) = _barProof(
                BAR_ENS_LABEL,
                _nsec3Rdata(0, 0, hex"", MAX_HASH, BITMAP_A_ONLY)
            );
        vm.warp(SYNTH_AT);
        ApexAbsencePredicate.Result memory result = predicate.proveAbsence(
            BAR_ENS,
            proofs
        );
        require(result.proven, "a matching record with no TXT must prove absence");
        require(
            result.route == ApexAbsencePredicate.Route.NoTxtBit,
            "expected NoTxtBit, the NODATA shape"
        );
        require(
            result.ownerHash == BAR_ENS_HASH &&
                result.nameHash == BAR_ENS_HASH,
            "the record must match the name by hash, not by name"
        );
        require(
            !result.wildcardDenied,
            "a NODATA proof does not deny the wildcard, and must not claim to"
        );
        // Attribution: the same bitmap, read directly, does list A and does not list TXT.
        require(
            predicate.rdataHasType(
                _nsec3Rdata(0, 0, hex"", MAX_HASH, BITMAP_A_ONLY),
                1
            ),
            "setup error: the bitmap should list A"
        );
        require(
            !predicate.rdataHasType(
                _nsec3Rdata(0, 0, hex"", MAX_HASH, BITMAP_A_ONLY),
                NSEC3Utils.DNSTYPE_TXT
            ),
            "setup error: the bitmap should not list TXT"
        );
    }

    /// An empty type bitmap is legal in NSEC3 and reports every type absent, which is the
    /// NODATA proof for an empty non-terminal. This is the one place the readers are
    /// deliberately lenient, and the predicate must not undo it: reverting here would refuse a
    /// sound proof. See the note on `NSEC3Utils.rdataHasType`.
    function test_NodataMatchingRecordWithAnEmptyBitmapIsProven() external {
        (
            ApexAbsencePredicate predicate,
            DNSSEC.RRSetWithSignature[][] memory proofs
        ) = _barProof(BAR_ENS_LABEL, _nsec3Rdata(0, 0, hex"", MAX_HASH, hex""));
        vm.warp(SYNTH_AT);
        ApexAbsencePredicate.Result memory result = predicate.proveAbsence(
            BAR_ENS,
            proofs
        );
        require(result.proven, "an empty NSEC3 bitmap proves every type absent");
        require(
            result.route == ApexAbsencePredicate.Route.NoTxtBit,
            "expected NoTxtBit"
        );
    }

    /// **CONTROL. The name exists with TXT, so the commitment is live and must not be
    /// released.** This is the NSEC3 counterpart of `aq.` and `zw.` in
    /// `RootAbsencePredicate.t.sol`: the record the predicate must refuse to read as absence.
    function test_ControlMatchingRecordWithTxtIsNotProven() external {
        (
            ApexAbsencePredicate predicate,
            DNSSEC.RRSetWithSignature[][] memory proofs
        ) = _barProof(
                BAR_ENS_LABEL,
                _nsec3Rdata(0, 0, hex"", MAX_HASH, BITMAP_WITH_TXT)
            );
        vm.warp(SYNTH_AT);
        ApexAbsencePredicate.Result memory result = predicate.proveAbsence(
            BAR_ENS,
            proofs
        );
        require(
            !result.proven,
            "CONTROL FAILED: a live TXT record was reported absent"
        );
        require(
            result.route == ApexAbsencePredicate.Route.Present,
            "expected Present"
        );
    }

    /// `Present` is a veto inside one call. A record that shows TXT on the name itself must not
    /// be overturned by a second record that would otherwise cover the name. Mirrors
    /// `test_DelegatedVetoesAnOtherwiseCoveringRecord` in the root suite.
    function test_ControlPresentVetoesAnOtherwiseCoveringRecord() external {
        (
            DNSSECImpl oracle,
            DNSSEC.RRSetWithSignature memory dnskeySet,
            uint16 keytag
        ) = _zoneKeyChain(BAR_NAME, 1);
        ApexAbsencePredicate predicate = new ApexAbsencePredicate(oracle);

        // Record A: the whole of hash order, so it covers hash(_ens.bar.).
        DNSSEC.RRSetWithSignature[]
            memory covering = new DNSSEC.RRSetWithSignature[](2);
        covering[0] = dnskeySet;
        covering[1] = _nsec3Record(
            _ownerName(ZERO_LABEL, BAR_NAME),
            _nsec3Rdata(0, 0, hex"", MAX_HASH, BITMAP_A_ONLY),
            BAR_NAME,
            2,
            keytag
        );
        // Record B: the name itself, with TXT.
        DNSSEC.RRSetWithSignature[]
            memory present = new DNSSEC.RRSetWithSignature[](2);
        present[0] = dnskeySet;
        present[1] = _nsec3Record(
            _ownerName(BAR_ENS_LABEL, BAR_NAME),
            _nsec3Rdata(0, 0, hex"", MAX_HASH, BITMAP_WITH_TXT),
            BAR_NAME,
            2,
            keytag
        );

        vm.warp(SYNTH_AT);
        // Covering record alone: proven. So the veto below is attributable to record B.
        require(
            predicate.proveAbsence(BAR_ENS, _p1(covering)).proven,
            "setup error: the covering record alone should prove absence"
        );
        ApexAbsencePredicate.Result memory result = predicate.proveAbsence(
            BAR_ENS,
            _p2(covering, present)
        );
        require(
            !result.proven,
            "CONTROL FAILED: Present must not be overturned by a covering record"
        );
        require(
            result.route == ApexAbsencePredicate.Route.Present,
            "expected Present to hold"
        );
        require(result.records == 2, "both records must still be read");
    }

    // ================================================================ the controls that fail

    /// **CONTROL. A name the proof does not cover must not be reported absent.** `desi`'s apex
    /// record matches `desi.` and its span does not reach `hash(_ens.desi.)`, which sorts below
    /// its owner hash. Read alone it decides nothing. This is the NSEC3 form of the `com.`
    /// control on the `zw.` closing record in the root suite: the ordinary gap must not wrap.
    function test_ControlRecordThatDoesNotCoverTheNameProvesNothing() external {
        ApexAbsencePredicate predicate = _predicate();
        vm.warp(AT);
        ApexAbsencePredicate.Result memory result = predicate.proveAbsence(
            DESI_QNAME,
            _p1(_desiChain(DESI_NSEC3_1_SET, DESI_NSEC3_1_SIG))
        );
        require(
            !result.proven,
            "CONTROL FAILED: _ens.desi. reported absent by a record that does not cover it"
        );
        require(
            result.route == ApexAbsencePredicate.Route.Unproven,
            "expected Unproven"
        );
        require(result.records == 1, "the record must still be read");
        require(
            result.apexMatched,
            "it is the apex record, so the closest-encloser flag is set"
        );
        // Attribution: the premise, measured. The queried hash sorts below this record's owner
        // hash, so only a wrap would reach it, and this record does not close the chain.
        require(
            uint160(DESI_ENS_HASH) < uint160(DESI_APEX_HASH),
            "setup error: hash(_ens.desi.) should sort below the apex record's owner hash"
        );
        require(
            !predicate.coversHash(
                DESI_APEX_HASH,
                hex"312c0c40bb8c5e0fb9e8bfcc3e5175e7b825c47e",
                DESI_ENS_HASH
            ),
            "setup error: this record's span should not reach the queried hash"
        );
    }

    /// **CONTROL, and changed check 1. A root-signed NSEC proof must revert.** `zw. NSEC .` is
    /// a real, root-signed record that validates through the oracle at `AT`. It is type 47.
    /// `RootAbsencePredicate` requires 47 and this contract requires 50, so the record that is
    /// the root predicate's whole subject is refused here rather than misread. The two rdata
    /// formats share no fields: an NSEC rdata begins with a name and an NSEC3 rdata begins with
    /// a hash algorithm byte.
    function test_ControlRootSignedNsecProofIsRefused() external {
        ApexAbsencePredicate predicate = _predicate();
        vm.warp(AT);
        DNSSEC.RRSetWithSignature[]
            memory chain = new DNSSEC.RRSetWithSignature[](2);
        chain[0] = DNSSEC.RRSetWithSignature(ROOT_DNSKEY_SET, ROOT_DNSKEY_SIG);
        chain[1] = DNSSEC.RRSetWithSignature(ROOT_NSEC_SET, ROOT_NSEC_SIG);

        // Attribution: the oracle itself accepts this chain at this time, and says it covers
        // NSEC and is signed by the root. So the refusal below is the predicate's own check.
        RRUtils.SignedSet[] memory sets = _realOracle().verifyRRSetAt(
            chain,
            AT
        );
        RRUtils.SignedSet memory last = sets[sets.length - 1];
        require(
            last.typeCovered == NSECUtils.DNSTYPE_NSEC,
            "setup error: the root fixture should cover NSEC"
        );
        require(
            last.signerName.equals(NSECUtils.ROOT_NAME),
            "setup error: the root fixture should be root-signed"
        );

        bool reverted;
        bytes4 sel;
        try predicate.proveAbsence(DESI_QNAME, _p1(chain)) {
            reverted = false;
        } catch (bytes memory reason) {
            reverted = true;
            sel = _selector(reason);
        }
        require(
            reverted,
            "CONTROL FAILED: a root-signed NSEC proof was accepted by the NSEC3 predicate"
        );
        require(
            sel == ApexAbsencePredicate.ProofNotNSEC3.selector,
            "expected ProofNotNSEC3"
        );
    }

    /// **CONTROL, and changed check 2. A proof from the wrong zone must revert.** `desi`'s
    /// chain is real and valid, and it says nothing about `firmdale`. The zone is derived from
    /// the queried name, so the caller cannot name a zone it controls and have that zone's hash
    /// order read as the target's.
    function test_ControlDesiChainCannotProveANameUnderFirmdale() external {
        ApexAbsencePredicate predicate = _predicate();
        vm.warp(AT);
        bool reverted;
        bytes4 sel;
        try
            predicate.proveAbsence(
                FIRMDALE_QNAME,
                _p1(_desiChain(DESI_NSEC3_0_SET, DESI_NSEC3_0_SIG))
            )
        {
            reverted = false;
        } catch (bytes memory reason) {
            reverted = true;
            sel = _selector(reason);
        }
        require(
            reverted,
            "CONTROL FAILED: desi's chain was accepted as a proof about firmdale"
        );
        require(
            sel == ApexAbsencePredicate.ProofNotFromZone.selector,
            "expected ProofNotFromZone"
        );
        // Attribution: the same proof, for its own zone's name, is accepted. So the revert is
        // the zone check and not the fixture.
        require(
            predicate
                .proveAbsence(
                    DESI_QNAME,
                    _p1(_desiChain(DESI_NSEC3_0_SET, DESI_NSEC3_0_SIG))
                )
                .proven,
            "attribution failed: the same proof must still work for _ens.desi."
        );
        require(
            keccak256(predicate.zoneOf(FIRMDALE_QNAME)) ==
                keccak256(FIRMDALE_NAME),
            "zoneOf(_ens.firmdale.) must be firmdale."
        );
    }

    /// **CONTROL, and changed check 2 against a forgery the caller fully controls.** A zone
    /// `baz.` with its own key signs a record whose span covers `hash(_ens.bar.)`. The oracle
    /// validates the chain completely. If the predicate trusted whichever zone the RRSIG claims
    /// to be from, this would release `_ens.bar.` on the say-so of a zone the attacker owns.
    /// Synthetic: no real zone is involved.
    function test_ControlForgedSignerZoneIsRefused() external {
        (
            DNSSECImpl oracle,
            DNSSEC.RRSetWithSignature memory dnskeySet,
            uint16 keytag
        ) = _zoneKeyChain(BAZ_NAME, 1);
        ApexAbsencePredicate predicate = new ApexAbsencePredicate(oracle);
        DNSSEC.RRSetWithSignature[]
            memory chain = new DNSSEC.RRSetWithSignature[](2);
        chain[0] = dnskeySet;
        chain[1] = _nsec3Record(
            _ownerName(ZERO_LABEL, BAZ_NAME),
            _nsec3Rdata(0, 0, hex"", MAX_HASH, BITMAP_A_ONLY),
            BAZ_NAME,
            2,
            keytag
        );

        // First: the oracle validates the forged chain end to end, with no real zone involved.
        RRUtils.SignedSet[] memory sets = oracle.verifyRRSetAt(chain, SYNTH_AT);
        require(
            keccak256(sets[sets.length - 1].signerName) == keccak256(BAZ_NAME),
            "setup error: the oracle did not validate the chain as signed by baz."
        );
        // Second: the span really would cover the queried hash, so the forgery is realistic
        // and the refusal is not an accident of the record's contents.
        require(
            predicate.coversHash(bytes20(0), MAX_HASH, BAR_ENS_HASH),
            "setup error: the forged span should cover hash(_ens.bar.)"
        );

        // Third: the predicate refuses it on the signer, before it reads the record at all.
        vm.warp(SYNTH_AT);
        bool reverted;
        bytes4 sel;
        try predicate.proveAbsence(BAR_ENS, _p1(chain)) {
            reverted = false;
        } catch (bytes memory reason) {
            reverted = true;
            sel = _selector(reason);
        }
        require(
            reverted,
            "CONTROL FAILED: a record signed by another zone was accepted"
        );
        require(
            sel == ApexAbsencePredicate.ProofNotFromZone.selector,
            "expected ProofNotFromZone"
        );
    }

    /// **CONTROL. An owner name that is not directly below the zone must revert.** The zone
    /// `bar.` signs a record owned by `<hash>.sub.bar.`, which the oracle accepts because the
    /// owner is a subdomain of the signer. An NSEC3 owner name is the hash prepended as **one**
    /// label to the zone apex, so a deeper name belongs to a chain hashed over a different
    /// zone's names and its span is not a span of hashes in this zone.
    function test_ControlOwnerNameBelowADeeperZoneIsRefused() external {
        (
            DNSSECImpl oracle,
            DNSSEC.RRSetWithSignature memory dnskeySet,
            uint16 keytag
        ) = _zoneKeyChain(BAR_NAME, 1);
        ApexAbsencePredicate predicate = new ApexAbsencePredicate(oracle);
        DNSSEC.RRSetWithSignature[]
            memory chain = new DNSSEC.RRSetWithSignature[](2);
        chain[0] = dnskeySet;
        chain[1] = _nsec3Record(
            _ownerName(ZERO_LABEL, SUB_BAR_NAME),
            _nsec3Rdata(0, 0, hex"", MAX_HASH, BITMAP_A_ONLY),
            BAR_NAME,
            3, // sub.bar. prefixed by the hash label is three labels
            keytag
        );

        // Attribution: the oracle accepts it, and the signer really is the right zone, so the
        // refusal is the owner-name check and nothing else.
        RRUtils.SignedSet[] memory sets = oracle.verifyRRSetAt(chain, SYNTH_AT);
        require(
            keccak256(sets[sets.length - 1].signerName) == keccak256(BAR_NAME),
            "setup error: the chain should be signed by bar."
        );

        vm.warp(SYNTH_AT);
        bool reverted;
        bytes4 sel;
        try predicate.proveAbsence(BAR_ENS, _p1(chain)) {
            reverted = false;
        } catch (bytes memory reason) {
            reverted = true;
            sel = _selector(reason);
        }
        require(
            reverted,
            "CONTROL FAILED: an owner name two labels below the zone was accepted"
        );
        require(
            sel == ApexAbsencePredicate.ProofOwnerNotInZone.selector,
            "expected ProofOwnerNotInZone"
        );
    }

    /// **CONTROL. Two NSEC3 records under one signature must revert.** They share an owner
    /// hash and carry different next-hashed-owner fields, so the second would widen the span of
    /// the first. Here the first record covers nothing and the second covers everything: if the
    /// predicate read both, it would report `_ens.bar.` absent.
    function test_ControlTwoRecordsUnderOneSignatureAreRefused() external {
        (
            DNSSECImpl oracle,
            DNSSEC.RRSetWithSignature memory dnskeySet,
            uint16 keytag
        ) = _zoneKeyChain(BAR_NAME, 1);
        ApexAbsencePredicate predicate = new ApexAbsencePredicate(oracle);
        DNSSEC.RRSetWithSignature[]
            memory chain = new DNSSEC.RRSetWithSignature[](2);
        chain[0] = dnskeySet;
        chain[1] = _twoNsec3RecordsOneSignature(
            _ownerName(ZERO_LABEL, BAR_NAME),
            _nsec3Rdata(0, 0, hex"", bytes20(uint160(1)), BITMAP_A_ONLY),
            _nsec3Rdata(0, 0, hex"", MAX_HASH, BITMAP_A_ONLY),
            BAR_NAME,
            2,
            keytag
        );

        // Attribution: the oracle accepts the shape, which is why the predicate has to refuse
        // it. `validateRRs` asks only that every record share one name, type and class.
        RRUtils.SignedSet[] memory sets = oracle.verifyRRSetAt(chain, SYNTH_AT);
        require(
            sets[sets.length - 1].typeCovered == DNSTYPE_NSEC3,
            "setup error: the oracle should accept two NSEC3 records in one set"
        );

        vm.warp(SYNTH_AT);
        bool reverted;
        bytes4 sel;
        try predicate.proveAbsence(BAR_ENS, _p1(chain)) {
            reverted = false;
        } catch (bytes memory reason) {
            reverted = true;
            sel = _selector(reason);
        }
        require(
            reverted,
            "CONTROL FAILED: two NSEC3 records under one signature were accepted"
        );
        require(
            sel == ApexAbsencePredicate.ProofNotOneRecord.selector,
            "expected ProofNotOneRecord"
        );
    }

    /// **CONTROL. A record one byte different from a signed one must be refused.** Corrupts the
    /// last byte of `desi`'s type bitmap, which adds the NSEC bit, and sends it under the
    /// original signature.
    function test_ControlTamperedRecordIsRefused() external {
        ApexAbsencePredicate predicate = _predicate();
        vm.warp(AT);
        bytes memory corrupt = DESI_NSEC3_0_SET;
        corrupt[corrupt.length - 1] = 0x13; // was 0x12
        bool reverted;
        try
            predicate.proveAbsence(
                DESI_QNAME,
                _p1(_desiChain(corrupt, DESI_NSEC3_0_SIG))
            )
        {
            reverted = false;
        } catch {
            reverted = true;
        }
        require(
            reverted,
            "CONTROL FAILED: a tampered NSEC3 record was accepted"
        );
        // Attribution: the uncorrupted sibling still verifies, so the refusal is the
        // corruption and not an unrelated fixture problem.
        require(
            predicate
                .proveAbsence(
                    DESI_QNAME,
                    _p1(_desiChain(DESI_NSEC3_0_SET, DESI_NSEC3_0_SIG))
                )
                .proven,
            "attribution failed: the uncorrupted record must still verify"
        );
    }

    // ========================================== the iteration cap, lower than the library's

    /// Required case: 20 iterations is accepted at the predicate. `firmdale` is the only zone
    /// in the root that publishes 20, and it is a real fixture, so the cap is measured against
    /// the highest count that exists rather than a synthetic one.
    function test_Iterations20AreAcceptedAtThePredicate() external {
        ApexAbsencePredicate predicate = _predicate();
        vm.warp(AT);
        (, bytes memory rdata) = _firstRecord(FIRMDALE_NSEC3_0_SET);
        require(
            predicate.readRdata(rdata).iterations == 20,
            "the firmdale fixture must declare 20 iterations"
        );
        require(
            predicate.maxIterations() == 20,
            "the predicate's cap must be 20"
        );
        require(
            predicate
                .proveAbsence(FIRMDALE_QNAME, _p1(_firmdaleChain()))
                .proven,
            "a 20-iteration zone must still be provable"
        );
    }

    /// Required case: 21 iterations is rejected **at the predicate**, while the library still
    /// hashes at 150. The two limits disagree on purpose: the library stays reusable and the
    /// permissionless entry point is where the bill is decided. See
    /// `ApexAbsencePredicate.MAX_ITERATIONS`.
    ///
    /// The 20-iteration sibling of the same synthetic record is proven first, so the refusal is
    /// attributable to the count alone.
    function test_Iterations21AreRejectedAtThePredicateOnly() external {
        // The library's own cap is 150 and it is reached through the predicate's pure
        // passthrough, so one contract shows both limits.
        ApexAbsencePredicate reader = _predicate();
        require(
            reader.hashName(BAR_ENS, hex"", 150) != bytes20(0),
            "the library must still hash at its own cap of 150"
        );
        require(
            reader.hashName(BAR_ENS, hex"", 21) == BAR_ENS_HASH_IT21,
            "the library must hash at 21, which the predicate refuses"
        );
        require(
            reader.hashName(BAR_ENS, hex"", 20) == BAR_ENS_HASH_IT20,
            "and at 20, which the predicate accepts"
        );

        // 20: accepted, and proven.
        (
            ApexAbsencePredicate at20,
            DNSSEC.RRSetWithSignature[][] memory proofs20
        ) = _barProof(
                ZERO_LABEL,
                _nsec3Rdata(0, 20, hex"", MAX_HASH, BITMAP_A_ONLY)
            );
        vm.warp(SYNTH_AT);
        require(
            at20.proveAbsence(BAR_ENS, proofs20).proven,
            "attribution failed: the same record at 20 iterations must be proven"
        );

        // 21: refused.
        (
            ApexAbsencePredicate at21,
            DNSSEC.RRSetWithSignature[][] memory proofs21
        ) = _barProof(
                ZERO_LABEL,
                _nsec3Rdata(0, 21, hex"", MAX_HASH, BITMAP_A_ONLY)
            );
        bool reverted;
        bytes4 sel;
        try at21.proveAbsence(BAR_ENS, proofs21) {
            reverted = false;
        } catch (bytes memory reason) {
            reverted = true;
            sel = _selector(reason);
        }
        require(
            reverted,
            "CONTROL FAILED: a record declaring 21 iterations was accepted"
        );
        require(
            sel == ApexAbsencePredicate.IterationCountAboveCap.selector,
            "expected IterationCountAboveCap, not the library's IterationCountTooHigh"
        );
    }

    // ================================================ the parameters are read from the record

    /// **CONTROL. The salt comes from each record, and the per-parameter hash cache must not
    /// leak one record's hashes into another's reading.** Two records, signed by the same zone,
    /// declaring different salts. The first covers `hash(_ens.bar.)` under no salt. The second
    /// **matches** `hash(_ens.bar.)` under salt `f00d` and lists TXT, so the correct reading is
    /// `Present` and the name is not released.
    ///
    /// A cache that reused the first record's hashes for the second would not see the match,
    /// would keep the first record's `NoName`, and would report the name absent while the zone
    /// publishes it. That is the exact false positive the strictness doctrine exists to stop,
    /// so this test is the cache's control and not a performance test.
    function test_ControlPerRecordSaltIsNotCachedAcrossParameters() external {
        (
            DNSSECImpl oracle,
            DNSSEC.RRSetWithSignature memory dnskeySet,
            uint16 keytag
        ) = _zoneKeyChain(BAR_NAME, 1);
        ApexAbsencePredicate predicate = new ApexAbsencePredicate(oracle);

        // Premise: the two salts give different hashes for the same name.
        require(
            predicate.hashName(BAR_ENS, hex"", 0) == BAR_ENS_HASH &&
                predicate.hashName(BAR_ENS, SALT_F00D, 0) ==
                BAR_ENS_HASH_F00D,
            "setup error: the two salts must give different hashes"
        );

        DNSSEC.RRSetWithSignature[]
            memory noSalt = new DNSSEC.RRSetWithSignature[](2);
        noSalt[0] = dnskeySet;
        noSalt[1] = _nsec3Record(
            _ownerName(ZERO_LABEL, BAR_NAME),
            _nsec3Rdata(0, 0, hex"", MAX_HASH, BITMAP_A_ONLY),
            BAR_NAME,
            2,
            keytag
        );
        DNSSEC.RRSetWithSignature[]
            memory salted = new DNSSEC.RRSetWithSignature[](2);
        salted[0] = dnskeySet;
        salted[1] = _nsec3Record(
            _ownerName(BAR_ENS_LABEL_F00D, BAR_NAME),
            _nsec3Rdata(0, 0, SALT_F00D, MAX_HASH, BITMAP_WITH_TXT),
            BAR_NAME,
            2,
            keytag
        );

        vm.warp(SYNTH_AT);
        // Attribution: the salted record alone reports Present, so the pair below is a test of
        // the cache and not of the record.
        ApexAbsencePredicate.Result memory alone = predicate.proveAbsence(
            BAR_ENS,
            _p1(salted)
        );
        require(
            alone.route == ApexAbsencePredicate.Route.Present,
            "setup error: the salted record alone should report Present"
        );

        ApexAbsencePredicate.Result memory result = predicate.proveAbsence(
            BAR_ENS,
            _p2(noSalt, salted)
        );
        require(
            !result.proven,
            "CONTROL FAILED: the salted record's match was missed and the name was released"
        );
        require(
            result.route == ApexAbsencePredicate.Route.Present,
            "expected Present: the second record matches the name under its own salt"
        );
        require(result.records == 2, "both records must be read");
    }

    /// The parameters of all three captured zones are read from the records, not assumed.
    /// `firmdale` is the counter-example to the modal set: 20 iterations and a four-byte salt,
    /// against the 1,222 zones that publish neither.
    function test_ParametersOfTheThreeZonesAreReadFromTheRecords() external {
        ApexAbsencePredicate predicate = _predicate();
        (, bytes memory firmdale) = _firstRecord(FIRMDALE_NSEC3_0_SET);
        NSEC3Utils.NSEC3Record memory f = predicate.readRdata(firmdale);
        require(f.iterations == 20, "firmdale: 20 iterations");
        require(
            keccak256(f.salt) == keccak256(hex"abbacafe"),
            "firmdale: salt abbacafe"
        );
        require(f.flags == 1, "firmdale: Opt-Out set");

        (, bytes memory desi) = _firstRecord(DESI_NSEC3_0_SET);
        NSEC3Utils.NSEC3Record memory d = predicate.readRdata(desi);
        require(d.iterations == 0 && d.salt.length == 0, "desi: no salt, 0 iterations");
        require(d.flags == 1, "desi: Opt-Out set");

        (, bytes memory nowruz) = _firstRecord(NOWRUZ_NSEC3_0_SET);
        require(
            predicate.readRdata(nowruz).flags == 0,
            "nowruz: Opt-Out clear"
        );
    }

    // ============================================================ the entry guards on the name

    /// **CONTROL, and changed check 3. The queried name must be exactly two labels.** One
    /// label is a top-level domain, which no zone proves absent from itself, and the root
    /// predicate is the contract that answers about it. Three labels is inside the zone but is
    /// not the question this contract answers.
    function test_ControlNameLabelCountIsRefusedAboveAndBelowTwo() external {
        ApexAbsencePredicate predicate = _predicate();
        vm.warp(AT);
        DNSSEC.RRSetWithSignature[][] memory proofs = _p1(
            _desiChain(DESI_NSEC3_0_SET, DESI_NSEC3_0_SIG)
        );

        // One label: desi. itself.
        require(
            _refusedWith(
                predicate,
                DESI_NAME,
                proofs,
                ApexAbsencePredicate.NotATopLevelChildName.selector
            ),
            "CONTROL FAILED: a one-label name was accepted"
        );
        // Three labels: a._ens.desi.
        require(
            _refusedWith(
                predicate,
                hex"0161045f656e73046465736900",
                proofs,
                ApexAbsencePredicate.NotATopLevelChildName.selector
            ),
            "CONTROL FAILED: a three-label name was accepted"
        );
        // The root itself.
        require(
            _refusedWith(
                predicate,
                hex"00",
                proofs,
                ApexAbsencePredicate.NotATopLevelChildName.selector
            ),
            "CONTROL FAILED: the root name was accepted"
        );
    }

    /// **CONTROL. An uppercase name is refused, not folded.** RFC 5155 section 5 hashes the
    /// canonical form, so `_ENS.DESI.` and `_ens.desi.` have the same hash in the zone and
    /// different hashes under a reader that does not fold. Refusing keeps the caller and the
    /// predicate agreed on which exact bytes were proven. The guard fires on the name's shape,
    /// before any proof is read.
    function test_ControlUppercaseNameIsRefused() external {
        ApexAbsencePredicate predicate = _predicate();
        vm.warp(AT);
        require(
            _refusedWith(
                predicate,
                hex"045f454e53044445534900", // _ENS.DESI.
                _p1(_desiChain(DESI_NSEC3_0_SET, DESI_NSEC3_0_SIG)),
                NSECUtils.NonCanonicalName.selector
            ),
            "CONTROL FAILED: an uppercase name was accepted"
        );
    }

    /// An empty chain inside the proofs array must not reach the oracle, per the documented
    /// rationale on `EmptyProof`.
    function test_ControlEmptyProofIsRefused() external {
        ApexAbsencePredicate predicate = _predicate();
        vm.warp(AT);
        DNSSEC.RRSetWithSignature[][] memory proofs = new DNSSEC.RRSetWithSignature[][](1);
        proofs[0] = new DNSSEC.RRSetWithSignature[](0);
        require(
            _refusedWith(
                predicate,
                DESI_QNAME,
                proofs,
                ApexAbsencePredicate.EmptyProof.selector
            ),
            "CONTROL FAILED: an empty proof chain was accepted"
        );
    }

    /// No proofs at all is not an error and is not absence. `requireAbsence` is the form that
    /// stops the transaction.
    function test_NoProofsIsUnprovenAndRequireAbsenceReverts() external {
        ApexAbsencePredicate predicate = _predicate();
        vm.warp(AT);
        DNSSEC.RRSetWithSignature[][] memory none = new DNSSEC.RRSetWithSignature[][](0);
        ApexAbsencePredicate.Result memory result = predicate.proveAbsence(
            DESI_QNAME,
            none
        );
        require(!result.proven && result.records == 0, "no proofs, nothing proven");
        require(
            _refusedWith(
                predicate,
                DESI_QNAME,
                none,
                ApexAbsencePredicate.AbsenceNotProven.selector
            ),
            "requireAbsence must revert when nothing is proven"
        );
    }

    /// The two name helpers, against the fixtures' own wire names.
    function test_ZoneOfAndEnsNameRoundTripTheFixtureNames() external {
        ApexAbsencePredicate predicate = _predicate();
        require(
            keccak256(predicate.zoneOf(DESI_QNAME)) == keccak256(DESI_NAME) &&
                keccak256(predicate.zoneOf(FIRMDALE_QNAME)) ==
                keccak256(FIRMDALE_NAME) &&
                keccak256(predicate.zoneOf(NOWRUZ_QNAME)) ==
                keccak256(NOWRUZ_NAME),
            "zoneOf must strip the first label"
        );
        require(
            keccak256(predicate.ensName(DESI_NAME)) == keccak256(DESI_QNAME) &&
                keccak256(predicate.ensName(FIRMDALE_NAME)) ==
                keccak256(FIRMDALE_QNAME) &&
                keccak256(predicate.ensName(NOWRUZ_NAME)) ==
                keccak256(NOWRUZ_QNAME),
            "ensName must rebuild the captured query names"
        );
        require(
            keccak256(predicate.wildcardName(DESI_NAME)) ==
                keccak256(hex"012a046465736900"),
            "wildcardName must build *.desi."
        );
    }

    // ============================================================== the RRSIG validity window

    /// Required case: a proof outside its validity window reverts, at both edges, using
    /// `NSEC3Fixtures`' own window constants. The block really is at those times, through
    /// `vm.warp`, so this exercises the same path a consumer uses.
    function test_ControlProofOutsideItsValidityWindowIsRefused() external {
        ApexAbsencePredicate predicate = _predicate();

        vm.warp(AFTER_EXPIRY);
        require(
            _refusedWith(
                predicate,
                DESI_QNAME,
                _p1(_desiChain(DESI_NSEC3_0_SET, DESI_NSEC3_0_SIG)),
                bytes4(0)
            ),
            "CONTROL FAILED: an expired proof was accepted"
        );

        vm.warp(BEFORE_INCEPTION);
        require(
            _refusedWith(
                predicate,
                DESI_QNAME,
                _p1(_desiChain(DESI_NSEC3_0_SET, DESI_NSEC3_0_SIG)),
                bytes4(0)
            ),
            "CONTROL FAILED: a premature proof was accepted"
        );

        // Attribution: the same proof inside the window is accepted, so both refusals are the
        // window and not the fixture.
        vm.warp(AT);
        require(
            predicate
                .proveAbsence(
                    DESI_QNAME,
                    _p1(_desiChain(DESI_NSEC3_0_SET, DESI_NSEC3_0_SIG))
                )
                .proven,
            "attribution failed: the same proof must be accepted inside the window"
        );
    }

    /// The entry point takes no time from the caller, so a captured proof stops working when
    /// its RRSIG expires. The only way to change the validation time is to change the block's.
    function test_ValidationTimeIsTheBlockAndNotAnArgument() external {
        ApexAbsencePredicate predicate = _predicate();
        vm.warp(AT);
        require(
            predicate
                .proveAbsence(
                    FIRMDALE_QNAME,
                    _p1(_firmdaleChain())
                )
                .proven,
            "proven inside the window"
        );
        vm.warp(AFTER_EXPIRY);
        require(
            _refusedWith(
                predicate,
                FIRMDALE_QNAME,
                _p1(_firmdaleChain()),
                bytes4(0)
            ),
            "the same call at a later block must fail, with no argument to change"
        );
    }

    // ------------------------------------------------------------------------- revert plumbing

    /// @dev True if the call reverted. When `want` is non-zero, the revert must also carry that
    ///      selector. `bytes4(0)` means "any revert", which is what an oracle-side refusal
    ///      needs, because the oracle's errors are its own.
    function _refusedWith(
        ApexAbsencePredicate predicate,
        bytes memory name,
        DNSSEC.RRSetWithSignature[][] memory proofs,
        bytes4 want
    ) internal view returns (bool) {
        bytes4 sel;
        bool reverted;
        if (want == ApexAbsencePredicate.AbsenceNotProven.selector) {
            try predicate.requireAbsence(name, proofs) {
                reverted = false;
            } catch (bytes memory reason) {
                reverted = true;
                sel = _selector(reason);
            }
        } else {
            try predicate.proveAbsence(name, proofs) {
                reverted = false;
            } catch (bytes memory reason) {
                reverted = true;
                sel = reason.length >= 4 ? _selector(reason) : bytes4(0);
            }
        }
        if (!reverted) {
            return false;
        }
        return want == bytes4(0) || sel == want;
    }

    /// @dev The owner name and rdata of the one NSEC3 record inside a captured set.
    ///      `readSignedSet` parses without verifying, so this is insensitive to the fixture
    ///      expiry.
    function _firstRecord(
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
}

/// Gas for the **release path** of the apex absence predicate, in the style of
/// `AbsenceGas.t.sol`: the oracle and the predicate are deployed in `setUp`, so neither
/// deployment is inside a measurement. That is the error that produced the ~2.67M figure
/// corrected in issue #2.
///
/// Two zones are the point of the table. `desi` publishes zero iterations, which is what 1,222
/// of the 1,308 NSEC3 zones in the root publish. `firmdale` publishes 20, which is the highest
/// count anywhere in the root and is this predicate's own cap. The difference between the two
/// rows is `SHA1.sol`, at about 31,810 gas for each hash.
///
/// Fixtures are the real four-link chains of 19 November 2026 and expire on 1 December 2026.
///
/// Run: forge test --match-contract ApexAbsenceGasTest -vv
contract ApexAbsenceGasTest is NSEC3Fixtures {
    address internal constant CONSOLE =
        0x000000000000000000636F6e736F6c652e6c6f67;

    ApexAbsencePredicate internal predicate;

    function setUp() public {
        predicate = new ApexAbsencePredicate(_realOracle());
    }

    function _log(string memory s) internal view {
        (bool ok, ) = CONSOLE.staticcall(
            abi.encodeWithSignature("log(string)", s)
        );
        ok;
    }

    function _u(uint256 v) internal pure returns (string memory) {
        if (v == 0) return "0";
        uint256 n = v;
        uint256 d;
        while (n != 0) {
            d++;
            n /= 10;
        }
        bytes memory b = new bytes(d);
        while (v != 0) {
            b[--d] = bytes1(uint8(48 + (v - (v / 10) * 10)));
            v /= 10;
        }
        return string(b);
    }

    function _pad(string memory s, uint256 w) internal pure returns (string memory) {
        bytes memory b = bytes(s);
        if (b.length >= w) return s;
        bytes memory out = new bytes(w);
        for (uint256 i; i < w; i++) {
            out[i] = i < w - b.length ? bytes1(" ") : b[i - (w - b.length)];
        }
        return string(out);
    }

    function _row(string memory what, uint256 used) internal view {
        _log(string.concat(_pad(_u(used), 10), "   ", what));
    }

    function _chainFor(
        bytes memory dsSet,
        bytes memory dsSig,
        bytes memory keySet,
        bytes memory keySig,
        bytes memory n3Set,
        bytes memory n3Sig
    ) internal pure returns (DNSSEC.RRSetWithSignature[][] memory proofs) {
        proofs = new DNSSEC.RRSetWithSignature[][](1);
        proofs[0] = _chain4(dsSet, dsSig, keySet, keySig, n3Set, n3Sig);
    }

    function test_apexAbsenceGas() public {
        vm.warp(AT);
        _log("gas          call");

        uint256 g0 = gasleft();
        predicate.requireAbsence(
            DESI_QNAME,
            _chainFor(
                DESI_DS_SET,
                DESI_DS_SIG,
                DESI_DNSKEY_SET,
                DESI_DNSKEY_SIG,
                DESI_NSEC3_0_SET,
                DESI_NSEC3_0_SIG
            )
        );
        _row(
            "requireAbsence, 1 proof, desi (0 iterations) - the release path",
            g0 - gasleft()
        );

        g0 = gasleft();
        predicate.requireAbsence(
            FIRMDALE_QNAME,
            _chainFor(
                FIRMDALE_DS_SET,
                FIRMDALE_DS_SIG,
                FIRMDALE_DNSKEY_SET,
                FIRMDALE_DNSKEY_SIG,
                FIRMDALE_NSEC3_0_SET,
                FIRMDALE_NSEC3_0_SIG
            )
        );
        _row(
            "requireAbsence, 1 proof, firmdale (20 iterations) - the release path",
            g0 - gasleft()
        );

        g0 = gasleft();
        predicate.proveAbsence(
            NOWRUZ_QNAME,
            _chainFor(
                NOWRUZ_DS_SET,
                NOWRUZ_DS_SIG,
                NOWRUZ_DNSKEY_SET,
                NOWRUZ_DNSKEY_SIG,
                NOWRUZ_NSEC3_0_SET,
                NOWRUZ_NSEC3_0_SIG
            )
        );
        _row("proveAbsence, 1 proof, nowruz (0 iterations)", g0 - gasleft());

        DNSSEC.RRSetWithSignature[][] memory three = new DNSSEC.RRSetWithSignature[][](3);
        three[0] = _chain4(DESI_DS_SET, DESI_DS_SIG, DESI_DNSKEY_SET, DESI_DNSKEY_SIG, DESI_NSEC3_0_SET, DESI_NSEC3_0_SIG);
        three[1] = _chain4(DESI_DS_SET, DESI_DS_SIG, DESI_DNSKEY_SET, DESI_DNSKEY_SIG, DESI_NSEC3_1_SET, DESI_NSEC3_1_SIG);
        three[2] = _chain4(DESI_DS_SET, DESI_DS_SIG, DESI_DNSKEY_SET, DESI_DNSKEY_SIG, DESI_NSEC3_2_SET, DESI_NSEC3_2_SIG);
        g0 = gasleft();
        predicate.requireAbsence(DESI_QNAME, three);
        _row(
            "requireAbsence, 3 proofs, desi - the complete RFC 5155 8.4 denial",
            g0 - gasleft()
        );

        // Attribution. The oracle's own verification of the same four-link chain, called
        // directly on the already deployed oracle. The difference between these rows and the
        // rows above is this contract's own reading, and for firmdale most of that difference
        // is `SHA1.sol`.
        DNSSEC oracle = predicate.oracle();
        g0 = gasleft();
        oracle.verifyRRSetAt(three[0], AT);
        _row("  of which: the oracle verifying desi's 4-link chain", g0 - gasleft());

        DNSSEC.RRSetWithSignature[] memory firmdaleChain = _chain4(
            FIRMDALE_DS_SET,
            FIRMDALE_DS_SIG,
            FIRMDALE_DNSKEY_SET,
            FIRMDALE_DNSKEY_SIG,
            FIRMDALE_NSEC3_0_SET,
            FIRMDALE_NSEC3_0_SIG
        );
        g0 = gasleft();
        oracle.verifyRRSetAt(firmdaleChain, AT);
        _row(
            "  of which: the oracle verifying firmdale's 4-link chain",
            g0 - gasleft()
        );

        g0 = gasleft();
        new ApexAbsencePredicate(oracle);
        _row("deployment of ApexAbsencePredicate", g0 - gasleft());
    }
}
