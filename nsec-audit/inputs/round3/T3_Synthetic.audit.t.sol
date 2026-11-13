// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {DNSSEC} from "src/contracts/dnssec-oracle/DNSSEC.sol";
import {DNSSECImpl} from "src/contracts/dnssec-oracle/DNSSECImpl.sol";
import {DummyAlgorithm} from "src/contracts/dnssec-oracle/algorithms/DummyAlgorithm.sol";
import {DummyDigest} from "src/contracts/dnssec-oracle/digests/DummyDigest.sol";
import {RRUtils} from "src/contracts/dnssec-oracle/RRUtils.sol";
import {RootAbsencePredicate} from "src/RootAbsencePredicate.sol";
import {NSECUtils} from "src/NSECUtils.sol";
import {Harness3} from "./Harness3.sol";
import {RootFixtures as F} from "../RootFixtures.sol";

/// @notice ROUND 3, inputs T20 to T28 and R37, R41, R43, R44. Everything here is SYNTHETIC.
///         Nothing is signed by the DNS root.
///
///         The chain inputs run against a SECOND oracle whose algorithm 253 and digest 253
///         accept any input, standing in for a signer that can sign anything. That reaches the
///         predicate's own checks on records the real root does not produce. No result from it
///         says what can be done against the live root. It says which of the predicate's
///         guarantees are in its own code.
contract T3Synthetic is Harness3 {
    uint8 internal constant DUMMY_ALG = 253;
    uint8 internal constant DUMMY_DIGEST = 253;

    bytes internal constant SY_ROOT = hex"00"; // .
    bytes internal constant SY_COM = hex"03636f6d00"; // com.
    bytes internal constant SY_NET = hex"036e657400"; // net.
    bytes internal constant SY_ZZZZ_COM = hex"047a7a7a7a03636f6d00"; // zzzz.com.
    bytes internal constant SY_ZZZ = hex"037a7a7a00"; // zzz.
    bytes internal constant SY_EXAMPLE = hex"076578616d706c6500"; // example.
    bytes internal constant SY_ZZZZ_EXAMPLE = hex"047a7a7a7a076578616d706c6500"; // zzzz.example.
    bytes internal constant SY_A_BBB = hex"0161" hex"03626262" hex"00"; // a.bbb.
    bytes internal constant SY_DOMAINS = hex"07646f6d61696e7300"; // domains.
    bytes internal constant SY_DOT = hex"03646f7400"; // dot.
    bytes internal constant SY_DOOSAN_UPPER = hex"06444f4f53414e00"; // DOOSAN.

    bytes internal constant BM_NS = hex"0006200000000003"; // NS RRSIG NSEC
    bytes internal constant BM_NO_NS = hex"0006000000000003"; // RRSIG NSEC, no NS

    DNSSECImpl internal dummyOracle;
    RootAbsencePredicate internal dummyPredicate;

    function setUp() public override {
        super.setUp();
        dummyOracle = new DNSSECImpl(_dsRR(SY_ROOT, _keytag(_key(DUMMY_ALG))));
        dummyOracle.setAlgorithm(DUMMY_ALG, new DummyAlgorithm());
        dummyOracle.setDigest(DUMMY_DIGEST, new DummyDigest());
        dummyPredicate = new RootAbsencePredicate(DNSSEC(dummyOracle));
    }

    // -------------------------------------------------------------- synthetic chain builders

    function _key(uint8 alg) internal pure returns (bytes memory) {
        return
            abi.encodePacked(
                uint16(0x0101),
                uint8(3),
                alg,
                keccak256("synthetic key a"),
                keccak256("synthetic key b")
            );
    }

    function _keytag(bytes memory keyrdata) internal pure returns (uint16) {
        return RRUtils.computeKeytag(keyrdata);
    }

    function _rr(
        bytes memory owner,
        uint16 rrtype,
        bytes memory rdata
    ) internal pure returns (bytes memory) {
        return
            abi.encodePacked(owner, rrtype, uint16(1), uint32(86400), uint16(rdata.length), rdata);
    }

    function _dsRR(bytes memory owner, uint16 keytag) internal pure returns (bytes memory) {
        return
            _rr(owner, 43, abi.encodePacked(keytag, DUMMY_ALG, DUMMY_DIGEST, keccak256("digest")));
    }

    function _signed(
        uint16 typeCovered,
        uint8 labels,
        uint16 keytag,
        bytes memory signer,
        bytes memory rrs
    ) internal pure returns (DNSSEC.RRSetWithSignature memory) {
        return
            DNSSEC.RRSetWithSignature(
                abi.encodePacked(
                    typeCovered,
                    DUMMY_ALG,
                    labels,
                    uint32(86400),
                    F.NSEC_EXPIRATION,
                    F.NSEC_INCEPTION,
                    keytag,
                    signer,
                    rrs
                ),
                hex"00"
            );
    }

    function _syntheticRootKeySet() internal pure returns (DNSSEC.RRSetWithSignature memory) {
        bytes memory k = _key(DUMMY_ALG);
        return _signed(48, 0, _keytag(k), SY_ROOT, _rr(SY_ROOT, 48, k));
    }

    function _syntheticRootProof(
        uint8 labels,
        bytes memory nsecRRs
    ) internal pure returns (DNSSEC.RRSetWithSignature[][] memory proofs) {
        bytes memory k = _key(DUMMY_ALG);
        DNSSEC.RRSetWithSignature[] memory chain = new DNSSEC.RRSetWithSignature[](2);
        chain[0] = _syntheticRootKeySet();
        chain[1] = _signed(47, labels, _keytag(k), SY_ROOT, nsecRRs);
        proofs = new DNSSEC.RRSetWithSignature[][](1);
        proofs[0] = chain;
    }

    function _nsec(
        bytes memory owner,
        bytes memory next,
        bytes memory bitmap
    ) internal pure returns (bytes memory) {
        return _rr(owner, 47, abi.encodePacked(next, bitmap));
    }

    // ============================================================= ported round 1 inputs

    /// T20 = I20. The comparator's boundaries and the wrap. The library is unchanged, so this
    ///      must be identical to round 1.
    function test_T20_comparator_boundaries_and_wrap() external {
        require(predicate.coversName(F.N_DOMAINS, F.N_DOT, F.N_DOOSAN), "gap must cover inside");
        require(!predicate.coversName(F.N_DOMAINS, F.N_DOT, F.N_DOMAINS), "owner is not covered");
        require(!predicate.coversName(F.N_DOMAINS, F.N_DOT, F.N_DOT), "next is not covered");
        require(predicate.coversName(F.N_ZW, F.N_ROOT, F.N_ZZZZZZZZ), "closing covers above");
        require(!predicate.coversName(F.N_ZW, F.N_ROOT, F.N_COM), "closing must not cover com.");
        require(!predicate.coversName(F.N_ZW, F.N_ROOT, F.N_ZW), "closing must not cover zw.");
        emit log("T20 unchanged from round 1");
    }

    /// T21 = I21. Uppercase sorts into a different gap.
    function test_T21_uppercase_lands_in_a_different_gap() external {
        require(!predicate.coversName(F.N_DOMAINS, F.N_DOT, SY_DOOSAN_UPPER), "not in that gap");
        require(
            predicate.coversName(F.N_ROOT, hex"0361616100", SY_DOOSAN_UPPER),
            "falls in the apex gap instead"
        );
        emit log("T21 unchanged from round 1");
    }

    /// T22. Round 2's R22 measured that the public three-argument `coversName` covered a
    ///      top-level name from a deep zone-closing record, because the comparator took the
    ///      closing branch on `next <= owner`. The three-argument form is now pinned to the
    ///      root apex, and neither shape has the root as its next-owner name, so both fall to
    ///      the ordinary branch and cover nothing. **This outcome changed.** The four-argument
    ///      form still covers them when the caller names the matching apex, which is what that
    ///      form is for. T51 is the finding about that freedom.
    function test_T22_public_comparator_no_longer_overaccepts_deep_records() external {
        require(
            !predicate.coversName(SY_ZZZZ_COM, SY_COM, SY_ZZZ),
            "pinned to the root, a com. closing record must cover nothing"
        );
        require(
            !predicate.coversName(SY_COM, SY_A_BBB, SY_NET),
            "pinned to the root, com. NSEC a.bbb. must cover nothing"
        );
        // The same two, read in the zone whose apex makes them closing records.
        require(
            predicate.coversNameInZone(SY_ZZZZ_COM, SY_COM, SY_ZZZ, SY_COM),
            "in the com. zone that record is the closing record"
        );
        emit log("T22 CHANGED from round 2. The pinned helper no longer over-accepts.");
    }

    /// T23 = I23. The signer check. The owner name in this chain is `zzzz.com.`, two labels, so
    ///      this also fixes the precedence: `ProofNotFromRoot` is checked before the record loop
    ///      and must therefore fire instead of `RecordNameTooDeep`.
    function test_T23_non_root_signer_refused_before_the_depth_check() external {
        bytes memory k = _key(DUMMY_ALG);
        uint16 tag = _keytag(k);
        DNSSEC.RRSetWithSignature[] memory chain = new DNSSEC.RRSetWithSignature[](4);
        chain[0] = _syntheticRootKeySet();
        chain[1] = _signed(43, 1, tag, SY_ROOT, _dsRR(SY_COM, tag));
        chain[2] = _signed(48, 1, tag, SY_COM, _rr(SY_COM, 48, k));
        chain[3] = _signed(47, 2, tag, SY_COM, _nsec(SY_ZZZZ_COM, SY_COM, BM_NS));

        RRUtils.SignedSet[] memory sets = dummyOracle.verifyRRSetAt(chain, block.timestamp);
        require(sets.length == 4, "the synthetic chain did not verify");

        DNSSEC.RRSetWithSignature[][] memory proofs = new DNSSEC.RRSetWithSignature[][](1);
        proofs[0] = chain;
        vm.expectRevert(
            abi.encodeWithSelector(
                RootAbsencePredicate.ProofNotFromRoot.selector,
                uint256(0),
                SY_COM
            )
        );
        dummyPredicate.proveNoDelegation(SY_ZZZ, proofs);
        emit log("T23 the signer check still fires, and it fires before the new depth check");
    }

    /// T24 = I24. Round 1's finding F2a. A root-signed NSEC record whose owner name is two
    ///      labels deep. Round 1: `proven = true` for the top-level name `zzz.`.
    ///      Expect now: `RecordNameTooDeep`.
    function test_T24_two_label_owner_now_refused() external {
        vm.expectRevert(
            abi.encodeWithSelector(
                RootAbsencePredicate.RecordNameTooDeep.selector,
                uint256(0),
                SY_ZZZZ_EXAMPLE
            )
        );
        dummyPredicate.proveNoDelegation(
            SY_ZZZ,
            _syntheticRootProof(2, _nsec(SY_ZZZZ_EXAMPLE, SY_EXAMPLE, BM_NS))
        );
        emit log("T24 F2a is closed. The owner name depth is checked.");
    }

    /// T25 = I25. Round 1's finding F2b. Two NSEC records in one signed set, the second with
    ///      the root as its next-owner name. Round 1: `proven = true` for the live gTLD `.dot`.
    ///      Expect now: `ProofNotOneRecord`.
    function test_T25_two_records_in_one_set_now_refused() external {
        bytes memory rrs = abi.encodePacked(
            _nsec(SY_DOMAINS, SY_DOT, BM_NS),
            _nsec(SY_DOMAINS, SY_ROOT, BM_NS)
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                RootAbsencePredicate.ProofNotOneRecord.selector,
                uint256(0),
                uint256(2)
            )
        );
        dummyPredicate.proveNoDelegation(SY_DOT, _syntheticRootProof(1, rrs));
        emit log("T25 F2b is closed. Exactly one record per proof.");
    }

    /// T26 = I26. The NS bit route, which the new checks must not break. One record, depth 1.
    function test_T26_no_ns_bit_route_still_works() external {
        RootAbsencePredicate.Result memory withNs = dummyPredicate.proveNoDelegation(
            SY_DOT,
            _syntheticRootProof(1, _nsec(SY_DOT, SY_EXAMPLE, BM_NS))
        );
        _report("R26a dot. present with the NS bit set", withNs);
        _expect(withNs, false, RootAbsencePredicate.Route.Delegated, 1);

        RootAbsencePredicate.Result memory noNs = dummyPredicate.proveNoDelegation(
            SY_DOT,
            _syntheticRootProof(1, _nsec(SY_DOT, SY_EXAMPLE, BM_NO_NS))
        );
        _report("R26b dot. present with the NS bit clear", noNs);
        _expect(noNs, true, RootAbsencePredicate.Route.NoNsBit, 1);
    }

    /// T27 = I27. The type bitmap reader. `NSECUtils.hasType` is byte-identical to round 1, so
    ///      round 1's finding F5 must still be there. Measured, not assumed.
    function test_T27_bitmap_reader_unchanged() external {
        require(predicate.hasType(BM_NS, 2), "NS must be found");
        require(!predicate.hasType(BM_NS, 43), "DS must not be found");
        require(!predicate.hasType(BM_NO_NS, 2), "NS must not be found when clear");

        vm.expectRevert(
            abi.encodeWithSelector(NSECUtils.InvalidTypeBitmapBlock.selector, uint8(0), uint8(0))
        );
        predicate.hasType(hex"0000", 2);
        vm.expectRevert(
            abi.encodeWithSelector(NSECUtils.TruncatedTypeBitmap.selector, uint256(0))
        );
        predicate.hasType(hex"000620000000", 2);
        vm.expectRevert(
            abi.encodeWithSelector(
                NSECUtils.TypeBitmapWindowsOutOfOrder.selector,
                uint8(0),
                uint8(0)
            )
        );
        predicate.hasType(hex"00062000000000030006000000000003", 2);
        vm.expectRevert(abi.encodeWithSelector(NSECUtils.EmptyTypeBitmap.selector));
        predicate.hasType(hex"", 2);

        // Round 1's F5, unchanged. A bitmap that omits window 0 reports NS as absent.
        require(
            !predicate.hasType(hex"0106200000000003", 2),
            "a bitmap with no window 0 still reports NS as absent"
        );
        emit log("T27 F5 is NOT fixed. hasType is byte-identical to round 1.");
    }

    // ======================================================= new attacks on the new surface

    /// T37. The next-owner side of the depth check. The docstring at `RecordNameTooDeep` names
    ///      `com. NSEC a.bbb.` as the shape to stop. Owner is one label and passes. The record
    ///      is refused on the next-owner name. SYNTHETIC chain.
    function test_T37_deep_next_owner_refused() external {
        vm.expectRevert(
            abi.encodeWithSelector(
                RootAbsencePredicate.RecordNameTooDeep.selector,
                uint256(0),
                SY_A_BBB
            )
        );
        dummyPredicate.proveNoDelegation(SY_NET, _syntheticRootProof(1, _nsec(SY_COM, SY_A_BBB, BM_NS)));
        emit log("T37 the next-owner name is checked too, and the error names it");
    }

    /// T41. Two IDENTICAL NSEC records in one set. The input says nothing false. It is refused
    ///      anyway, because the count is checked and not the content. SYNTHETIC chain.
    ///      R38, which is root-signed, shows this shape cannot reach the predicate from the
    ///      real root, because the signature is over the de-duplicated canonical set.
    function test_T41_two_identical_records_refused() external {
        bytes memory one = _nsec(SY_DOMAINS, SY_DOT, BM_NS);
        vm.expectRevert(
            abi.encodeWithSelector(
                RootAbsencePredicate.ProofNotOneRecord.selector,
                uint256(0),
                uint256(2)
            )
        );
        dummyPredicate.proveNoDelegation(F.N_DOOSAN, _syntheticRootProof(1, abi.encodePacked(one, one)));
        emit log("T41 a duplicated but identical record is refused on the count");
    }

    /// T43. **The shape the new checks do not catch.** `com. NSEC com.` has a next-owner name
    ///      equal to its owner name. Both names are one label, so the depth check passes. There
    ///      is one record, so the count check passes. The signer is the root. `coversName` then
    ///      reads `next <= owner` as the record that closes the zone, and the record covers
    ///      every top-level name above `com.`. SYNTHETIC chain. `.net` is live.
    function test_T43_next_equal_to_owner_is_now_unproven() external {
        RootAbsencePredicate.Result memory r = dummyPredicate.proveNoDelegation(
            SY_NET,
            _syntheticRootProof(1, _nsec(SY_COM, SY_COM, BM_NS))
        );
        _report("T43 root-signed com. NSEC com., queried for live net.", r);
        // Round 2: proven, NoName. Round 3: nothing decided, and no revert, which is the
        // narrowing the builder described. The record is read and covers nothing.
        _expect(r, false, RootAbsencePredicate.Route.Unproven, 1);
        emit log("T43 CHANGED. G1 half one is closed, as Unproven and not as a revert.");
    }

    /// T44. The same with both names at the root. `. NSEC .` passes every new check and covers
    ///      every top-level name there is. SYNTHETIC chain.
    function test_T44_root_to_root_record_is_now_unproven() external {
        RootAbsencePredicate.Result memory r = dummyPredicate.proveNoDelegation(
            F.N_COM,
            _syntheticRootProof(0, _nsec(SY_ROOT, SY_ROOT, BM_NS))
        );
        _report("T44 root-signed . NSEC ., queried for live com.", r);
        // Round 2: proven for every top-level name. This is the shape that the audit's own
        // proposed fix in round 2 would NOT have closed, because its next-owner name IS the
        // root, so a `next == ROOT_NAME` condition is satisfied by it. The second condition,
        // `owner != apex`, is what closes it.
        _expect(r, false, RootAbsencePredicate.Route.Unproven, 1);

        RootAbsencePredicate.Result memory r2 = dummyPredicate.proveNoDelegation(
            SY_NET,
            _syntheticRootProof(0, _nsec(SY_ROOT, SY_ROOT, BM_NS))
        );
        _expect(r2, false, RootAbsencePredicate.Route.Unproven, 1);
        emit log("T44 CHANGED. G1 half two is closed by the owner != apex condition.");
    }
}

/// @notice ROUND 3, input R28. The comparator fuzz, repeated unchanged, because
///         `NSECUtils.coversName` is byte-identical to round 1.
contract T4ComparatorFuzz is Harness3 {
    bytes[] internal names;

    function setUp() public override {
        super.setUp();
        names.push(hex"00"); // .
        names.push(hex"016100"); // a.
        names.push(hex"016200"); // b.
        names.push(hex"0361616100"); // aaa.
        names.push(hex"03636f6d00"); // com.
        names.push(hex"07646f6d61696e7300"); // domains.
        names.push(hex"03646f7400"); // dot.
        names.push(hex"027a7700"); // zw.
        names.push(hex"087a7a7a7a7a7a7a7a00"); // zzzzzzzz.
        names.push(hex"012a00"); // *.
        names.push(hex"047a7a7a7a03636f6d00"); // zzzz.com.
        names.push(hex"01610161" hex"00"); // a.a.
    }

    /// @dev The rule, restated here from RFC 4034 section 4.1.1 rather than from the
    ///      implementation: a record denies `q` when `owner < q`, and either its next-owner
    ///      name is the zone apex while its owner name is not, which is the record that closes
    ///      the zone, or `q < next`.
    function _rule(
        bytes memory owner,
        bytes memory next,
        bytes memory q,
        bytes memory apex
    ) internal pure returns (bool) {
        if (RRUtils.compareNames(owner, q) >= 0) return false;
        if (keccak256(next) == keccak256(apex)) {
            return keccak256(owner) != keccak256(apex);
        }
        return RRUtils.compareNames(q, next) < 0;
    }

    function testFuzz_T28_coversName_matches_the_rule(
        uint8 i,
        uint8 j,
        uint8 k,
        uint8 a
    ) external view {
        uint256 n = names.length;
        bytes memory owner = names[i % n];
        bytes memory next = names[j % n];
        bytes memory q = names[k % n];
        bytes memory apex = names[a % n];

        // the three-argument form, pinned to the root
        require(
            predicate.coversName(owner, next, q) == _rule(owner, next, q, hex"00"),
            "coversName disagrees with the rule in the root zone"
        );
        // the four-argument form, with the apex fuzzed as well
        require(
            predicate.coversNameInZone(owner, next, q, apex) == _rule(owner, next, q, apex),
            "coversNameInZone disagrees with the rule"
        );
    }
}
