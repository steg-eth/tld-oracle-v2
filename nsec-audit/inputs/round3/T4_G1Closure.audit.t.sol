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

/// @notice ROUND 3, inputs T45 and T47 to T58. The G1 closure, the runtime apex, and liveness.
///
///         The synthetic chain inputs run against a second oracle whose algorithm 253 and
///         digest 253 accept any input, standing in for a signer that can sign anything. No
///         result from that oracle says what can be done against the live root.
contract T6G1Closure is Harness3 {
    uint8 internal constant DUMMY_ALG = 253;
    uint8 internal constant DUMMY_DIGEST = 253;

    bytes internal constant SY_ROOT = hex"00"; // .
    bytes internal constant SY_COM = hex"03636f6d00"; // com.
    bytes internal constant SY_NET = hex"036e657400"; // net.
    bytes internal constant SY_AAA = hex"0361616100"; // aaa.
    bytes internal constant SY_ZW = hex"027a7700"; // zw.
    bytes internal constant SY_ZZZ = hex"037a7a7a00"; // zzz.
    bytes internal constant SY_A_B = hex"0161" hex"016200"; // a.b.
    bytes internal constant BM_NS = hex"0006200000000003";

    DNSSECImpl internal dummyOracle;
    RootAbsencePredicate internal dummyPredicate;

    function setUp() public override {
        super.setUp();
        dummyOracle = new DNSSECImpl(_dsRR(SY_ROOT, _keytag(_key())));
        dummyOracle.setAlgorithm(DUMMY_ALG, new DummyAlgorithm());
        dummyOracle.setDigest(DUMMY_DIGEST, new DummyDigest());
        dummyPredicate = new RootAbsencePredicate(DNSSEC(dummyOracle));
    }

    // ---------------------------------------------------------------- synthetic chain builders

    function _key() internal pure returns (bytes memory) {
        return
            abi.encodePacked(
                uint16(0x0101),
                uint8(3),
                DUMMY_ALG,
                keccak256("synthetic key a"),
                keccak256("synthetic key b")
            );
    }

    function _keytag(bytes memory k) internal pure returns (uint16) {
        return RRUtils.computeKeytag(k);
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
        bytes memory signer,
        bytes memory rrs,
        uint32 inception
    ) internal pure returns (DNSSEC.RRSetWithSignature memory) {
        return
            DNSSEC.RRSetWithSignature(
                abi.encodePacked(
                    typeCovered,
                    DUMMY_ALG,
                    labels,
                    uint32(86400),
                    F.NSEC_EXPIRATION,
                    inception,
                    _keytag(_key()),
                    signer,
                    rrs
                ),
                hex"00"
            );
    }

    function _rootKeySet() internal pure returns (DNSSEC.RRSetWithSignature memory) {
        return _signed(48, 0, SY_ROOT, _rr(SY_ROOT, 48, _key()), F.NSEC_INCEPTION);
    }

    /// @dev One proof: synthetic root DNSKEY, then one NSEC set signed by the synthetic root.
    function _rootProof(
        uint8 labels,
        bytes memory rrs
    ) internal pure returns (DNSSEC.RRSetWithSignature[][] memory proofs) {
        return _rootProofAt(labels, rrs, F.NSEC_INCEPTION);
    }

    function _rootProofAt(
        uint8 labels,
        bytes memory rrs,
        uint32 inception
    ) internal pure returns (DNSSEC.RRSetWithSignature[][] memory proofs) {
        DNSSEC.RRSetWithSignature[] memory chain = new DNSSEC.RRSetWithSignature[](2);
        chain[0] = _rootKeySet();
        chain[1] = _signed(47, labels, SY_ROOT, rrs, inception);
        proofs = new DNSSEC.RRSetWithSignature[][](1);
        proofs[0] = chain;
    }

    function _nsec(
        bytes memory owner,
        bytes memory next
    ) internal pure returns (bytes memory) {
        return _rr(owner, 47, abi.encodePacked(next, BM_NS));
    }

    // ==================================================== restored from round 2, unchanged

    /// T45. The reachability envelope of `ProofNotOneRecord`. A signed set with no records
    ///      cannot reach the check: `DNSSECImpl.validateRRs` leaves the name empty and
    ///      `RRUtils.labelCount` trips its own `assert`. Root-signed header, no records.
    function test_T45_a_record_free_set_panics_upstream() external {
        bytes memory headerOnly = hex"002f0801000151806b0519d06af3e840223b00";
        vm.expectRevert(abi.encodePacked(hex"4e487b71", uint256(1)));
        predicate.proveNoDelegation(F.N_DOOSAN, _one(headerOnly, F.DOMAINS_SIG));
        emit log("T45 unchanged. Panic(0x01) from RRUtils, not ProofNotOneRecord(i, 0)");
    }

    // ============================== G1: is there a second class that still reads as closing?

    /// T47. **The second class, and it is not a shape defect.** The closing branch is now
    ///      keyed on `next == apex AND owner != apex`. `com. NSEC .` satisfies both. It is one
    ///      label, one record, root-signed, and structurally a perfectly well formed
    ///      zone-closing record. It is simply a lie about which name is last in the zone, and
    ///      it reports the live gTLD `.net` as absent. SYNTHETIC chain.
    ///
    ///      No local check can separate this from the genuine `zw. NSEC .`, because the
    ///      difference is which name the root zone actually ends with. That is zone-global
    ///      state and it changes whenever ICANN adds or removes a top-level domain. This audit
    ///      therefore proposes no further condition here. See the report for why that is a
    ///      statement about the limit of shape checking and not a defect in the fix.
    function test_T47_closing_record_with_the_wrong_owner() external {
        RootAbsencePredicate.Result memory r = dummyPredicate.proveNoDelegation(
            SY_NET,
            _rootProof(1, _nsec(SY_COM, SY_ROOT))
        );
        _report("T47 root-signed com. NSEC ., queried for live net.", r);
        _expect(r, true, RootAbsencePredicate.Route.NoName, 1);

        // It covers every name above com., not just net.
        RootAbsencePredicate.Result memory r2 = dummyPredicate.proveNoDelegation(
            SY_ZZZ,
            _rootProof(1, _nsec(SY_COM, SY_ROOT))
        );
        _expect(r2, true, RootAbsencePredicate.Route.NoName, 1);
        // And it does not cover a name below com., so the owner bound still holds.
        RootAbsencePredicate.Result memory r3 = dummyPredicate.proveNoDelegation(
            SY_AAA,
            _rootProof(1, _nsec(SY_COM, SY_ROOT))
        );
        _expect(r3, false, RootAbsencePredicate.Route.Unproven, 1);
        emit log("T47 a well formed closing record with a false owner. Signature-bounded only.");
    }

    /// T48. The closing branch, enumerated exhaustively over the shape space the entry point
    ///      admits. The depth rule holds every owner and next-owner name to zero or one label,
    ///      so the space is small enough to enumerate rather than sample. Pure calls, no DNS
    ///      data. This is the construction argument for G1.
    function test_T48_closing_branch_taxonomy() external {
        bytes memory apex = SY_ROOT;
        bytes memory high = SY_ZZZ; // the queried name, above com. and net.

        // next == apex, owner == apex. The apex cannot own the closing record.
        require(!predicate.coversName(apex, apex, high), ". NSEC . must cover nothing");
        // next == apex, owner is one label below it. This is the closing form.
        require(predicate.coversName(SY_COM, apex, high), "com. NSEC . is a closing record");
        require(predicate.coversName(SY_ZW, apex, hex"037a7a7a00"), "zw. NSEC . closes");
        // and the owner bound on the closing form
        require(!predicate.coversName(SY_COM, apex, SY_AAA), "closing covers nothing below");
        require(!predicate.coversName(SY_COM, apex, SY_COM), "closing excludes its own owner");

        // next != apex, next == owner. Round 2's first G1 half.
        require(!predicate.coversName(SY_COM, SY_COM, high), "com. NSEC com. covers nothing");
        // next != apex, next sorts below owner. Not a closing record, so it covers nothing.
        require(!predicate.coversName(SY_COM, SY_AAA, high), "com. NSEC aaa. covers nothing");
        require(!predicate.coversName(SY_COM, SY_AAA, SY_NET), "and nothing in between");
        // next != apex, next above owner. The ordinary gap.
        require(predicate.coversName(SY_COM, SY_NET, hex"03636f7000"), "an ordinary gap covers");
        require(!predicate.coversName(SY_COM, SY_NET, high), "and only inside itself");
        // owner == apex, next != apex. The apex's own record, which points forward.
        require(predicate.coversName(apex, SY_AAA, hex"02616100"), "apex record covers below aaa.");
        require(!predicate.coversName(apex, SY_AAA, high), "and nothing above aaa.");

        emit log("T48 exactly two shapes cover anything: the ordinary gap, and X. NSEC . for");
        emit log("T48 a one-label X. Every other shape in the admitted space covers nothing.");
    }

    /// T49. The round 2 audit's own proposed fix, implemented here and run against the inputs
    ///      that existed when it was proposed. The proposal was to require
    ///      `next == ROOT_NAME` on the closing branch. `. NSEC .` satisfies that condition,
    ///      so the proposal would have left round 2's T44 open. The second condition is what
    ///      closes it. Pure, no DNS data.
    function test_T49_the_round2_proposal_was_insufficient() external {
        // The proposed rule, as round 2 wrote it: owner < name, and either next == ROOT_NAME
        // or name < next.
        bytes memory apex = SY_ROOT;
        bool proposedOnRootToRoot = _proposedRule(apex, apex, SY_COM);
        require(proposedOnRootToRoot, "the round 2 proposal accepts . NSEC . as closing");
        require(
            !predicate.coversName(apex, apex, SY_COM),
            "the rule that shipped refuses it"
        );
        // Both rules agree on the shape the proposal was aimed at.
        require(!_proposedRule(SY_COM, SY_COM, SY_NET), "the proposal closes com. NSEC com.");
        require(!predicate.coversName(SY_COM, SY_COM, SY_NET), "so does the shipped rule");
        emit log("T49 the round 2 proposal closed one G1 half and left the other open");
    }

    /// @dev Round 2's proposed condition, for the comparison in T49 only.
    function _proposedRule(
        bytes memory owner,
        bytes memory next,
        bytes memory name
    ) internal pure returns (bool) {
        if (RRUtils.compareNames(owner, name) >= 0) return false;
        if (keccak256(next) == keccak256(hex"00")) return true; // the proposed condition
        return RRUtils.compareNames(name, next) < 0;
    }

    // ================================================= the apex as a runtime value

    /// T50. The apex that reaches the comparator is the signer name the oracle authenticated,
    ///      and it cannot differ from the root. Three measurements.
    ///      1. The signer check at `RootAbsencePredicate.sol:225` precedes the comparator call
    ///         at `:289`, over the same `signedSet`, which is never reassigned. So any record
    ///         that reaches the comparator has a signer name byte-equal to `hex"00"`.
    ///      2. The pinned three-argument helper and the four-argument helper given the root
    ///         agree on every real fixture, which is the same substitution the entry point
    ///         makes.
    ///      3. A record whose signer name is not the root never reaches the comparator, which
    ///         T23 measures as `ProofNotFromRoot`.
    function test_T50_apex_is_the_authenticated_signer_name() external {
        bytes[4] memory owners = [F.N_DOMAINS, F.N_AQ, F.N_ZW, F.N_ROOT];
        bytes[4] memory nexts = [F.N_DOT, hex"096171756172656c6c6500", F.N_ROOT, F.N_AAA];
        bytes[5] memory queries = [F.N_DOOSAN, F.N_AA, F.N_COM, F.N_ZZZZZZZZ, F.N_WILDCARD];
        for (uint256 i; i < owners.length; ++i) {
            for (uint256 j; j < queries.length; ++j) {
                require(
                    predicate.coversName(owners[i], nexts[i], queries[j]) ==
                        predicate.coversNameInZone(owners[i], nexts[i], queries[j], hex"00"),
                    "the pinned form and the explicit root form disagree"
                );
            }
        }
        emit log("T50 the pinned apex and the authenticated root signer name are the same value");
    }

    /// T51. Changing the signer name is caught twice, independently, before the comparator.
    ///      The signer name lives inside the bytes the signature covers, so it cannot be
    ///      edited. And `DNSSECImpl.verifySignature:193` requires the record owner to be at or
    ///      below the signer, so a signer name that is not an ancestor of the record is refused
    ///      by the oracle before the signature is even checked.
    ///      Root-signed `domains. NSEC dot.` with the signer name byte changed from the root
    ///      to `com.`, keeping the genuine signature.
    function test_T51_signer_name_cannot_be_edited() external {
        // The genuine set is a 19-byte header ending in the root signer name, then the record.
        bytes memory prefix = hex"002f0801000151806b0519d06af3e840223b"; // 18 bytes, no signer
        bytes memory rr = hex"07646f6d61696e7300002f000100015180000d03646f74000006200000000013";
        require(
            keccak256(abi.encodePacked(prefix, hex"00", rr)) == keccak256(F.DOMAINS_SET),
            "the split of DOMAINS_SET is wrong"
        );
        // signer name rewritten to com., which domains. is not below
        bytes memory forged = abi.encodePacked(prefix, SY_COM, rr);
        vm.expectRevert(
            abi.encodeWithSelector(
                DNSSECImpl.InvalidSignerName.selector,
                F.N_DOMAINS,
                SY_COM
            )
        );
        predicate.proveNoDelegation(F.N_DOOSAN, _one(forged, F.DOMAINS_SIG));
        emit log("T51 the oracle refuses the rewritten signer before any signature work");
    }

    /// T52. A child zone cannot sign a record about a top-level name. The oracle's own
    ///      `isSubdomainOf` test refuses it, independently of the predicate's signer check.
    ///      SYNTHETIC chain: root DNSKEY, DS for com., com. DNSKEY, then an NSEC set signed by
    ///      `com.` whose owner name is `zw.`.
    function test_T52_a_child_zone_cannot_sign_about_a_tld() external {
        DNSSEC.RRSetWithSignature[] memory chain = new DNSSEC.RRSetWithSignature[](4);
        chain[0] = _rootKeySet();
        chain[1] = _signed(43, 1, SY_ROOT, _dsRR(SY_COM, _keytag(_key())), F.NSEC_INCEPTION);
        chain[2] = _signed(48, 1, SY_COM, _rr(SY_COM, 48, _key()), F.NSEC_INCEPTION);
        chain[3] = _signed(47, 1, SY_COM, _nsec(SY_ZW, SY_ROOT), F.NSEC_INCEPTION);
        DNSSEC.RRSetWithSignature[][] memory proofs = new DNSSEC.RRSetWithSignature[][](1);
        proofs[0] = chain;
        vm.expectRevert(
            abi.encodeWithSelector(DNSSECImpl.InvalidSignerName.selector, SY_ZW, SY_COM)
        );
        dummyPredicate.proveNoDelegation(SY_ZZZ, proofs);
        emit log("T52 the oracle refuses a com.-signed record owned by zw., before the predicate");
    }

    /// T53. The four-argument public helper lets the caller choose the apex, which is what that
    ///      form is for and is also a degree of freedom a third party can get wrong. Named so
    ///      that the report can point at it. Pure, no DNS data.
    function test_T53_four_argument_helper_apex_freedom() external {
        // With the apex named as aaa., a record pointing at aaa. reads as a closing record.
        require(
            predicate.coversNameInZone(SY_COM, SY_AAA, SY_NET, SY_AAA),
            "named apex aaa. makes com. NSEC aaa. a closing record"
        );
        // The pinned form, read in the root, covers nothing there.
        require(!predicate.coversName(SY_COM, SY_AAA, SY_NET), "pinned to the root it does not");
        // And a caller who names an apex that is neither endpoint gets the ordinary branch.
        require(
            !predicate.coversNameInZone(SY_COM, SY_AAA, SY_NET, SY_ZW),
            "an unrelated apex leaves the ordinary branch, which covers nothing here"
        );
        emit log("T53 the apex argument changes the answer. The entry point does not expose it.");
    }

    // ============================================================ liveness, which now matters

    /// T54. The liveness trap this fix could have fallen into. `owner != apex` is scoped inside
    ///      the `next == apex` branch. If it were a precondition on the whole function, the
    ///      root's own record `. NSEC aaa.`, which is apex-owned, would cover nothing, and
    ///      every name below the first top-level domain would stop being provable. Measured
    ///      both ways: the apex-owned record still covers on the ordinary branch, and the
    ///      apex-owned closing shape still covers nothing. Root-signed for the first half.
    function test_T54_apex_owned_record_still_covers() external {
        RootAbsencePredicate.Result memory r = predicate.proveNoDelegation(
            F.N_AA,
            _one(F.ROOT_SET, F.ROOT_SIG)
        );
        _report("T54 aa. against the real apex record . NSEC aaa.", r);
        _expect(r, true, RootAbsencePredicate.Route.NoName, 1);
        require(r.apexWildcardDenied, "the apex record still denies the wildcard");

        require(
            predicate.coversName(SY_ROOT, SY_AAA, F.N_AA),
            "apex-owned ordinary record must still cover"
        );
        require(
            !predicate.coversName(SY_ROOT, SY_ROOT, F.N_AA),
            "apex-owned closing shape must cover nothing"
        );
        emit log("T54 the owner != apex condition is scoped to the closing branch only");
    }

    /// T55. Every real record shape still covers the gap it is supposed to cover. For each of
    ///      the four root-signed fixtures, the probe name is the owner's label with a trailing
    ///      zero byte, which sorts immediately above the owner and strictly below any next-owner
    ///      name above it. For the apex record the probe is `aa.`, which sorts below `aaa.`.
    ///      Root-signed. `output/root-chain-liveness.log` extends this to all 1437 records.
    function test_T55_every_real_gap_is_still_covered() external {
        // domains. NSEC dot.  probe domains\000.
        RootAbsencePredicate.Result memory a = predicate.proveNoDelegation(
            hex"08646f6d61696e7300" hex"00",
            _one(F.DOMAINS_SET, F.DOMAINS_SIG)
        );
        _expect(a, true, RootAbsencePredicate.Route.NoName, 1);
        // aq. NSEC aquarelle.  probe aq\000.
        RootAbsencePredicate.Result memory b = predicate.proveNoDelegation(
            hex"03617100" hex"00",
            _one(F.AQ_SET, F.AQ_SIG)
        );
        _expect(b, true, RootAbsencePredicate.Route.NoName, 1);
        // zw. NSEC .  the closing record, probe zw\000.
        RootAbsencePredicate.Result memory c = predicate.proveNoDelegation(
            hex"037a7700" hex"00",
            _one(F.ZW_SET, F.ZW_SIG)
        );
        _expect(c, true, RootAbsencePredicate.Route.NoName, 1);
        // . NSEC aaa.  probe aa.
        RootAbsencePredicate.Result memory d = predicate.proveNoDelegation(
            F.N_AA,
            _one(F.ROOT_SET, F.ROOT_SIG)
        );
        _expect(d, true, RootAbsencePredicate.Route.NoName, 1);
        emit log("T55 all four real shapes still cover a name inside their own gap");
    }

    /// T56. A record whose next-owner name sorts below its owner name without being the apex.
    ///      The old rule read that as a closing record. The new rule sends it to the ordinary
    ///      branch, where it covers nothing, and the call returns Unproven rather than
    ///      reverting. No record in the root zone has this shape. SYNTHETIC chain.
    function test_T56_backward_record_covers_nothing() external {
        RootAbsencePredicate.Result memory r = dummyPredicate.proveNoDelegation(
            SY_NET,
            _rootProof(1, _nsec(SY_COM, SY_AAA))
        );
        _report("T56 root-signed com. NSEC aaa., queried for net.", r);
        _expect(r, false, RootAbsencePredicate.Route.Unproven, 1);
        emit log("T56 a backward record is read, covers nothing, and does not revert");
    }

    // ================================================== what the dedupe changed

    /// T57. The dedupe key is `keccak256(signedSet.data)`, which is the authenticated record
    ///      bytes and not the signature. Two proofs carrying the same record under different
    ///      RRSIG inceptions therefore count as one record. The root re-signs at least daily,
    ///      so that pair is a shape a caller can really assemble. Whether one is the right
    ///      answer depends on what a consumer means by "records"; it is the right answer for
    ///      distinct records and the wrong one for independent signatures. SYNTHETIC chain,
    ///      because two root signatures over one record cannot be fabricated here.
    function test_T57_dedupe_ignores_the_signature() external {
        bytes memory rrs = _nsec(F.N_DOMAINS, F.N_DOT);
        DNSSEC.RRSetWithSignature[][] memory proofs = new DNSSEC.RRSetWithSignature[][](2);
        DNSSEC.RRSetWithSignature[] memory c0 = new DNSSEC.RRSetWithSignature[](2);
        c0[0] = _rootKeySet();
        c0[1] = _signed(47, 1, SY_ROOT, rrs, F.NSEC_INCEPTION);
        DNSSEC.RRSetWithSignature[] memory c1 = new DNSSEC.RRSetWithSignature[](2);
        c1[0] = _rootKeySet();
        c1[1] = _signed(47, 1, SY_ROOT, rrs, F.NSEC_INCEPTION + 1); // a later inception
        proofs[0] = c0;
        proofs[1] = c1;

        RootAbsencePredicate.Result memory r = dummyPredicate.proveNoDelegation(
            F.N_DOOSAN,
            proofs
        );
        _report("T57 one record under two different signatures", r);
        _expect(r, true, RootAbsencePredicate.Route.NoName, 1);
        require(
            r.inception == F.NSEC_INCEPTION,
            "the reported inception is the first deciding record's"
        );
        emit log("T57 records = 1 for two independently signed copies of one record");
    }

    /// T58. The cost claims in the new docstring, which names 281k for one proof, 552k for two,
    ///      234k inside the oracle, and 1.54M to deploy, measured on the `zw.` and apex
    ///      fixtures. Measured here on the same fixtures, with the same method. Root-signed.
    function test_T58_docstring_cost_claims() external {
        uint256 g0 = gasleft();
        DNSSECImpl o = new DNSSECImpl(F.ANCHORS);
        uint256 gOracle = g0 - gasleft();
        g0 = gasleft();
        RootAbsencePredicate p = new RootAbsencePredicate(DNSSEC(oracle));
        uint256 gPredicate = g0 - gasleft();
        o; // the oracle deployment is measured for context only

        // Cold first, then warm. The oracle's `anchors`, `algorithms[8]` and `digests[2]`
        // are cold storage on the first touch in a transaction, which is worth about 20k.
        // A real release transaction pays the cold price once.
        g0 = gasleft();
        oracle.verifyRRSetAt(_proof(F.ZW_SET, F.ZW_SIG), block.timestamp);
        uint256 gVerifyCold = g0 - gasleft();
        g0 = gasleft();
        oracle.verifyRRSetAt(_proof(F.ZW_SET, F.ZW_SIG), block.timestamp);
        uint256 gVerify = g0 - gasleft();

        g0 = gasleft();
        p.proveNoDelegation(F.N_ZZZZZZZZ, _one(F.ZW_SET, F.ZW_SIG));
        uint256 gOneCold = g0 - gasleft();
        g0 = gasleft();
        p.proveNoDelegation(F.N_ZZZZZZZZ, _one(F.ZW_SET, F.ZW_SIG));
        uint256 gOne = g0 - gasleft();

        g0 = gasleft();
        p.proveNoDelegation(
            F.N_ZZZZZZZZ,
            _two(F.ZW_SET, F.ZW_SIG, F.ROOT_SET, F.ROOT_SIG)
        );
        uint256 gTwo = g0 - gasleft();
        emit log_named_uint("T58 one proof, cold storage", gOneCold);
        emit log_named_uint("T58 oracle verifyRRSetAt one chain, cold storage", gVerifyCold);

        emit log_named_uint("T58 one proof, zw. fixture, docstring says 281000", gOne);
        emit log_named_uint("T58 two proofs, zw. plus apex, docstring says 552000", gTwo);
        emit log_named_uint("T58 oracle verifyRRSetAt one chain, docstring says 234000", gVerify);
        emit log_named_uint("T58 deploy RootAbsencePredicate, docstring says 1540000", gPredicate);
        emit log_named_uint("T58 deploy DNSSECImpl, for context", gOracle);
    }
}
