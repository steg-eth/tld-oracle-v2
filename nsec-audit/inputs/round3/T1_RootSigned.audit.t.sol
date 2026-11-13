// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {DNSSEC} from "src/contracts/dnssec-oracle/DNSSEC.sol";
import {DNSSECImpl} from "src/contracts/dnssec-oracle/DNSSECImpl.sol";
import {RSASHA256Algorithm} from "src/contracts/dnssec-oracle/algorithms/RSASHA256Algorithm.sol";
import {SHA256Digest} from "src/contracts/dnssec-oracle/digests/SHA256Digest.sol";
import {RootAbsencePredicate} from "src/RootAbsencePredicate.sol";
import {NSECUtils} from "src/NSECUtils.sol";
import {Harness3} from "./Harness3.sol";
import {RootFixtures as F} from "../RootFixtures.sol";

/// @notice ROUND 3, inputs T01 to T19 and T29 to R30. Round 1's I01 to I19 and I29 to I30,
///         ported to the two-argument entry points. The fixtures are the same bytes. The only
///         mechanical change is that the validation time now comes from the block clock, which
///         `Harness3.setUp` warps to `F.INSIDE`.
///
///         Every input is root-signed material from 198.41.0.4, 11 November 2026. T15 is the
///         one exception and says so.
contract T1RootSigned is Harness3 {
    // =========================================================== positive controls, first

    /// T01 = I01. An ordinary gap. Round 1: proven, NoName, 1 record. Expect no change.
    function test_T01_control_ordinary_gap_doosan() external {
        RootAbsencePredicate.Result memory r = predicate.proveNoDelegation(
            F.N_DOOSAN,
            _one(F.DOMAINS_SET, F.DOMAINS_SIG)
        );
        _report("T01 ordinary gap, doosan. against domains. NSEC dot.", r);
        _expect(r, true, RootAbsencePredicate.Route.NoName, 1);
        require(keccak256(r.owner) == keccak256(F.N_DOMAINS), "deciding owner is not domains.");
        require(keccak256(r.next) == keccak256(F.N_DOT), "deciding next is not dot.");
        require(r.inception == F.NSEC_INCEPTION, "inception not carried from the RRSIG");
        require(!r.apexWildcardDenied, "one gap record must not deny the apex wildcard");
    }

    /// T02 = I02. The wrap at the end of the zone. Round 1: proven, NoName. Expect no change.
    ///      The closing record's next-owner name is the root, which has zero labels. The new
    ///      depth check must let a zero-label next-owner name through.
    function test_T02_control_zone_wrap_closing_record() external {
        RootAbsencePredicate.Result memory r = predicate.proveNoDelegation(
            F.N_ZZZZZZZZ,
            _one(F.ZW_SET, F.ZW_SIG)
        );
        _report("T02 zone wrap, zzzzzzzz. against zw. NSEC .", r);
        _expect(r, true, RootAbsencePredicate.Route.NoName, 1);
        require(keccak256(r.owner) == keccak256(F.N_ZW), "deciding owner is not zw.");
        require(keccak256(r.next) == keccak256(F.N_ROOT), "deciding next is not the root");
    }

    // ============================================================= ported round 1 inputs

    /// T03 = I03. A live ccTLD with NS and no DS.
    function test_T03_live_aq_ns_present_no_ds() external {
        RootAbsencePredicate.Result memory r = predicate.proveNoDelegation(
            F.N_AQ,
            _one(F.AQ_SET, F.AQ_SIG)
        );
        _report("T03 live ccTLD aq., its own record", r);
        _expect(r, false, RootAbsencePredicate.Route.Delegated, 1);
        bytes memory rdata = hex"096171756172656c6c65000006200000000003";
        require(predicate.rdataHasType(rdata, 2), "NS must be present in the aq. bitmap");
        require(!predicate.rdataHasType(rdata, 43), "DS must be absent from the aq. bitmap");
        vm.expectRevert(
            abi.encodeWithSelector(
                RootAbsencePredicate.AbsenceNotProven.selector,
                F.N_AQ,
                RootAbsencePredicate.Route.Delegated
            )
        );
        predicate.requireNoDelegation(F.N_AQ, _one(F.AQ_SET, F.AQ_SIG));
    }

    /// T04 = I04. The specification's named control. `com.` is not covered by `zw. NSEC .`.
    function test_T04_wrap_must_not_cover_com() external {
        RootAbsencePredicate.Result memory r = predicate.proveNoDelegation(
            F.N_COM,
            _one(F.ZW_SET, F.ZW_SIG)
        );
        _report("T04 com. against the closing record zw. NSEC .", r);
        _expect(r, false, RootAbsencePredicate.Route.Unproven, 1);
    }

    /// T05 = I05. The same against a live ccTLD with no DS.
    function test_T05_wrap_must_not_cover_aq() external {
        RootAbsencePredicate.Result memory r = predicate.proveNoDelegation(
            F.N_AQ,
            _one(F.ZW_SET, F.ZW_SIG)
        );
        _report("T05 aq. against the closing record zw. NSEC .", r);
        _expect(r, false, RootAbsencePredicate.Route.Unproven, 1);
    }

    /// T06 = I06. The next-owner boundary at the apex. `.aaa` is live.
    function test_T06_apex_next_owner_is_live_aaa() external {
        RootAbsencePredicate.Result memory r = predicate.proveNoDelegation(
            F.N_AAA,
            _one(F.ROOT_SET, F.ROOT_SIG)
        );
        _report("T06 live aaa., the next-owner of . NSEC aaa.", r);
        _expect(r, false, RootAbsencePredicate.Route.Unproven, 1);
        require(r.apexWildcardDenied, "the apex record denies *. and must report it");
    }

    /// T07 = I07. The owner boundary. `.domains` is live.
    function test_T07_gap_owner_is_live_domains() external {
        RootAbsencePredicate.Result memory r = predicate.proveNoDelegation(
            F.N_DOMAINS,
            _one(F.DOMAINS_SET, F.DOMAINS_SIG)
        );
        _report("T07 live domains., the owner of domains. NSEC dot.", r);
        _expect(r, false, RootAbsencePredicate.Route.Delegated, 1);
    }

    /// T08 = I08. The next-owner boundary of an ordinary gap. `.dot` is live.
    function test_T08_gap_next_owner_is_live_dot() external {
        RootAbsencePredicate.Result memory r = predicate.proveNoDelegation(
            F.N_DOT,
            _one(F.DOMAINS_SET, F.DOMAINS_SIG)
        );
        _report("T08 live dot., the next-owner of domains. NSEC dot.", r);
        _expect(r, false, RootAbsencePredicate.Route.Unproven, 1);
    }

    /// T09 = I09. The bottom of the zone, through a zero-label owner name. The new depth check
    ///      must let a zero-label owner name through.
    function test_T09_apex_record_covers_low_name_aa() external {
        RootAbsencePredicate.Result memory r = predicate.proveNoDelegation(
            F.N_AA,
            _one(F.ROOT_SET, F.ROOT_SIG)
        );
        _report("T09 aa. against the apex record . NSEC aaa.", r);
        _expect(r, true, RootAbsencePredicate.Route.NoName, 1);
        require(keccak256(r.owner) == keccak256(F.N_ROOT), "deciding owner is not the root");
        require(r.apexWildcardDenied, "the apex record denies *. as well");
    }

    /// T10 = I10. The two records the root returns for an absent name, as two proofs.
    function test_T10_two_independent_proofs_doosan() external {
        RootAbsencePredicate.Result memory r = predicate.proveNoDelegation(
            F.N_DOOSAN,
            _two(F.DOMAINS_SET, F.DOMAINS_SIG, F.ROOT_SET, F.ROOT_SIG)
        );
        _report("T10 doosan. with both records the root returns", r);
        _expect(r, true, RootAbsencePredicate.Route.NoName, 2);
        require(r.apexWildcardDenied, "the apex record in proof 2 denies *.");
    }

    /// T11 replaces I11. Round 1's finding F1. The same proof, at a 2031 block, with no way to
    ///      supply a time. Round 1: `proven = true` at `at` inside the window while the block
    ///      clock was 2031. Expect now: refused, because the only clock is the chain's.
    function test_T11_stale_proof_is_now_refused() external {
        vm.warp(1925000000); // the same block time round 1 used, 2031
        // The first set in the chain is the root DNSKEY set, which expires 2026-12-01.
        vm.expectRevert(
            abi.encodeWithSelector(
                DNSSECImpl.SignatureExpired.selector,
                uint32(1796083200),
                uint32(1925000000)
            )
        );
        predicate.proveNoDelegation(F.N_DOOSAN, _one(F.DOMAINS_SET, F.DOMAINS_SIG));

        // And through the other surviving entry point. `proveNoDelegationNow` was removed in
        // round 3, so there are two entry points now, not three. T42 measures its removal.
        vm.expectRevert(
            abi.encodeWithSelector(
                DNSSECImpl.SignatureExpired.selector,
                uint32(1796083200),
                uint32(1925000000)
            )
        );
        predicate.requireNoDelegation(F.N_DOOSAN, _one(F.DOMAINS_SET, F.DOMAINS_SIG));
        emit log("T11 both surviving entry points refuse the stale proof at a 2031 block");
    }

    /// T12 replaces I12. Round 1 showed that `at` above 2^32 aliased into the window. There is
    ///      no `at`. The remaining question is the block clock itself, which T34 takes.
    ///      Here: the fixture window's own edges, driven by the block clock.
    function test_T12_window_edges_by_block_clock() external {
        vm.warp(uint256(F.NSEC_EXPIRATION) + 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                DNSSECImpl.SignatureExpired.selector,
                F.NSEC_EXPIRATION,
                uint32(F.NSEC_EXPIRATION) + 1
            )
        );
        predicate.proveNoDelegation(F.N_DOOSAN, _one(F.DOMAINS_SET, F.DOMAINS_SIG));

        vm.warp(uint256(F.NSEC_INCEPTION) - 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                DNSSECImpl.SignatureNotValidYet.selector,
                F.NSEC_INCEPTION,
                uint32(F.NSEC_INCEPTION) - 1
            )
        );
        predicate.proveNoDelegation(F.N_DOOSAN, _one(F.DOMAINS_SET, F.DOMAINS_SIG));

        // And inside, one second after inception and one second before expiration.
        vm.warp(uint256(F.NSEC_INCEPTION));
        RootAbsencePredicate.Result memory a = predicate.proveNoDelegation(
            F.N_DOOSAN,
            _one(F.DOMAINS_SET, F.DOMAINS_SIG)
        );
        _expect(a, true, RootAbsencePredicate.Route.NoName, 1);
        vm.warp(uint256(F.NSEC_EXPIRATION));
        RootAbsencePredicate.Result memory b = predicate.proveNoDelegation(
            F.N_DOOSAN,
            _one(F.DOMAINS_SET, F.DOMAINS_SIG)
        );
        _expect(b, true, RootAbsencePredicate.Route.NoName, 1);
        emit log("T12 the window is closed at both edges and open at both endpoints");
    }

    /// T13 = I13. Two NSEC records in one chain, refused by the oracle's folding.
    function test_T13_two_nsec_records_in_one_chain_refused() external {
        DNSSEC.RRSetWithSignature[][] memory proofs = new DNSSEC.RRSetWithSignature[][](1);
        DNSSEC.RRSetWithSignature[] memory chain = new DNSSEC.RRSetWithSignature[](3);
        chain[0] = DNSSEC.RRSetWithSignature(F.DNSKEY_SET, F.DNSKEY_SIG);
        chain[1] = DNSSEC.RRSetWithSignature(F.ZW_SET, F.ZW_SIG);
        chain[2] = DNSSEC.RRSetWithSignature(F.ROOT_SET, F.ROOT_SIG);
        proofs[0] = chain;
        vm.expectRevert(
            abi.encodeWithSelector(DNSSECImpl.InvalidProofType.selector, uint16(47))
        );
        predicate.proveNoDelegation(F.N_ZZZZZZZZ, proofs);
    }

    /// T14 = I14, folded into T12 because the window can only be driven by the block clock now.
    ///      This input keeps the name and checks the DNSKEY window is the outer one, so that a
    ///      refusal at the NSEC edges in T12 is attributable to the NSEC set.
    function test_T14_dnskey_window_contains_the_nsec_window() external {
        // One second before the NSEC inception, the DNSKEY set alone still verifies.
        vm.warp(uint256(F.NSEC_INCEPTION) - 1);
        DNSSEC.RRSetWithSignature[] memory keyOnly = new DNSSEC.RRSetWithSignature[](1);
        keyOnly[0] = DNSSEC.RRSetWithSignature(F.DNSKEY_SET, F.DNSKEY_SIG);
        oracle.verifyRRSetAt(keyOnly, block.timestamp);
        // One second after the NSEC expiration, likewise.
        vm.warp(uint256(F.NSEC_EXPIRATION) + 1);
        oracle.verifyRRSetAt(keyOnly, block.timestamp);
        emit log("T14 the DNSKEY window strictly contains the NSEC window, as in round 1");
    }

    /// T15 = I15. One byte changed in the record, with the genuine signature.
    function test_T15_one_byte_mutation_refused() external {
        vm.expectRevert(
            abi.encodeWithSelector(DNSSECImpl.NoMatchingProof.selector, hex"00")
        );
        predicate.proveNoDelegation(F.N_DOT, _one(F.CORRUPT_SET, F.DOMAINS_SIG));
    }

    /// T16 = I16. A proof whose last set is not NSEC reverts the whole call.
    function test_T16_non_nsec_proof_reverts_whole_call() external {
        DNSSEC.RRSetWithSignature[][] memory proofs = new DNSSEC.RRSetWithSignature[][](1);
        DNSSEC.RRSetWithSignature[] memory chain = new DNSSEC.RRSetWithSignature[](1);
        chain[0] = DNSSEC.RRSetWithSignature(F.DNSKEY_SET, F.DNSKEY_SIG);
        proofs[0] = chain;
        vm.expectRevert(
            abi.encodeWithSelector(
                RootAbsencePredicate.ProofNotNSEC.selector,
                uint256(0),
                uint16(48)
            )
        );
        predicate.proveNoDelegation(F.N_DOOSAN, proofs);
    }

    /// T17 = I17. The shape of the queried name.
    function test_T17_query_name_shape_guards() external {
        vm.expectRevert(
            abi.encodeWithSelector(NSECUtils.NonCanonicalName.selector, F.N_COM_UPPER)
        );
        predicate.proveNoDelegation(F.N_COM_UPPER, _one(F.ZW_SET, F.ZW_SIG));

        vm.expectRevert(
            abi.encodeWithSelector(
                RootAbsencePredicate.NotATopLevelName.selector,
                F.N_NIC_DOOSAN
            )
        );
        predicate.proveNoDelegation(F.N_NIC_DOOSAN, _one(F.DOMAINS_SET, F.DOMAINS_SIG));

        vm.expectRevert(
            abi.encodeWithSelector(RootAbsencePredicate.NotATopLevelName.selector, F.N_ROOT)
        );
        predicate.proveNoDelegation(F.N_ROOT, _one(F.ROOT_SET, F.ROOT_SIG));

        vm.expectRevert(
            abi.encodeWithSelector(NSECUtils.MalformedName.selector, hex"03636f6d0000")
        );
        predicate.proveNoDelegation(hex"03636f6d0000", _one(F.ZW_SET, F.ZW_SIG));

        RootAbsencePredicate.Result memory r = predicate.proveNoDelegation(
            F.N_WILDCARD,
            _one(F.ROOT_SET, F.ROOT_SIG)
        );
        _report("T17 the literal wildcard label *. as the queried name", r);
        _expect(r, true, RootAbsencePredicate.Route.NoName, 1);
        emit log("T17 *. is still accepted as a queried name, unchanged from round 1");
    }

    /// T18 = I18. Nothing to read.
    function test_T18_empty_proofs_prove_nothing() external {
        DNSSEC.RRSetWithSignature[][] memory none = new DNSSEC.RRSetWithSignature[][](0);
        RootAbsencePredicate.Result memory r = predicate.proveNoDelegation(F.N_DOOSAN, none);
        _report("T18 an empty proof array", r);
        _expect(r, false, RootAbsencePredicate.Route.Unproven, 0);

        vm.expectRevert(
            abi.encodeWithSelector(
                RootAbsencePredicate.AbsenceNotProven.selector,
                F.N_DOOSAN,
                RootAbsencePredicate.Route.Unproven
            )
        );
        predicate.requireNoDelegation(F.N_DOOSAN, none);

        DNSSEC.RRSetWithSignature[][] memory oneEmpty = new DNSSEC.RRSetWithSignature[][](1);
        oneEmpty[0] = new DNSSEC.RRSetWithSignature[](0);
        vm.expectRevert(
            abi.encodeWithSelector(RootAbsencePredicate.EmptyProof.selector, uint256(0))
        );
        predicate.proveNoDelegation(F.N_DOOSAN, oneEmpty);
    }

    /// T19 = I19. Cost, for comparison with round 1's 315,370 and 566,163.
    function test_T19_gas() external {
        uint256 g0 = gasleft();
        predicate.proveNoDelegation(F.N_DOOSAN, _one(F.DOMAINS_SET, F.DOMAINS_SIG));
        uint256 one = g0 - gasleft();
        g0 = gasleft();
        predicate.proveNoDelegation(
            F.N_DOOSAN,
            _two(F.DOMAINS_SET, F.DOMAINS_SIG, F.ROOT_SET, F.ROOT_SIG)
        );
        uint256 two = g0 - gasleft();
        emit log_named_uint("T19 gas, one proof", one);
        emit log_named_uint("T19 gas, two proofs", two);
        emit log_named_uint("T19 round 1 was, one proof", 315370);
        emit log_named_uint("T19 round 1 was, two proofs", 566163);
    }

    /// T30 = I30. The covering record's bitmap is not the query's bitmap.
    function test_T30_covering_record_bitmap_is_not_the_querys_bitmap() external {
        bytes memory aqua = hex"0461717561" hex"00"; // aqua.
        RootAbsencePredicate.Result memory r = predicate.proveNoDelegation(
            aqua,
            _one(F.AQ_SET, F.AQ_SIG)
        );
        _report("T30 aqua. inside the gap aq. NSEC aquarelle.", r);
        _expect(r, true, RootAbsencePredicate.Route.NoName, 1);
        require(keccak256(r.owner) == keccak256(F.N_AQ), "the deciding owner is aq.");
    }
}

/// @notice ROUND 3, input R29. The cost breakdown again, to see whether the new checks moved it.
contract T2Cost is Harness3 {
    function test_T29_cost_breakdown() external {
        uint256 g0 = gasleft();
        DNSSECImpl o = new DNSSECImpl(F.ANCHORS);
        uint256 gOracle = g0 - gasleft();
        g0 = gasleft();
        o.setAlgorithm(8, new RSASHA256Algorithm());
        o.setDigest(2, new SHA256Digest());
        uint256 gConfig = g0 - gasleft();
        g0 = gasleft();
        RootAbsencePredicate p = new RootAbsencePredicate(DNSSEC(o));
        uint256 gPredicate = g0 - gasleft();

        g0 = gasleft();
        o.verifyRRSetAt(_proof(F.DOMAINS_SET, F.DOMAINS_SIG), block.timestamp);
        uint256 gVerify = g0 - gasleft();

        g0 = gasleft();
        p.proveNoDelegation(F.N_DOOSAN, _one(F.DOMAINS_SET, F.DOMAINS_SIG));
        uint256 gOne = g0 - gasleft();
        g0 = gasleft();
        p.proveNoDelegation(
            F.N_DOOSAN,
            _two(F.DOMAINS_SET, F.DOMAINS_SIG, F.ROOT_SET, F.ROOT_SIG)
        );
        uint256 gTwo = g0 - gasleft();

        emit log_named_uint("T29 deploy DNSSECImpl", gOracle);
        emit log_named_uint("T29 deploy and set algorithm 8 and digest 2", gConfig);
        emit log_named_uint("T29 deploy RootAbsencePredicate", gPredicate);
        emit log_named_uint("T29 oracle verifyRRSetAt, one NSEC chain", gVerify);
        emit log_named_uint("T29 predicate, one proof", gOne);
        emit log_named_uint("T29 predicate, two proofs", gTwo);
        emit log_named_uint("T29 second proof costs", gTwo - gOne);
        emit log_named_uint("T29 deploy + config + one verify", gOracle + gConfig + gVerify);

        bytes memory oneCalldata = abi.encodeCall(
            RootAbsencePredicate.proveNoDelegation,
            (F.N_DOOSAN, _one(F.DOMAINS_SET, F.DOMAINS_SIG))
        );
        emit log_named_uint("T29 calldata bytes, one proof", oneCalldata.length);
        emit log_named_uint("T29 round 1 calldata bytes, one proof", 2020);
    }
}
