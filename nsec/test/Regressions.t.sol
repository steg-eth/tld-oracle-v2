// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {DNSSEC} from "../src/contracts/dnssec-oracle/DNSSEC.sol";
import {DNSSECImpl} from "../src/contracts/dnssec-oracle/DNSSECImpl.sol";
import {RootAbsencePredicate} from "../src/RootAbsencePredicate.sol";
import {RootFixtures} from "./RootFixtures.sol";
import {SyntheticChainBuilder} from "./SyntheticChainBuilder.sol";

/// Regression tests for the defects an independent audit found and predicate fixed:
/// F1 (stale-proof replay), F2 (the uint32 alias), I24 (owner/next-owner depth), I25
/// (one NSEC record per proof), and G1 (the closing-record rule keyed on endpoint order
/// instead of the zone apex). Each test here is built to FAIL against the corresponding
/// pre-fix contract -- not merely to fail to compile against it.
///
/// Every claim about what the old code actually does (as opposed to what it would be expected
/// to do) was independently checked by reconstructing the pre-fix contract, byte for byte, in a
/// scratch Foundry project outside both repositories -- `/tmp/nsec-oldcode-check` for F1/F2/
/// I24/I25, `/tmp/nsec-g1-oldcode-check` for G1 -- and running the equivalent assertions
/// against it. Neither directory is read by or referenced from anything under this tree. All
/// reproduced exactly as described in their dispatches. See the suite report for the result of
/// each probe.
contract RegressionsTest is RootFixtures, SyntheticChainBuilder {
    bytes internal constant NAME_A_DOT_COM = hex"016103636f6d00"; // a.com. (2 labels)
    bytes internal constant NAME_A_DOT_BBB = hex"01610362626200"; // a.bbb. (2 labels)
    bytes internal constant NAME_ZZZZ = hex"047a7a7a7a00"; // zzzz.
    bytes internal constant NAME_CON = hex"03636f6e00"; // con.
    bytes internal constant NAME_BBB = hex"0362626200"; // bbb.
    bytes internal constant NAME_ZZ = hex"027a7a00"; // zz.
    bytes internal constant NAME_NET = hex"036e657400"; // net.

    // A non-root zone, "bar.", and names inside it, for exercising coversNameInZone's general
    // apex rule rather than the root-pinned coversName.
    bytes internal constant BAR_APEX = hex"0362617200"; // bar.
    bytes internal constant NAME_AAA_DOT_BAR = hex"036161610362617200"; // aaa.bar.
    bytes internal constant NAME_MMM_DOT_BAR = hex"036d6d6d0362617200"; // mmm.bar.
    bytes internal constant NAME_ZZZ_DOT_BAR = hex"037a7a7a0362617200"; // zzz.bar.
    bytes internal constant NAME_ZZZZZZZ_DOT_BAR = hex"077a7a7a7a7a7a7a0362617200"; // zzzzzzz.bar.

    function _selector(bytes memory reason) internal pure returns (bytes4 sel) {
        require(reason.length >= 4, "revert reason too short to carry a selector");
        assembly {
            sel := mload(add(reason, 32))
        }
    }

    function _predicate() internal returns (RootAbsencePredicate p) {
        p = new RootAbsencePredicate(_realOracle());
    }

    // =====================================================================================
    // F1 -- the stale-proof replay
    // =====================================================================================

    /// The November 2026 fixtures, warped to a far-future block, must NOT prove. Confirmed
    /// against the reconstructed old code (`test_OLD_F1_StaleProofReplaySucceeds`): with the
    /// old three-argument signature, a caller could pass `at = AT` (inside the Nov 2026 window)
    /// while the real block was 2031, and `proveNoDelegation` returned `proven = true` for
    /// `.doosan`. The new code has no `at` parameter at all -- the only time it will ever use is
    /// `block.timestamp` -- so the same 2031 block, with the same fixture, must revert
    /// `SignatureExpired` instead.
    function test_F1_StaleFixtureAtFarFutureBlock_MustNotProve() external {
        RootAbsencePredicate predicate = _predicate();
        vm.warp(1_927_497_600); // 2031-02-28T00:00:00Z, long past the fixture's Nov 2026 window
        bytes4 sel;
        bool reverted;
        try predicate.proveNoDelegation(NAME_DOOSAN, _oneProof(DOMAINS_SET, DOMAINS_SIG)) {
            reverted = false;
        } catch (bytes memory reason) {
            reverted = true;
            sel = _selector(reason);
        }
        require(reverted, "CONTROL FAILED: a stale Nov 2026 proof verified at a 2031 block");
        require(
            sel == DNSSECImpl.SignatureExpired.selector,
            "expected SignatureExpired, since block.timestamp is genuinely 2031 now"
        );
    }

    /// The old three-argument `proveNoDelegation(bytes,(bytes,bytes)[][],uint256)` selector must
    /// not be reachable at all, rather than merely being bypassed by always passing
    /// `block.timestamp` as the third argument. A raw call encoded with the exact old selector
    /// and a well-formed payload (the AT-shifted argument the task asks to rule out) must fail
    /// to dispatch, because no function on the current contract matches it and there is no
    /// fallback.
    function test_F1_OldThreeArgumentSelectorNoLongerExists() external {
        RootAbsencePredicate predicate = _predicate();
        vm.warp(AT);

        bytes4 oldSelector = bytes4(keccak256("proveNoDelegation(bytes,(bytes,bytes)[][],uint256)"));
        bytes4 newSelector = RootAbsencePredicate.proveNoDelegation.selector;
        require(oldSelector != newSelector, "the two-argument function must have a different selector");

        bytes memory oldShapedCalldata = abi.encodeWithSelector(
            oldSelector,
            NAME_DOOSAN,
            _oneProof(DOMAINS_SET, DOMAINS_SIG),
            AT
        );
        (bool ok, ) = address(predicate).staticcall(oldShapedCalldata);
        require(!ok, "CONTROL FAILED: a call shaped like the old 3-arg selector must not dispatch");
    }

    // =====================================================================================
    // F2 -- the uint32 alias
    // =====================================================================================

    /// Required case: above type(uint32).max, the call must revert TimestampOutOfRange.
    function test_F2_AboveUint32Max_RevertsTimestampOutOfRange() external {
        RootAbsencePredicate predicate = _predicate();
        uint256 justAbove = uint256(type(uint32).max) + 1;
        vm.warp(justAbove);
        bytes4 sel;
        bytes memory capturedReason;
        bool reverted;
        try predicate.proveNoDelegation(NAME_DOOSAN, _oneProof(DOMAINS_SET, DOMAINS_SIG)) {
            reverted = false;
        } catch (bytes memory reason) {
            reverted = true;
            capturedReason = reason;
            sel = _selector(reason);
        }
        require(reverted, "CONTROL FAILED: a block time above uint32 max was accepted");
        require(
            sel == RootAbsencePredicate.TimestampOutOfRange.selector,
            "expected TimestampOutOfRange"
        );
        uint256 reportedTimestamp = abi.decode(_dropSelector(capturedReason), (uint256));
        require(reportedTimestamp == justAbove, "the reverted timestamp must be block.timestamp itself");
    }

    /// Required case, the other side of the boundary: at EXACTLY type(uint32).max, the guard
    /// (`at > type(uint32).max`) does not fire, because the comparison is not satisfied at
    /// equality. The call reaches the oracle, which narrows via `uint32(currentTime)` with no
    /// truncation (the max fits exactly) and then compares using RFC 1982 serial arithmetic:
    /// `int32(type(uint32).max)` reads as -1, so the expiration check is satisfied (not expired)
    /// but the inception check fails hard, giving `SignatureNotValidYet` rather than
    /// `SignatureExpired`. Confirmed against the reconstructed old code
    /// (`test_OLD_F2_AtExactUint32Max_SignatureNotValidYet`): this exact boundary behaves
    /// identically under old and new code, because it is an oracle-level arithmetic property,
    /// not something either version of the guard controls.
    function test_F2_AtExactUint32Max_GuardDoesNotFire_OracleRevertsSignatureNotValidYet() external {
        RootAbsencePredicate predicate = _predicate();
        vm.warp(type(uint32).max);
        bytes4 sel;
        bool reverted;
        try predicate.proveNoDelegation(NAME_DOOSAN, _oneProof(DOMAINS_SET, DOMAINS_SIG)) {
            reverted = false;
        } catch (bytes memory reason) {
            reverted = true;
            sel = _selector(reason);
        }
        require(reverted, "CONTROL FAILED: expected a revert at exactly uint32 max");
        require(
            sel == DNSSECImpl.SignatureNotValidYet.selector,
            "expected SignatureNotValidYet (RFC 1982 arithmetic), not SignatureExpired or TimestampOutOfRange"
        );
    }

    function _dropSelector(bytes memory reason) internal pure returns (bytes memory out) {
        out = new bytes(reason.length - 4);
        for (uint256 i = 0; i < out.length; i++) {
            out[i] = reason[i + 4];
        }
    }

    // =====================================================================================
    // I24 -- owner/next-owner depth
    // =====================================================================================

    /// SYNTHETIC (no real root fixture carries a two-label owner or next-owner name; see
    /// `RootAbsencePredicate.sol`'s own doc comment on `MAX_RECORD_LABELS`). Signed by the real
    /// root name this time (not a forged zone), so only the depth check is exercised, not the
    /// signer check. "a.com. NSEC com." -- owner two labels deep. Confirmed against the
    /// reconstructed old code (`test_OLD_I24_OwnerTwoLabelsDeep_ClosesZoneOverTopLevelNames`):
    /// the old code, with no depth check, read this as a zone-closing record and reported
    /// `zzzz.` (and every other top-level name sorting after `a.com.`) as proven absent.
    function test_I24_OwnerTwoLabelsDeep_RevertsRecordNameTooDeep() external {
        (DNSSECImpl oracle, DNSSEC.RRSetWithSignature memory dnskeySet, uint16 keytag) = _zoneKeyChain(
            hex"00",
            0
        );
        DNSSEC.RRSetWithSignature memory nsecSet = _nsecRecord(
            NAME_A_DOT_COM,
            NAME_COM,
            hex"0006000000000003",
            hex"00",
            2,
            keytag
        );
        DNSSEC.RRSetWithSignature[] memory chain = new DNSSEC.RRSetWithSignature[](2);
        chain[0] = dnskeySet;
        chain[1] = nsecSet;
        DNSSEC.RRSetWithSignature[][] memory proofs = new DNSSEC.RRSetWithSignature[][](1);
        proofs[0] = chain;

        RootAbsencePredicate predicate = new RootAbsencePredicate(oracle);
        vm.warp(SYNTH_AT);

        bytes4 sel;
        bool reverted;
        try predicate.proveNoDelegation(NAME_ZZZZ, proofs) {
            reverted = false;
        } catch (bytes memory reason) {
            reverted = true;
            sel = _selector(reason);
        }
        require(reverted, "CONTROL FAILED: a.com. NSEC com. was accepted as covering zzzz.");
        require(
            sel == RootAbsencePredicate.RecordNameTooDeep.selector,
            "expected RecordNameTooDeep"
        );
    }

    /// SYNTHETIC, the other direction. "com. NSEC a.bbb." -- next-owner two labels deep.
    /// Confirmed against the reconstructed old code
    /// (`test_OLD_I24_NextTwoLabelsDeep_ClosesZoneOverTopLevelNames`): read the same way, with
    /// the same consequence, for the symmetric reason.
    function test_I24_NextOwnerTwoLabelsDeep_RevertsRecordNameTooDeep() external {
        (DNSSECImpl oracle, DNSSEC.RRSetWithSignature memory dnskeySet, uint16 keytag) = _zoneKeyChain(
            hex"00",
            0
        );
        DNSSEC.RRSetWithSignature memory nsecSet = _nsecRecord(
            NAME_COM,
            NAME_A_DOT_BBB,
            hex"0006000000000003",
            hex"00",
            1,
            keytag
        );
        DNSSEC.RRSetWithSignature[] memory chain = new DNSSEC.RRSetWithSignature[](2);
        chain[0] = dnskeySet;
        chain[1] = nsecSet;
        DNSSEC.RRSetWithSignature[][] memory proofs = new DNSSEC.RRSetWithSignature[][](1);
        proofs[0] = chain;

        RootAbsencePredicate predicate = new RootAbsencePredicate(oracle);
        vm.warp(SYNTH_AT);

        bytes4 sel;
        bool reverted;
        try predicate.proveNoDelegation(NAME_ZZZZ, proofs) {
            reverted = false;
        } catch (bytes memory reason) {
            reverted = true;
            sel = _selector(reason);
        }
        require(reverted, "CONTROL FAILED: com. NSEC a.bbb. was accepted as covering zzzz.");
        require(
            sel == RootAbsencePredicate.RecordNameTooDeep.selector,
            "expected RecordNameTooDeep"
        );
    }

    // =====================================================================================
    // I25 -- one NSEC record per proof
    // =====================================================================================

    /// SYNTHETIC (no real root fixture carries two records under one signature). One signature
    /// over "com. NSEC con." (an ordinary-looking gap) and "com. NSEC bbb." (the zone-closing
    /// record in disguise), both owned by com., so DNSSECImpl's own RRset checks (same name,
    /// type, class) accept it whole. Confirmed against the reconstructed old code
    /// (`test_OLD_I25_TwoRecordsOneSignature_SecondRecordProvesAbsence`): the old code read both
    /// records and the second one proved `zz.` absent.
    function test_I25_TwoRecordsOneSignature_RevertsProofNotOneRecord() external {
        (DNSSECImpl oracle, DNSSEC.RRSetWithSignature memory dnskeySet, uint16 keytag) = _zoneKeyChain(
            hex"00",
            0
        );
        DNSSEC.RRSetWithSignature memory nsecSet = _twoNsecRecordsOneSignature(
            NAME_COM,
            NAME_CON,
            hex"0006000000000003",
            NAME_BBB,
            hex"0006000000000003",
            hex"00",
            1,
            keytag
        );
        DNSSEC.RRSetWithSignature[] memory chain = new DNSSEC.RRSetWithSignature[](2);
        chain[0] = dnskeySet;
        chain[1] = nsecSet;
        DNSSEC.RRSetWithSignature[][] memory proofs = new DNSSEC.RRSetWithSignature[][](1);
        proofs[0] = chain;

        RootAbsencePredicate predicate = new RootAbsencePredicate(oracle);
        vm.warp(SYNTH_AT);

        bytes4 sel;
        bytes memory capturedReason;
        bool reverted;
        try predicate.proveNoDelegation(NAME_ZZ, proofs) {
            reverted = false;
        } catch (bytes memory reason) {
            reverted = true;
            capturedReason = reason;
            sel = _selector(reason);
        }
        require(reverted, "CONTROL FAILED: two NSEC records under one signature were accepted");
        require(sel == RootAbsencePredicate.ProofNotOneRecord.selector, "expected ProofNotOneRecord");
        (uint256 index, uint256 records) = abi.decode(_dropSelector(capturedReason), (uint256, uint256));
        require(index == 0, "the offending proof index must be reported");
        require(records == 2, "the actual record count (2) must be reported");
    }

    // =====================================================================================
    // G1 -- the closing-record rule is keyed on the zone apex, not on endpoint order
    // =====================================================================================

    /// SYNTHETIC. `com. NSEC com.` -- next == owner, signed by the root. Under the pre-G1 rule
    /// (`next <= owner` closes the zone), this reads as closing the root zone and covers every
    /// name above `com.`, including the live TLD `net.`. Confirmed against the reconstructed
    /// pre-G1 contract (`test_OLD_G1_ComNsecCom_ReportsNetAbsent`): `proven == true`,
    /// route `NoName`, for `net.`.
    ///
    /// G1 is a NARROWING, not a new revert: this shape no longer reads as a closing record, but
    /// the call must still complete normally and return `Route.Unproven`, not revert. Asserted
    /// directly (no try/catch) -- if the call reverted, this test would itself revert and fail.
    function test_G1_ComNsecCom_MustNotReportNetAbsent_AndMustNotRevert() external {
        (DNSSECImpl oracle, DNSSEC.RRSetWithSignature memory dnskeySet, uint16 keytag) = _zoneKeyChain(
            hex"00",
            0
        );
        DNSSEC.RRSetWithSignature memory nsecSet = _nsecRecord(
            NAME_COM,
            NAME_COM, // next == owner
            hex"0006000000000003",
            hex"00", // signed by the root
            1,
            keytag
        );
        DNSSEC.RRSetWithSignature[] memory chain = new DNSSEC.RRSetWithSignature[](2);
        chain[0] = dnskeySet;
        chain[1] = nsecSet;
        DNSSEC.RRSetWithSignature[][] memory proofs = new DNSSEC.RRSetWithSignature[][](1);
        proofs[0] = chain;

        RootAbsencePredicate predicate = new RootAbsencePredicate(oracle);
        vm.warp(SYNTH_AT);
        RootAbsencePredicate.Result memory result = predicate.proveNoDelegation(NAME_NET, proofs);

        require(!result.proven, "CONTROL FAILED: com. NSEC com. was accepted as covering net.");
        require(
            result.route == RootAbsencePredicate.Route.Unproven,
            "a shape that no longer closes the zone must read Unproven, not some other route"
        );
        require(result.records == 1, "the record is still read, just not treated as a closing record");
    }

    /// SYNTHETIC. `. NSEC .` -- both owner and next-owner are the apex itself, signed by the
    /// root. This is the shape a one-line fix of "next == ROOT_NAME" alone would still miss,
    /// because next IS the root here too; the second condition (`owner != zoneApex`) is what
    /// closes it. Confirmed against the reconstructed pre-G1 contract
    /// (`test_OLD_G1_RootNsecRoot_ReportsEveryTldAbsent`): `proven == true` for BOTH `net.` and
    /// `com.` -- i.e. every TLD, not one in particular.
    function test_G1_RootNsecRoot_MustNotReportAnyTldAbsent() external {
        (DNSSECImpl oracle, DNSSEC.RRSetWithSignature memory dnskeySet, uint16 keytag) = _zoneKeyChain(
            hex"00",
            0
        );
        DNSSEC.RRSetWithSignature memory nsecSet = _nsecRecord(
            hex"00", // owner: the root itself
            hex"00", // next: the root itself
            hex"0006000000000003",
            hex"00",
            0,
            keytag
        );
        DNSSEC.RRSetWithSignature[] memory chain = new DNSSEC.RRSetWithSignature[](2);
        chain[0] = dnskeySet;
        chain[1] = nsecSet;
        DNSSEC.RRSetWithSignature[][] memory proofs = new DNSSEC.RRSetWithSignature[][](1);
        proofs[0] = chain;

        RootAbsencePredicate predicate = new RootAbsencePredicate(oracle);
        vm.warp(SYNTH_AT);

        RootAbsencePredicate.Result memory resultNet = predicate.proveNoDelegation(NAME_NET, proofs);
        require(!resultNet.proven, "CONTROL FAILED: . NSEC . was accepted as covering net.");
        require(resultNet.route == RootAbsencePredicate.Route.Unproven, "expected Unproven for net.");

        RootAbsencePredicate.Result memory resultCom = predicate.proveNoDelegation(NAME_COM, proofs);
        require(!resultCom.proven, "CONTROL FAILED: . NSEC . was accepted as covering com. (EVERY TLD)");
        require(resultCom.route == RootAbsencePredicate.Route.Unproven, "expected Unproven for com. too");
    }

    /// Liveness control: the genuine closing record, `zw. NSEC .` (real, root-signed, 11
    /// November 2026 fixture), must still prove names above `zw.` absent. This is the test that
    /// would catch an over-tight G1 fix -- one that, in guarding against `com. NSEC com.` and
    /// `. NSEC .`, also stopped recognising the one closing record the root actually publishes.
    function test_G1_GenuineClosingRecordStillProvesAbsence_LivenessControl() external {
        RootAbsencePredicate predicate = _predicate();
        vm.warp(AT);
        RootAbsencePredicate.Result memory result = predicate.proveNoDelegation(
            NAME_ZZZZZZZZ,
            _oneProof(WRAP_SET, WRAP_SIG)
        );
        require(result.proven, "LIVENESS CONTROL FAILED: zw. NSEC . must still prove zzzzzzzz. absent");
        require(result.route == RootAbsencePredicate.Route.NoName, "expected NoName from the real closing record");
        require(keccak256(result.owner) == keccak256(NAME_ZW), "owner must still be reported as zw.");
    }

    /// `coversNameInZone` must behave correctly for a non-root zone, since the library is now
    /// general rather than root-specific. Four cases inside a made-up zone "bar.": an ordinary
    /// gap, the genuine closing record (owner != apex), the apex-owned-record protection
    /// generalised (owner == apex must not close, the "bar." analogue of ". NSEC ."), and the
    /// over-accept control (a name below the owner is never covered).
    function test_G1_CoversNameInZone_BehavesCorrectlyForANonRootZone() external {
        RootAbsencePredicate predicate = _predicate();

        require(
            predicate.coversNameInZone(NAME_AAA_DOT_BAR, NAME_ZZZ_DOT_BAR, NAME_MMM_DOT_BAR, BAR_APEX),
            "an ordinary gap inside bar. must still be covered"
        );

        require(
            predicate.coversNameInZone(NAME_ZZZ_DOT_BAR, BAR_APEX, NAME_ZZZZZZZ_DOT_BAR, BAR_APEX),
            "the genuine closing record of bar. (next == bar.'s own apex) must cover names above its owner"
        );

        require(
            !predicate.coversNameInZone(BAR_APEX, BAR_APEX, NAME_ZZZ_DOT_BAR, BAR_APEX),
            "CONTROL FAILED: bar.'s own apex-owned record (bar. NSEC bar.) must not close the zone"
        );

        require(
            !predicate.coversNameInZone(NAME_ZZZ_DOT_BAR, BAR_APEX, NAME_AAA_DOT_BAR, BAR_APEX),
            "CONTROL FAILED: a name below the owner must not be covered by bar.'s closing record"
        );
    }

    /// `records` dedupe: the exact same real, root-signed record, sent as two separate proofs
    /// in one call, must count once, not twice. Confirmed against the reconstructed pre-G1
    /// contract (`test_OLD_G1_RecordsDoesNotDedupe`): `records == 2`.
    function test_G1_RecordsDedupe_SameRecordSentTwiceCountsOnce() external {
        RootAbsencePredicate predicate = _predicate();
        vm.warp(AT);
        RootAbsencePredicate.Result memory result = predicate.proveNoDelegation(
            NAME_ZZZZZZZZ,
            _twoProofs(WRAP_SET, WRAP_SIG, WRAP_SET, WRAP_SIG)
        );
        require(result.proven, "the record should still prove absence");
        require(result.records == 1, "CONTROL FAILED: the duplicate record must be counted once, not twice");
    }
}
