// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {DNSSEC} from "../src/contracts/dnssec-oracle/DNSSEC.sol";
import {NSECUtils} from "../src/NSECUtils.sol";
import {RootAbsencePredicate} from "../src/RootAbsencePredicate.sol";
import {RootFixtures} from "./RootFixtures.sol";

/// Task 3: the three behaviours predicate says are unchanged, pinned explicitly rather than
/// left to be assumed from the pre-existing (now migrated) tests that happen to cover them.
/// Each test below is deliberately built a little differently from its sibling in
/// `RootAbsencePredicate.t.sol` / `PredicateGuards.t.sol` (a different fixture pairing, or an
/// explicit selector decode instead of a bare revert check), so this file is not simply a copy
/// and catches a regression the sibling's exact shape might miss.
contract PinnedBehaviorsTest is RootFixtures {
    function _selector(bytes memory reason) internal pure returns (bytes4 sel) {
        require(reason.length >= 4, "revert reason too short to carry a selector");
        assembly {
            sel := mload(add(reason, 32))
        }
    }

    function _predicate() internal returns (RootAbsencePredicate p) {
        p = new RootAbsencePredicate(_realOracle());
    }

    /// Pin: a non-NSEC set anywhere in the proofs array reverts the WHOLE call with
    /// ProofNotNSEC, even when an earlier proof in the same call already proves absence on its
    /// own. Proof 0 is the real WRAP_SET chain, which proves zzzzzzzz. absent by itself (see
    /// test_NameAfterLastOwnerCoveredByClosingRecord). Proof 1 is just the bare, real,
    /// root-signed DNSKEY set verified against the anchors -- a genuine signed set, just not an
    /// NSEC one. The call must still revert, in full, rather than returning proof 0's answer.
    function test_Pin_NonNsecProofRevertsWholeCall_EvenWithAnotherProvingProof() external {
        RootAbsencePredicate predicate = _predicate();
        vm.warp(AT);

        DNSSEC.RRSetWithSignature[][] memory proofs = new DNSSEC.RRSetWithSignature[][](2);
        proofs[0] = _chain(WRAP_SET, WRAP_SIG);
        DNSSEC.RRSetWithSignature[] memory dnskeyOnlyChain = new DNSSEC.RRSetWithSignature[](1);
        dnskeyOnlyChain[0] = DNSSEC.RRSetWithSignature(DNSKEY_SET, DNSKEY_SIG);
        proofs[1] = dnskeyOnlyChain;

        bytes4 sel;
        bytes memory capturedReason;
        bool reverted;
        try predicate.proveNoDelegation(NAME_ZZZZZZZZ, proofs) {
            reverted = false;
        } catch (bytes memory reason) {
            reverted = true;
            capturedReason = reason;
            sel = _selector(reason);
        }
        require(reverted, "PIN BROKEN: a non-NSEC proof must fail the whole call");
        require(sel == RootAbsencePredicate.ProofNotNSEC.selector, "expected ProofNotNSEC");
        (uint256 index, uint16 dnstype) = abi.decode(_dropSelector(capturedReason), (uint256, uint16));
        require(index == 1, "the offending proof must be reported as index 1");
        require(dnstype == 48, "the DNSKEY set's own type (48) must be reported, not NSEC's (47)");
    }

    /// Pin: two NSEC sets in one chain still revert from the oracle's own fold -- a different
    /// fixture pairing (DOMAINS_SET then WRAP_SET, instead of the existing test's WRAP_SET then
    /// ROOT_SET) from `test_TwoSiblingNsecsInOneChainRefused`, so this is not merely the same
    /// bytes re-run under a new name.
    function test_Pin_TwoNsecSetsInOneChainStillRevertsFromTheFold() external {
        RootAbsencePredicate predicate = _predicate();
        vm.warp(AT);

        DNSSEC.RRSetWithSignature[] memory chain = new DNSSEC.RRSetWithSignature[](3);
        chain[0] = DNSSEC.RRSetWithSignature(DNSKEY_SET, DNSKEY_SIG);
        chain[1] = DNSSEC.RRSetWithSignature(DOMAINS_SET, DOMAINS_SIG);
        chain[2] = DNSSEC.RRSetWithSignature(WRAP_SET, WRAP_SIG);
        DNSSEC.RRSetWithSignature[][] memory proofs = new DNSSEC.RRSetWithSignature[][](1);
        proofs[0] = chain;

        bool reverted;
        try predicate.proveNoDelegation(NAME_DOOSAN, proofs) {
            reverted = false;
        } catch {
            reverted = true;
        }
        require(reverted, "PIN BROKEN: two sibling NSEC sets in one chain must not verify");
    }

    /// Pin: an uppercase query still reverts NonCanonicalName. Same guard
    /// `test_UppercaseNameIsRefused` exercises, pinned here with the ordinary gap fixture
    /// (doosan./domains.) instead of the wrap fixture, and with an explicit selector decode
    /// rather than a bare revert check.
    function test_Pin_UppercaseQueryStillRevertsNonCanonicalName() external {
        RootAbsencePredicate predicate = _predicate();
        vm.warp(AT);
        bytes memory upperDoosan = hex"06444f4f53414e00"; // DOOSAN. (uppercase)

        bytes4 sel;
        bool reverted;
        try predicate.proveNoDelegation(upperDoosan, _oneProof(DOMAINS_SET, DOMAINS_SIG)) {
            reverted = false;
        } catch (bytes memory reason) {
            reverted = true;
            sel = _selector(reason);
        }
        require(reverted, "PIN BROKEN: an uppercase query name must be refused");
        require(sel == NSECUtils.NonCanonicalName.selector, "expected NonCanonicalName");
    }

    /// Pin: a multi-label query still reverts NotATopLevelName. Same guard
    /// `test_TwoLabelNameIsRefusedEvenWithAValidProof` exercises, pinned here with a THREE-label
    /// name (not two) and the wrap fixture (not the ordinary-gap fixture), with an explicit
    /// selector decode.
    function test_Pin_MultiLabelQueryStillRevertsNotATopLevelName() external {
        RootAbsencePredicate predicate = _predicate();
        vm.warp(AT);
        bytes memory threeLabel = hex"03666f6f036261720362617a00"; // foo.bar.baz. (3 labels)

        bytes4 sel;
        bool reverted;
        try predicate.proveNoDelegation(threeLabel, _oneProof(WRAP_SET, WRAP_SIG)) {
            reverted = false;
        } catch (bytes memory reason) {
            reverted = true;
            sel = _selector(reason);
        }
        require(reverted, "PIN BROKEN: a three-label query name must be refused");
        require(sel == RootAbsencePredicate.NotATopLevelName.selector, "expected NotATopLevelName");
    }

    function _dropSelector(bytes memory reason) internal pure returns (bytes memory out) {
        out = new bytes(reason.length - 4);
        for (uint256 i = 0; i < out.length; i++) {
            out[i] = reason[i + 4];
        }
    }
}
