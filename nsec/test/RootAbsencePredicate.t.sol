// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {DNSSEC} from "../src/contracts/dnssec-oracle/DNSSEC.sol";
import {RootAbsencePredicate} from "../src/RootAbsencePredicate.sol";
import {RootFixtures} from "./RootFixtures.sol";

/// The predicate's own suite, against real root-signed fixtures (11 November 2026, valid to
/// 24 November 2026 05:00 UTC). Every test here drives `RootAbsencePredicate`, not `DNSSECImpl`
/// directly -- the 17 tests in `tools/nsec/*.t.sol` already measured the oracle and are not
/// duplicated here.
///
/// Migration note (F1 fix): every entry point dropped its `at` parameter and now validates at
/// `block.timestamp`. Every call below that used to pass a timestamp now calls `vm.warp` to that
/// same timestamp first, then calls the two-argument form. `_acceptsAt` is unchanged: it drives
/// `DNSSECImpl.verifyRRSetAt` directly, which still takes an explicit time.
contract RootAbsencePredicateRealFixturesTest is RootFixtures {
    RootAbsencePredicate internal predicate;

    function _predicate() internal returns (RootAbsencePredicate p) {
        p = new RootAbsencePredicate(_realOracle());
    }

    // ------------------------------------------------------------- wrap-aware bounds, via the predicate

    /// Required case: com. must NOT be covered by the zw. closing record. The wrap-aware form
    /// must not over-accept.
    function test_ComNotCoveredByZwClosingRecord() external {
        predicate = _predicate();
        vm.warp(AT);
        RootAbsencePredicate.Result memory result = predicate.proveNoDelegation(
            NAME_COM,
            _oneProof(WRAP_SET, WRAP_SIG)
        );
        require(!result.proven, "CONTROL FAILED: com. reported absent via the zw. closing record");
        require(
            result.route == RootAbsencePredicate.Route.Unproven,
            "expected Unproven: zw. does not cover or match com."
        );
        require(result.records == 1, "the zw. record must still be read");
    }

    /// Required case: a name that sorts after the last owner name IS covered by the closing
    /// record.
    function test_NameAfterLastOwnerCoveredByClosingRecord() external {
        predicate = _predicate();
        vm.warp(AT);
        RootAbsencePredicate.Result memory result = predicate.proveNoDelegation(
            NAME_ZZZZZZZZ,
            _oneProof(WRAP_SET, WRAP_SIG)
        );
        require(result.proven, "zzzzzzzz. must be proven absent by the zw. closing record");
        require(
            result.route == RootAbsencePredicate.Route.NoName,
            "expected NoName from the closing record"
        );
        require(keccak256(result.owner) == keccak256(NAME_ZW), "owner must be zw.");
        require(keccak256(result.next) == keccak256(hex"00"), "next must be the root");
    }

    // ------------------------------------------------------------------- the ordinary gap

    /// Required case: a name inside an ordinary gap. Same gap RootProof.t.sol uses to measure
    /// the oracle; here it drives the predicate end to end.
    function test_NameInsideOrdinaryGapIsProvenAbsent() external {
        predicate = _predicate();
        vm.warp(AT);
        RootAbsencePredicate.Result memory result = predicate.proveNoDelegation(
            NAME_DOOSAN,
            _oneProof(DOMAINS_SET, DOMAINS_SIG)
        );
        require(result.proven, "doosan. must be proven absent");
        require(result.route == RootAbsencePredicate.Route.NoName, "expected NoName");
    }

    // ------------------------------------------------------- NS present: aq. and zw. must hold

    /// Required case: aq. is a live delegation with NS and no DS. Querying it directly must
    /// report Delegated, never an absence route. A predicate keyed on DS absence would release
    /// it; this predicate does not read DS at all.
    function test_AqIsNotReleased() external {
        predicate = _predicate();
        vm.warp(AT);
        RootAbsencePredicate.Result memory result = predicate.proveNoDelegation(
            NAME_AQ,
            _oneProof(AQ_SET, AQ_SIG)
        );
        require(!result.proven, "CONTROL FAILED: aq. reported absent");
        require(
            result.route == RootAbsencePredicate.Route.Delegated,
            "expected Delegated: aq. carries NS"
        );
    }

    /// Required case: zw. is also a live delegation with NS and no DS, so the trap is not
    /// unique to aq. Queried directly (not as the tail past it), it must also report Delegated.
    function test_ZwIsNotReleased() external {
        predicate = _predicate();
        vm.warp(AT);
        RootAbsencePredicate.Result memory result = predicate.proveNoDelegation(
            NAME_ZW,
            _oneProof(WRAP_SET, WRAP_SIG)
        );
        require(!result.proven, "CONTROL FAILED: zw. reported absent");
        require(
            result.route == RootAbsencePredicate.Route.Delegated,
            "expected Delegated: zw. carries NS"
        );
    }

    /// Delegated outranks NoName within one call: a proof that matches the queried name directly
    /// (NS present) must not be overturned by a second proof that would otherwise cover it.
    function test_DelegatedVetoesAnOtherwiseCoveringRecord() external {
        predicate = _predicate();
        vm.warp(AT);
        // zw. itself (Delegated) plus the root's own ". NSEC aaa." record, which covers nothing
        // of zw. (aaa. < zw.) but exercises the fold with a second, unrelated proof present.
        RootAbsencePredicate.Result memory result = predicate.proveNoDelegation(
            NAME_ZW,
            _twoProofs(WRAP_SET, WRAP_SIG, ROOT_SET, ROOT_SIG)
        );
        require(!result.proven, "CONTROL FAILED: Delegated must not be overturned");
        require(result.route == RootAbsencePredicate.Route.Delegated, "expected Delegated to hold");
        require(result.records == 2, "both records must still be read");
    }

    // ----------------------------------------------------------------- tampered record refused

    /// Required case: a record one byte different from a signed one must be refused. Corrupts a
    /// type-bitmap byte (not the next-owner name NegativeControl.t.sol corrupts), driven through
    /// the predicate rather than the oracle directly.
    function test_TamperedBitmapByteIsRefused() external {
        predicate = _predicate();
        vm.warp(AT);
        bool reverted;
        try predicate.proveNoDelegation(NAME_ZZZZZZZZ, _oneProof(WRAP_SET_CORRUPT, WRAP_SIG)) {
            reverted = false;
        } catch {
            reverted = true;
        }
        require(reverted, "CONTROL FAILED: predicate accepted a tampered NSEC record");
    }

    // sanity: the uncorrupted sibling of the test above must still pass, so the refusal above is
    // attributable to the corruption and not to some unrelated fixture problem.
    function test_AttributionUncorruptedSiblingStillAccepted() external {
        predicate = _predicate();
        vm.warp(AT);
        RootAbsencePredicate.Result memory result = predicate.proveNoDelegation(
            NAME_ZZZZZZZZ,
            _oneProof(WRAP_SET, WRAP_SIG)
        );
        require(result.proven, "uncorrupted WRAP_SET must still verify");
    }

    // --------------------------------------------------------------- the RRSIG signature window

    function test_InsideWindowAccepted() external {
        predicate = _predicate();
        vm.warp(INSIDE);
        RootAbsencePredicate.Result memory result = predicate.proveNoDelegation(
            NAME_ZZZZZZZZ,
            _oneProof(WRAP_SET, WRAP_SIG)
        );
        require(result.proven, "should accept inside the window");
    }

    /// Required case: the right edge of the RRSIG window. Stronger after migration: the block
    /// really is at `AFTER_NSEC_EXPIRY` (via `vm.warp`) rather than a value merely passed as an
    /// argument, so this now also exercises the predicate's own `TimestampOutOfRange` guard
    /// seeing a timestamp that is in range but still past the signature's own window.
    function test_ExpiredWindowRejected() external {
        predicate = _predicate();
        vm.warp(AFTER_NSEC_EXPIRY);
        bool reverted;
        try predicate.proveNoDelegation(NAME_ZZZZZZZZ, _oneProof(WRAP_SET, WRAP_SIG)) {
            reverted = false;
        } catch {
            reverted = true;
        }
        require(reverted, "CONTROL FAILED: expired NSEC accepted");
    }

    /// Required case: the left edge of the RRSIG window. Stronger after migration, same as above.
    function test_NotYetValidWindowRejected() external {
        predicate = _predicate();
        vm.warp(BEFORE_NSEC_INCEPTION);
        bool reverted;
        try predicate.proveNoDelegation(NAME_ZZZZZZZZ, _oneProof(WRAP_SET, WRAP_SIG)) {
            reverted = false;
        } catch {
            reverted = true;
        }
        require(reverted, "CONTROL FAILED: premature NSEC accepted");
    }

    /// Required attribution control: at both edges above, the DNSKEY set alone (no NSEC set
    /// folded on top of it) is still inside its own, wider validity window. The refusals above
    /// therefore come from the NSEC set's window, not from the anchor's. Unchanged by the
    /// migration: `_acceptsAt` drives the oracle directly, which still takes an explicit `at`.
    function test_AttributionDnskeyAloneStillValidAtBothEdges() external {
        DNSSEC.RRSetWithSignature[] memory one = new DNSSEC.RRSetWithSignature[](1);
        one[0] = DNSSEC.RRSetWithSignature(DNSKEY_SET, DNSKEY_SIG);
        require(
            _acceptsAt(one, AFTER_NSEC_EXPIRY),
            "CONTROL FAILED: dnskey set itself should still validate after NSEC expiry"
        );
        require(
            _acceptsAt(one, BEFORE_NSEC_INCEPTION),
            "CONTROL FAILED: dnskey set itself should already validate before NSEC inception"
        );
    }

    function _acceptsAt(
        DNSSEC.RRSetWithSignature[] memory chain,
        uint256 at
    ) internal returns (bool ok) {
        try _realOracle().verifyRRSetAt(chain, at) {
            ok = true;
        } catch {
            ok = false;
        }
    }

    // ------------------------------------------------------- the array-of-proofs calling convention

    /// Required case: two sibling NSEC records passed in ONE chain must be refused, because
    /// `verifyRRSetAt` folds its input and an NSEC set cannot act as the proof for the one that
    /// follows it.
    ///
    /// Pinned (task 3, I25's sibling claim): this is the "two NSEC sets in one *chain*" shape,
    /// still refused by the oracle's own fold -- distinct from I25 below, which is two NSEC
    /// *records* under one signature inside a single chain element.
    function test_TwoSiblingNsecsInOneChainRefused() external {
        predicate = _predicate();
        vm.warp(AT);
        DNSSEC.RRSetWithSignature[][] memory proofs = new DNSSEC.RRSetWithSignature[][](1);
        DNSSEC.RRSetWithSignature[] memory chain = new DNSSEC.RRSetWithSignature[](3);
        chain[0] = DNSSEC.RRSetWithSignature(DNSKEY_SET, DNSKEY_SIG);
        chain[1] = DNSSEC.RRSetWithSignature(WRAP_SET, WRAP_SIG);
        chain[2] = DNSSEC.RRSetWithSignature(ROOT_SET, ROOT_SIG);
        proofs[0] = chain;

        bool reverted;
        try predicate.proveNoDelegation(NAME_ZZZZZZZZ, proofs) {
            reverted = false;
        } catch {
            reverted = true;
        }
        require(reverted, "CONTROL FAILED: two sibling NSEC sets in one chain must not verify");
    }

    /// Positive control for the case above, and the measured calling convention itself: the same
    /// two records verify, and combine, when each gets its own chain in the proofs array.
    function test_TwoIndependentProofsCombineCorrectly() external {
        predicate = _predicate();
        vm.warp(AT);
        RootAbsencePredicate.Result memory result = predicate.proveNoDelegation(
            NAME_ZZZZZZZZ,
            _twoProofs(WRAP_SET, WRAP_SIG, ROOT_SET, ROOT_SIG)
        );
        require(result.proven, "zzzzzzzz. must still be proven absent");
        require(result.route == RootAbsencePredicate.Route.NoName, "expected NoName from zw.");
        require(result.records == 2, "both records must be read");
        require(
            result.apexWildcardDenied,
            "the root's own record must be recognised as denying the apex wildcard"
        );
    }

    // -------------------------------------------------------------------------- empty proof guard

    /// An empty chain inside the proofs array must not reach the oracle, per the documented
    /// rationale on `RootAbsencePredicate.EmptyProof`.
    function test_EmptyProofRejected() external {
        predicate = _predicate();
        vm.warp(AT);
        DNSSEC.RRSetWithSignature[][] memory proofs = new DNSSEC.RRSetWithSignature[][](1);
        proofs[0] = new DNSSEC.RRSetWithSignature[](0);

        bool reverted;
        try predicate.proveNoDelegation(NAME_ZZZZZZZZ, proofs) {
            reverted = false;
        } catch {
            reverted = true;
        }
        require(reverted, "CONTROL FAILED: an empty proof chain must be rejected");
    }

    // ------------------------------------------------------------------- requireNoDelegation

    function test_RequireNoDelegationRevertsWhenUnproven() external {
        predicate = _predicate();
        vm.warp(AT);
        bool reverted;
        try predicate.requireNoDelegation(NAME_COM, _oneProof(WRAP_SET, WRAP_SIG)) {
            reverted = false;
        } catch {
            reverted = true;
        }
        require(reverted, "CONTROL FAILED: requireNoDelegation must revert when unproven");
    }

    function test_RequireNoDelegationSucceedsWhenProven() external {
        predicate = _predicate();
        vm.warp(AT);
        RootAbsencePredicate.Result memory result = predicate.requireNoDelegation(
            NAME_ZZZZZZZZ,
            _oneProof(WRAP_SET, WRAP_SIG)
        );
        require(result.proven, "requireNoDelegation must return the proven result");
    }
}
