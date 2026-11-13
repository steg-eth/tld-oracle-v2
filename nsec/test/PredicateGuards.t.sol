// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {DNSSEC} from "../src/contracts/dnssec-oracle/DNSSEC.sol";
import {DNSSECImpl} from "../src/contracts/dnssec-oracle/DNSSECImpl.sol";
import {RRUtils} from "../src/contracts/dnssec-oracle/RRUtils.sol";
import {NSECUtils} from "../src/NSECUtils.sol";
import {RootAbsencePredicate} from "../src/RootAbsencePredicate.sol";
import {RootFixtures} from "./RootFixtures.sol";
import {SyntheticChainBuilder} from "./SyntheticChainBuilder.sol";

/// Tests for the three checks `RootAbsencePredicate` adds beyond issue #1: the RRSIG signer
/// must be the root, the queried name must be exactly one label below the root, and the name
/// must be lowercase. All three are entry guards: they fire before any NSEC record is read.
///
/// Migration note (F1 fix): every `proveNoDelegation`/`requireNoDelegation` call that used to
/// pass a timestamp now calls `vm.warp` to that same timestamp first, then calls the
/// two-argument form.
contract PredicateGuardsTest is RootFixtures, SyntheticChainBuilder {
    // ---------------------------------------------------------------------- selector decoding

    function _selector(bytes memory reason) internal pure returns (bytes4 sel) {
        require(reason.length >= 4, "revert reason too short to carry a selector");
        assembly {
            sel := mload(add(reason, 32))
        }
    }

    // --------------------------------------------------------- guard: the queried name must be lowercase

    /// compareNames compares raw bytes and does no case folding. If the guard did not exist, an
    /// uppercase query would sort into a different gap than its lowercase form.
    function test_PureSanity_CompareNamesDoesNotFoldCase() external pure {
        require(
            RRUtils.compareNames(NAME_COM, NAME_COM_UPPER) != 0,
            "compareNames must treat COM. and com. as different names"
        );
    }

    /// Required case: the name must be lowercase. Uppercase must be refused even with a real,
    /// otherwise-valid proof in hand, proving the refusal is the guard and not a proof failure.
    function test_UppercaseNameIsRefused() external {
        RootAbsencePredicate predicate = new RootAbsencePredicate(_realOracle());
        vm.warp(AT);
        bytes4 sel;
        bool reverted;
        try predicate.proveNoDelegation(NAME_COM_UPPER, _oneProof(WRAP_SET, WRAP_SIG)) {
            reverted = false;
        } catch (bytes memory reason) {
            reverted = true;
            sel = _selector(reason);
        }
        require(reverted, "CONTROL FAILED: uppercase query name was accepted");
        require(
            sel == NSECUtils.NonCanonicalName.selector,
            "expected NonCanonicalName, got a different revert"
        );
    }

    /// Sanity: the lowercase form of the exact same query, against the exact same proof, is not
    /// itself an error (it is simply Unproven, per test_ComNotCoveredByZwClosingRecord in the
    /// main suite) -- so the revert above is attributable to case, not to the proof.
    function test_AttributionLowercaseSiblingDoesNotRevertOnNameShape() external {
        RootAbsencePredicate predicate = new RootAbsencePredicate(_realOracle());
        vm.warp(AT);
        RootAbsencePredicate.Result memory result = predicate.proveNoDelegation(
            NAME_COM,
            _oneProof(WRAP_SET, WRAP_SIG)
        );
        require(!result.proven, "com. is not covered by zw. either way");
    }

    // ------------------------------------------------- guard: exactly one label below the root

    /// Required case: com. NSEC con. would read as covering foo.com. if the predicate let a
    /// two-label name through. There is no such fixture here (domains. NSEC dot. is used
    /// instead, and does not matter: the guard fires on the name's shape alone, before any
    /// proof is inspected), but the mechanism is identical -- a deeper name needs a proof from a
    /// deeper zone, which this contract does not read.
    function test_TwoLabelNameIsRefusedEvenWithAValidProof() external {
        RootAbsencePredicate predicate = new RootAbsencePredicate(_realOracle());
        vm.warp(AT);
        bytes4 sel;
        bool reverted;
        try predicate.proveNoDelegation(NAME_FOO_DOT_COM, _oneProof(DOMAINS_SET, DOMAINS_SIG)) {
            reverted = false;
        } catch (bytes memory reason) {
            reverted = true;
            sel = _selector(reason);
        }
        require(reverted, "CONTROL FAILED: a two-label query name was accepted");
        require(
            sel == RootAbsencePredicate.NotATopLevelName.selector,
            "expected NotATopLevelName, got a different revert"
        );
    }

    /// Sanity: the root name itself (zero labels) is refused the same way.
    function test_RootNameItselfIsRefused() external {
        RootAbsencePredicate predicate = new RootAbsencePredicate(_realOracle());
        vm.warp(AT);
        bool reverted;
        try predicate.proveNoDelegation(hex"00", _oneProof(DOMAINS_SET, DOMAINS_SIG)) {
            reverted = false;
        } catch {
            reverted = true;
        }
        require(reverted, "CONTROL FAILED: the root name itself must not be a valid query");
    }

    // ----------------------------------------------------- guard: the RRSIG signer must be the root

    /// Synthetic. Builds a fully self-consistent chain with no real cryptography (DummyAlgorithm
    /// and DummyDigest both always return true): a zone "bar." with its own self-signed DNSKEY,
    /// and a closing NSEC record "zzz.bar. NSEC bar." that bar. signs for itself. The *oracle*
    /// validates this chain completely, end to end, exactly as it would for a real, validly
    /// delegated and DNSSEC-signed TLD's own closing record. If RootAbsencePredicate trusted
    /// whatever zone the RRSIG claims to be from, this record would be misread as closing the
    /// ROOT zone, and -- because "zzz.bar." sorts below "com." -- would incorrectly report com.
    /// absent. None of this is root-signed; it tests the predicate's own signer-name check in
    /// isolation from real RSA signatures.
    ///
    /// Note: `zzz.bar.` is two labels deep, which the new `RecordNameTooDeep` check (I24) would
    /// also refuse -- but the signer check runs first in `proveNoDelegation`, before the owner
    /// name is even read, so this remains a clean test of `ProofNotFromRoot` specifically. See
    /// `Regressions.t.sol` for I24 tested on its own, with a signer that IS the root.
    ///
    /// G1 migration: `coversName` now takes the zone apex as a fourth argument, and the closing
    /// branch fires on `next == zoneApex`, not on `next <= owner`. Pinned to the root (the
    /// three-argument `predicate.coversName`), this record's `next` is `bar.`, not the root, so
    /// it no longer reads as closing the ROOT zone at all -- the premise below is rewritten to
    /// `coversNameInZone(..., barName)`, treating `bar.` as its own zone's apex (which is what
    /// "under the wrap rule alone" now has to mean, since the comparator needs an apex to mean
    /// anything). Both the old premise's falsity and the new premise's truth are asserted below,
    /// not assumed, and the test's conclusion -- the predicate still refuses the forgery -- is
    /// independently re-checked rather than taken on predicate's word.
    function test_ForgedNonRootSignerIsRefused() external {
        bytes memory barName = hex"0362617200"; // bar.
        bytes memory zzzBarName = hex"037a7a7a0362617200"; // zzz.bar.

        (
            DNSSECImpl oracle,
            DNSSEC.RRSetWithSignature memory dnskeySet,
            uint16 keytag
        ) = _zoneKeyChain(barName, 1);

        // "zzz.bar. NSEC bar.", self-signed by bar. -- a legitimate closing record for bar.'s
        // own zone, which must not be readable as a closing record for the ROOT zone.
        DNSSEC.RRSetWithSignature memory nsecSet = _nsecRecord(
            zzzBarName,
            barName,
            hex"000100", // window 0, length 1, data 0x00 -- content irrelevant, read never happens
            barName, // the forged signer: bar., not the root
            2,
            keytag
        );

        DNSSEC.RRSetWithSignature[] memory chain = new DNSSEC.RRSetWithSignature[](2);
        chain[0] = dnskeySet;
        chain[1] = nsecSet;
        DNSSEC.RRSetWithSignature[][] memory proofs = new DNSSEC.RRSetWithSignature[][](1);
        proofs[0] = chain;

        RootAbsencePredicate predicate = new RootAbsencePredicate(oracle);

        // First: the underlying oracle validates this chain completely, with no root involved
        // at all. Confirms the forgery is realistic at the oracle layer, not a chain that would
        // have failed anyway. Unchanged by migration: the oracle call still takes an explicit
        // time.
        RRUtils.SignedSet[] memory sets = oracle.verifyRRSetAt(chain, SYNTH_AT);
        require(
            keccak256(sets[sets.length - 1].signerName) == keccak256(barName),
            "setup error: the oracle did not validate the forged chain as signed by bar."
        );

        // Second: pinned to the root, this record no longer reads as covering com. at all --
        // its next-owner (bar.) is not the root, so the G1 apex rule refuses the closing branch
        // outright. This is the OLD premise, and it must now be false.
        require(
            !predicate.coversName(zzzBarName, barName, NAME_COM),
            "G1 regression: pinned to the root, this record must NOT read as covering com."
        );

        // Third: the wrap math still reads this as covering com. if bar. is told it is its OWN
        // zone's apex -- which is exactly the forgery the signer check closes off: nothing
        // authenticates that "bar." is the right apex to use for a query about a root TLD.
        require(
            predicate.coversNameInZone(zzzBarName, barName, NAME_COM, barName),
            "setup error: the forged record should cover com. when bar. is (wrongly) taken as the apex"
        );

        // Fourth: the predicate itself must still refuse it.
        vm.warp(SYNTH_AT);
        bytes4 sel;
        bool reverted;
        try predicate.proveNoDelegation(NAME_COM, proofs) {
            reverted = false;
        } catch (bytes memory reason) {
            reverted = true;
            sel = _selector(reason);
        }
        require(reverted, "CONTROL FAILED: a non-root-signed closing record was accepted");
        require(
            sel == RootAbsencePredicate.ProofNotFromRoot.selector,
            "expected ProofNotFromRoot, got a different revert"
        );
    }
}
