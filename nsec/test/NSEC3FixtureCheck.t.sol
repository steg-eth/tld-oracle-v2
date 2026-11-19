// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {DNSSEC} from "../src/contracts/dnssec-oracle/DNSSEC.sol";
import {DNSSECImpl} from "../src/contracts/dnssec-oracle/DNSSECImpl.sol";
import {RRUtils} from "../src/contracts/dnssec-oracle/RRUtils.sol";
import {BytesUtils} from "../src/contracts/utils/BytesUtils.sol";
import {NSEC3Fixtures} from "./NSEC3Fixtures.sol";

/// Proves the captured NSEC3 chains validate through the real oracle, before any predicate
/// reads them. A failure here is a bad fixture, not a bad predicate. That separation is the
/// whole point of this file: it is run first, so a later failure in the predicate's own suite
/// cannot be blamed on the bytes.
contract NSEC3FixtureCheck is NSEC3Fixtures {
    using BytesUtils for bytes;

    uint16 constant DNSTYPE_NSEC3 = 50;

    function _check(
        bytes memory zone,
        bytes memory dsSet,
        bytes memory dsSig,
        bytes memory keySet,
        bytes memory keySig,
        bytes memory n3Set,
        bytes memory n3Sig
    ) internal {
        DNSSECImpl oracle = _realOracle();
        RRUtils.SignedSet[] memory sets = oracle.verifyRRSetAt(
            _chain4(dsSet, dsSig, keySet, keySig, n3Set, n3Sig),
            AT
        );
        require(sets.length == 4, "the oracle must return four signed sets");
        RRUtils.SignedSet memory last = sets[sets.length - 1];
        require(last.typeCovered == DNSTYPE_NSEC3, "the last set must cover NSEC3");
        // The root-signed case asserts signerName == root. Here it is the zone, which is the
        // check the NSEC3 predicate has to make instead of RootAbsencePredicate's ROOT_NAME.
        require(last.signerName.equals(zone), "the last set must be signed by the zone");
    }

    function test_desi_0() external {
        _check(DESI_NAME, DESI_DS_SET, DESI_DS_SIG, DESI_DNSKEY_SET, DESI_DNSKEY_SIG, DESI_NSEC3_0_SET, DESI_NSEC3_0_SIG);
    }

    function test_desi_1() external {
        _check(DESI_NAME, DESI_DS_SET, DESI_DS_SIG, DESI_DNSKEY_SET, DESI_DNSKEY_SIG, DESI_NSEC3_1_SET, DESI_NSEC3_1_SIG);
    }

    function test_desi_2() external {
        _check(DESI_NAME, DESI_DS_SET, DESI_DS_SIG, DESI_DNSKEY_SET, DESI_DNSKEY_SIG, DESI_NSEC3_2_SET, DESI_NSEC3_2_SIG);
    }

    function test_firmdale_0() external {
        _check(FIRMDALE_NAME, FIRMDALE_DS_SET, FIRMDALE_DS_SIG, FIRMDALE_DNSKEY_SET, FIRMDALE_DNSKEY_SIG, FIRMDALE_NSEC3_0_SET, FIRMDALE_NSEC3_0_SIG);
    }

    function test_nowruz_0() external {
        _check(NOWRUZ_NAME, NOWRUZ_DS_SET, NOWRUZ_DS_SIG, NOWRUZ_DNSKEY_SET, NOWRUZ_DNSKEY_SIG, NOWRUZ_NSEC3_0_SET, NOWRUZ_NSEC3_0_SIG);
    }

    function test_nowruz_1() external {
        _check(NOWRUZ_NAME, NOWRUZ_DS_SET, NOWRUZ_DS_SIG, NOWRUZ_DNSKEY_SET, NOWRUZ_DNSKEY_SIG, NOWRUZ_NSEC3_1_SET, NOWRUZ_NSEC3_1_SIG);
    }
}
