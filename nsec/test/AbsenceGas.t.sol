// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// Gas measurement for the **absence** path, re-measuring the ~281,000 / ~552,000 figures that
/// `../README.md` line 118 publishes. Written 17 November 2026 because those numbers had no test
/// in the repository that reproduced them, while `PresenceGas.t.sol` covers the renewal chain.
///
/// The oracle is deployed once in `setUp` and the measurement excludes that deployment, which is
/// the error that produced the ~2.67M figure corrected in issue #2.
///
/// Fixtures are the real root-signed NSEC records of 11 November 2026 from `RootFixtures.sol`.
/// RRSIGs run to 24 November 2026 05:00 UTC. After that this file fails on signature expiry.
///
/// Run: forge test --match-path test/AbsenceGas.t.sol -vv

import {DNSSEC} from "../src/contracts/dnssec-oracle/DNSSEC.sol";
import {RootAbsencePredicate} from "../src/RootAbsencePredicate.sol";
import {RootFixtures} from "./RootFixtures.sol";

contract AbsenceGasTest is RootFixtures {
    address internal constant CONSOLE = 0x000000000000000000636F6e736F6c652e6c6f67;

    RootAbsencePredicate internal predicate;

    function setUp() public {
        predicate = new RootAbsencePredicate(_realOracle());
    }

    function _log(string memory s) internal view {
        (bool ok,) = CONSOLE.staticcall(abi.encodeWithSignature("log(string)", s));
        ok;
    }

    function _u(uint256 v) internal pure returns (string memory) {
        if (v == 0) return "0";
        uint256 n = v;
        uint256 d;
        while (n != 0) { d++; n /= 10; }
        bytes memory b = new bytes(d);
        while (v != 0) { b[--d] = bytes1(uint8(48 + (v - (v / 10) * 10))); v /= 10; }
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

    function test_absenceGas() public {
        vm.warp(AT);
        _log("gas          call");

        uint256 g0 = gasleft();
        predicate.proveNoDelegation(NAME_DOOSAN, _oneProof(DOMAINS_SET, DOMAINS_SIG));
        _row("proveNoDelegation, 1 proof, ordinary gap (doosan. in domains.->dot.)", g0 - gasleft());

        g0 = gasleft();
        predicate.proveNoDelegation(NAME_ZZZZZZZZ, _oneProof(WRAP_SET, WRAP_SIG));
        _row("proveNoDelegation, 1 proof, closing record (zzzzzzzz. after zw.)", g0 - gasleft());

        g0 = gasleft();
        predicate.proveNoDelegation(NAME_ZZZZZZZZ, _twoProofs(WRAP_SET, WRAP_SIG, ROOT_SET, ROOT_SIG));
        _row("proveNoDelegation, 2 proofs (closing record + root apex wildcard denial)", g0 - gasleft());

        g0 = gasleft();
        predicate.requireNoDelegation(NAME_DOOSAN, _oneProof(DOMAINS_SET, DOMAINS_SIG));
        _row("requireNoDelegation, 1 proof (the release path)", g0 - gasleft());

        g0 = gasleft();
        predicate.proveNoDelegation(NAME_AQ, _oneProof(AQ_SET, AQ_SIG));
        _row("proveNoDelegation, 1 proof, DELEGATED (aq. has NS, no DS) - rejects", g0 - gasleft());
    }
}
