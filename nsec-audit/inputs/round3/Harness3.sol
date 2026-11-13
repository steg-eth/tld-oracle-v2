// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {DNSSEC} from "src/contracts/dnssec-oracle/DNSSEC.sol";
import {DNSSECImpl} from "src/contracts/dnssec-oracle/DNSSECImpl.sol";
import {RSASHA256Algorithm} from "src/contracts/dnssec-oracle/algorithms/RSASHA256Algorithm.sol";
import {SHA256Digest} from "src/contracts/dnssec-oracle/digests/SHA256Digest.sol";
import {RootAbsencePredicate} from "src/RootAbsencePredicate.sol";
import {RootFixtures as F} from "../RootFixtures.sol";

interface Vm {
    function warp(uint256) external;
    function expectRevert(bytes calldata revertData) external;
    function expectRevert() external;
}

/// @notice Round 3 harness. Same oracle configuration as round 1 and as mainnet
///         0x668ad4467129d49ECbe6274d95197797C0E262AA: the live root trust anchors, algorithm 8
///         and digest 2, nothing else.
///
///         One difference from round 1, and it is forced by the fix. No entry point takes a
///         validation time, so every root-signed input needs the block clock inside the
///         fixture's RRSIG window. `setUp` warps to `F.INSIDE`, which is 2026-11-11 16:43:22Z.
///         A test that wants another time warps again.
contract Harness3 {
    Vm internal constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    event log(string);
    event log_named_uint(string key, uint256 val);
    event log_named_bytes(string key, bytes val);
    event log_named_bytes32(string key, bytes32 val);
    event log_named_string(string key, string val);

    DNSSECImpl internal oracle;
    RootAbsencePredicate internal predicate;

    function setUp() public virtual {
        oracle = new DNSSECImpl(F.ANCHORS);
        oracle.setAlgorithm(8, new RSASHA256Algorithm());
        oracle.setDigest(2, new SHA256Digest());
        predicate = new RootAbsencePredicate(DNSSEC(oracle));
        vm.warp(F.INSIDE);
    }

    function _proof(
        bytes memory set,
        bytes memory sig
    ) internal pure returns (DNSSEC.RRSetWithSignature[] memory chain) {
        chain = new DNSSEC.RRSetWithSignature[](2);
        chain[0] = DNSSEC.RRSetWithSignature(F.DNSKEY_SET, F.DNSKEY_SIG);
        chain[1] = DNSSEC.RRSetWithSignature(set, sig);
    }

    function _one(
        bytes memory set,
        bytes memory sig
    ) internal pure returns (DNSSEC.RRSetWithSignature[][] memory proofs) {
        proofs = new DNSSEC.RRSetWithSignature[][](1);
        proofs[0] = _proof(set, sig);
    }

    function _two(
        bytes memory setA,
        bytes memory sigA,
        bytes memory setB,
        bytes memory sigB
    ) internal pure returns (DNSSEC.RRSetWithSignature[][] memory proofs) {
        proofs = new DNSSEC.RRSetWithSignature[][](2);
        proofs[0] = _proof(setA, sigA);
        proofs[1] = _proof(setB, sigB);
    }

    function _report(
        string memory input,
        RootAbsencePredicate.Result memory r
    ) internal {
        emit log_named_string("input", input);
        emit log_named_uint("  proven", r.proven ? 1 : 0);
        emit log_named_uint("  route(0=Unproven,1=NoName,2=NoNsBit,3=Delegated)", uint256(r.route));
        emit log_named_bytes("  owner", r.owner);
        emit log_named_bytes("  next", r.next);
        emit log_named_uint("  inception", r.inception);
        emit log_named_uint("  apexWildcardDenied", r.apexWildcardDenied ? 1 : 0);
        emit log_named_uint("  records", r.records);
    }

    function _expect(
        RootAbsencePredicate.Result memory r,
        bool proven,
        RootAbsencePredicate.Route route,
        uint256 records
    ) internal pure {
        require(r.proven == proven, "proven differs from the expected value");
        require(r.route == route, "route differs from the expected value");
        require(r.records == records, "record count differs from the expected value");
    }
}
