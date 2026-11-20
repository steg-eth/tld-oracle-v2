// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {DNSSEC} from "../src/contracts/dnssec-oracle/DNSSEC.sol";
import {DNSSECImpl} from "../src/contracts/dnssec-oracle/DNSSECImpl.sol";
import {RSASHA256Algorithm} from "../src/contracts/dnssec-oracle/algorithms/RSASHA256Algorithm.sol";
import {SHA256Digest} from "../src/contracts/dnssec-oracle/digests/SHA256Digest.sol";
import {SHA1Digest} from "../src/contracts/dnssec-oracle/digests/SHA1Digest.sol";
import {RSASHA512Algorithm} from "../src/RSASHA512Algorithm.sol";
import {Alg10Fixture} from "./Alg10Fixture.sol";

interface Vm {
    function warp(uint256) external;
}

/// End to end: a real, root-anchored chain whose last link is an algorithm 10 DNSKEY set.
///
/// `swiss.` is on the on-chain public suffix list, so it is a sweep target. Without algorithm 10
/// the oracle cannot validate its zone at all, which is what the control below demonstrates: the
/// same chain, with only algorithm 10 unregistered, fails.
contract Alg10ChainTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    bytes internal constant ANCHORS = hex"00002b000100000e1000244f660802e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d00002b000100000e10002497280802683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16";

    function _oracle(bool withAlg10) internal returns (DNSSECImpl o) {
        o = new DNSSECImpl(ANCHORS);
        o.setAlgorithm(8, new RSASHA256Algorithm());
        o.setDigest(1, new SHA1Digest());
        o.setDigest(2, new SHA256Digest());
        if (withAlg10) {
            o.setAlgorithm(10, new RSASHA512Algorithm());
        }
    }

    function _chain() internal pure returns (DNSSEC.RRSetWithSignature[] memory c) {
        c = new DNSSEC.RRSetWithSignature[](3);
        c[0] = DNSSEC.RRSetWithSignature(Alg10Fixture.ROOT_DNSKEY_SET, Alg10Fixture.ROOT_DNSKEY_SIG);
        c[1] = DNSSEC.RRSetWithSignature(Alg10Fixture.TLD_DS_SET, Alg10Fixture.TLD_DS_SIG);
        c[2] = DNSSEC.RRSetWithSignature(Alg10Fixture.TLD_DNSKEY_SET, Alg10Fixture.TLD_DNSKEY_SIG);
    }

    /// The chain validates once algorithm 10 is registered.
    function test_alg10ChainVerifies() public {
        DNSSECImpl o = _oracle(true);
        vm.warp(Alg10Fixture.INSIDE);
        (bytes memory rrs, uint32 inception) = o.verifyRRSet(_chain());
        require(rrs.length > 0, "empty rrs");
        require(inception > 0, "zero inception");
    }

    /// Control: the identical chain, with algorithm 10 absent, does not validate. This is the
    /// state of the deployed oracle today.
    function test_withoutAlg10_theSameChainFails() public {
        DNSSECImpl o = _oracle(false);
        vm.warp(Alg10Fixture.INSIDE);
        bool reverted;
        try o.verifyRRSet(_chain()) returns (bytes memory, uint32) {
            reverted = false;
        } catch {
            reverted = true;
        }
        require(reverted, "chain verified without algorithm 10, so the control is wrong");
    }
}
