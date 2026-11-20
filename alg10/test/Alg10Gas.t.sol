// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {DNSSEC} from "../src/contracts/dnssec-oracle/DNSSEC.sol";
import {DNSSECImpl} from "../src/contracts/dnssec-oracle/DNSSECImpl.sol";
import {RSASHA256Algorithm} from "../src/contracts/dnssec-oracle/algorithms/RSASHA256Algorithm.sol";
import {SHA256Digest} from "../src/contracts/dnssec-oracle/digests/SHA256Digest.sol";
import {SHA1Digest} from "../src/contracts/dnssec-oracle/digests/SHA1Digest.sol";
import {RSASHA512Algorithm} from "../src/RSASHA512Algorithm.sol";
import {Alg10Fixture} from "./Alg10Fixture.sol";

interface Vm { function warp(uint256) external; }

/// Cost of the algorithm 10 link, isolated by measuring each prefix of the chain.
contract Alg10GasTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address internal constant CONSOLE = 0x000000000000000000636F6e736F6c652e6c6f67;

    bytes internal constant ANCHORS_REF = hex"00";

    DNSSECImpl internal oracle;

    function _log(string memory s) internal view {
        (bool ok,) = CONSOLE.staticcall(abi.encodeWithSignature("log(string)", s)); ok;
    }
    function _u(uint256 v) internal pure returns (string memory) {
        if (v == 0) return "0";
        uint256 n = v; uint256 d;
        while (n != 0) { d++; n /= 10; }
        bytes memory b = new bytes(d);
        while (v != 0) { b[--d] = bytes1(uint8(48 + (v % 10))); v /= 10; }
        return string(b);
    }
    function _pad(string memory s, uint256 w) internal pure returns (string memory) {
        bytes memory b = bytes(s);
        if (b.length >= w) return s;
        bytes memory o = new bytes(w);
        for (uint256 i; i < w - b.length; i++) o[i] = " ";
        for (uint256 i; i < b.length; i++) o[w - b.length + i] = b[i];
        return string(o);
    }

    function _prefix(uint256 n) internal pure returns (DNSSEC.RRSetWithSignature[] memory c) {
        c = new DNSSEC.RRSetWithSignature[](n);
        if (n > 0) c[0] = DNSSEC.RRSetWithSignature(Alg10Fixture.ROOT_DNSKEY_SET, Alg10Fixture.ROOT_DNSKEY_SIG);
        if (n > 1) c[1] = DNSSEC.RRSetWithSignature(Alg10Fixture.TLD_DS_SET, Alg10Fixture.TLD_DS_SIG);
        if (n > 2) c[2] = DNSSEC.RRSetWithSignature(Alg10Fixture.TLD_DNSKEY_SET, Alg10Fixture.TLD_DNSKEY_SIG);
    }

    function test_alg10Gas() public {
        oracle = new DNSSECImpl(hex"00002b000100000e1000244f660802e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d00002b000100000e10002497280802683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16");
        oracle.setAlgorithm(8, new RSASHA256Algorithm());
        oracle.setAlgorithm(10, new RSASHA512Algorithm());
        oracle.setDigest(1, new SHA1Digest());
        oracle.setDigest(2, new SHA256Digest());
        vm.warp(Alg10Fixture.INSIDE);

        _log("sets  cumulative   this level   what the level is");
        string[3] memory labels = [
            "1. root DNSKEY (alg 8)",
            "2. swiss DS, signed by root (alg 8)",
            "3. swiss DNSKEY (alg 10, RSASHA512)"
        ];
        uint256 prev;
        for (uint256 n = 1; n <= 3; n++) {
            DNSSEC.RRSetWithSignature[] memory c = _prefix(n);
            uint256 g0 = gasleft();
            oracle.verifyRRSet(c);
            uint256 used = g0 - gasleft();
            _log(string.concat(_pad(_u(n), 4), _pad(_u(used), 13), _pad(_u(used - prev), 13), "   ", labels[n-1]));
            prev = used;
        }

        uint256 g1 = gasleft();
        RSASHA512Algorithm a = new RSASHA512Algorithm();
        _log(string.concat("deployment of RSASHA512Algorithm: ", _u(g1 - gasleft())));
        a;
    }
}
