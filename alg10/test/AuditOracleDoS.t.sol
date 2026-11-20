// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

// THROWAWAY AUDIT TEST - do not commit.

import {DNSSEC} from "../src/contracts/dnssec-oracle/DNSSEC.sol";
import {DNSSECImpl} from "../src/contracts/dnssec-oracle/DNSSECImpl.sol";
import {RSASHA256Algorithm} from "../src/contracts/dnssec-oracle/algorithms/RSASHA256Algorithm.sol";
import {SHA256Digest} from "../src/contracts/dnssec-oracle/digests/SHA256Digest.sol";
import {SHA1Digest} from "../src/contracts/dnssec-oracle/digests/SHA1Digest.sol";
import {RSASHA512Algorithm} from "../src/RSASHA512Algorithm.sol";
import {RRUtils} from "../src/contracts/dnssec-oracle/RRUtils.sol";

interface Vm { function warp(uint256) external; }

/// Reachability: can an attacker-supplied proof make DNSSECImpl.verifyRRSet panic,
/// instead of reverting with NoMatchingProof (the correct outcome)?
contract AuditOracleDoSTest {
    using RRUtils for *;

    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address internal constant CONSOLE = 0x000000000000000000636F6e736F6c652e6c6f67;
    function _log(string memory s) internal view {
        (bool ok,) = CONSOLE.staticcall(abi.encodeWithSignature("log(string)", s)); ok;
    }
    function _hex(bytes memory b) internal pure returns (string memory) {
        bytes memory h = "0123456789abcdef";
        bytes memory o = new bytes(2 * b.length);
        for (uint256 i; i < b.length; i++) { o[2*i] = h[uint8(b[i]) >> 4]; o[2*i+1] = h[uint8(b[i]) & 0xf]; }
        return string(o);
    }

    bytes internal constant ANCHORS = hex"00002b000100000e1000244f660802e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d00002b000100000e10002497280802683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16";

    DNSSECImpl internal oracle;

    function _setup() internal {
        oracle = new DNSSECImpl(ANCHORS);
        oracle.setAlgorithm(8, new RSASHA256Algorithm());
        oracle.setAlgorithm(10, new RSASHA512Algorithm());
        oracle.setDigest(1, new SHA1Digest());
        oracle.setDigest(2, new SHA256Digest());
        vm.warp(1763000000);
    }

    /// name = "." (root), which is the owner of the anchors' DS records, so the
    /// ProofNameMismatch branch is not reached before `algorithm.verify`.
    bytes internal constant ROOTNAME = hex"00";

    /// Builds one RRSetWithSignature: an RRSIG(DNSKEY) over a one-record DNSKEY RRset
    /// whose RDATA is `keyrdata`, with the keytag field set to the blob's real keytag.
    function _proof(bytes memory keyrdata) internal pure returns (DNSSEC.RRSetWithSignature memory) {
        uint16 keytag = keyrdata.computeKeytag();
        bytes memory rrs = abi.encodePacked(
            ROOTNAME,               // owner name: root
            uint16(48),             // TYPE = DNSKEY
            uint16(1),              // CLASS = IN
            uint32(3600),           // TTL
            uint16(keyrdata.length),
            keyrdata
        );
        bytes memory rrsig = abi.encodePacked(
            uint16(48),             // type covered = DNSKEY
            uint8(10),              // algorithm 10
            uint8(0),               // labels (root = 0)
            uint32(3600),           // original TTL
            uint32(0x7fffffff),     // expiration
            uint32(0),              // inception
            keytag,
            ROOTNAME,               // signer name = root
            rrs
        );
        return DNSSEC.RRSetWithSignature(rrsig, hex"00");
    }

    function _run(bytes memory keyrdata) internal returns (uint256, bytes memory) {
        DNSSEC.RRSetWithSignature[] memory c = new DNSSEC.RRSetWithSignature[](1);
        c[0] = _proof(keyrdata);
        try oracle.verifyRRSet(c) returns (bytes memory, uint32) {
            return (1, "");
        } catch (bytes memory err) {
            return (2, err);
        }
    }

    /// 7-byte DNSKEY RDATA: flags=ZONE, protocol=3, algorithm=10, long-exponent form
    /// with a declared exponent length of zero. Parses to an empty modulus.
    function test_oracle_typedError_onEmptyModulus() public {
        _setup();
        bytes memory keyrdata;
        keyrdata = abi.encodePacked(hex"0100", hex"03", hex"0a", uint8(0), uint16(0));
        (uint256 r, bytes memory err) = _run(keyrdata);
        _log(string.concat("empty-modulus blob -> ", r == 2 ? "REVERT " : "ok ", "0x", _hex(err)));
        // 0x4e487b71 = Panic(uint256); 0x32 = array out of bounds
        require(r == 2, "expected revert");
        require(bytes4(err) != bytes4(0x4e487b71), "still panicking: the H-1 guard is not in effect");
        require(bytes4(err) == bytes4(0x06cde0f3), "expected NoMatchingProof");
    }

    /// 32-byte modulus, exponent 1. Reaches `result.length - 64` and underflows.
    function test_oracle_typedError_onShortModulus() public {
        _setup();
        bytes memory modulus = new bytes(32);
        for (uint256 i; i < 32; i++) modulus[i] = 0xff;
        bytes memory keyrdata = abi.encodePacked(hex"0100", hex"03", hex"0a", uint8(1), hex"01", modulus);
        // sig must recover to something starting 0x00 0x01; with e=1, sig mod n == sig
        bytes memory sig = new bytes(32);
        sig[1] = 0x01;
        for (uint256 i = 2; i < 32; i++) sig[i] = 0xff;

        uint16 keytag = keyrdata.computeKeytag();
        bytes memory rrs = abi.encodePacked(ROOTNAME, uint16(48), uint16(1), uint32(3600), uint16(keyrdata.length), keyrdata);
        bytes memory rrsig = abi.encodePacked(
            uint16(48), uint8(10), uint8(0), uint32(3600), uint32(0x7fffffff), uint32(0), keytag, ROOTNAME, rrs
        );
        DNSSEC.RRSetWithSignature[] memory c = new DNSSEC.RRSetWithSignature[](1);
        c[0] = DNSSEC.RRSetWithSignature(rrsig, sig);
        uint256 r; bytes memory err;
        try oracle.verifyRRSet(c) returns (bytes memory, uint32) { r = 1; }
        catch (bytes memory e) { r = 2; err = e; }
        _log(string.concat("32-byte-modulus blob -> ", r == 2 ? "REVERT " : "ok ", "0x", _hex(err)));
        require(r == 2, "expected revert");
        require(bytes4(err) != bytes4(0x4e487b71), "still panicking: the H-1 guard is not in effect");
        require(bytes4(err) == bytes4(0x06cde0f3), "expected NoMatchingProof");
    }

    /// Control: a well-formed 128-byte modulus with a signature that does not verify must
    /// reach `NoMatchingProof`, i.e. a typed error, not a panic. This is the correct outcome
    /// that the two cases above should also produce.
    function test_oracle_control_wellFormedKeyGivesTypedError() public {
        _setup();
        bytes memory modulus = new bytes(128);
        for (uint256 i; i < 128; i++) modulus[i] = 0xff;
        bytes memory keyrdata = abi.encodePacked(hex"0100", hex"03", hex"0a", uint8(3), hex"010001", modulus);
        (uint256 r, bytes memory err) = _run(keyrdata);
        _log(string.concat("128-byte-modulus blob -> ", r == 2 ? "revert " : "ok ", "0x", _hex(err)));
        require(bytes4(err) != bytes4(0x4e487b71), "control panicked, test is wrong");
    }
}
