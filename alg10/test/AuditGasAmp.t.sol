// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

// THROWAWAY AUDIT TEST - do not commit.

import {RSASHA512Algorithm} from "../src/RSASHA512Algorithm.sol";

/// How much gas can one attacker-supplied DNSKEY blob burn?
/// One case per test so each starts with the full test gas allowance.
contract AuditGasAmpTest {
    RSASHA512Algorithm internal a = new RSASHA512Algorithm();
    address internal constant CONSOLE = 0x000000000000000000636F6e736F6c652e6c6f67;
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

    function _blob(uint256 expLen) internal pure returns (bytes memory) {
        bytes memory e = new bytes(expLen);
        for (uint256 i; i < expLen; i++) e[i] = 0xff;
        bytes memory n = new bytes(128);
        for (uint256 i; i < 128; i++) n[i] = 0xff;
        if (expLen < 256) {
            return abi.encodePacked(hex"0100", hex"03", hex"0a", uint8(expLen), e, n);
        }
        return abi.encodePacked(hex"0100", hex"03", hex"0a", uint8(0), uint16(uint256(expLen)), e, n);
    }

    /// `budget` is the gas handed to the verifier, mimicking a caller that caps the stipend.
    function _one(uint256 expLen, uint256 budget) internal view {
        bytes memory key = _blob(expLen);
        bytes memory data = hex"deadbeef";
        bytes memory sig = new bytes(128);
        for (uint256 i; i < 128; i++) sig[i] = 0xab;
        bytes memory cd = abi.encodeWithSignature("verify(bytes,bytes,bytes)", key, data, sig);
        address target = address(a);
        uint256 g0 = gasleft();
        bool ok;
        bytes memory ret;
        assembly {
            let o := mload(0x40)
            ok := staticcall(budget, target, add(cd, 32), mload(cd), o, 32)
            ret := o
        }
        uint256 used = g0 - gasleft();
        _log(string.concat(
            "exponent ", _u(expLen), " bytes | keyblob ", _u(key.length),
            " bytes | budget ", _u(budget), " | call ok=", ok ? "1" : "0",
            " | gas consumed ", _u(used)
        ));
    }

    function test_exp3()     public view { _one(3,     30_000_000); }
    function test_exp255()   public view { _one(255,   30_000_000); }
    function test_exp512()   public view { _one(512,   30_000_000); }
    function test_exp1024()  public view { _one(1024,  30_000_000); }
    function test_exp4096()  public view { _one(4096,  30_000_000); }
    function test_exp65528() public view { _one(65528, 30_000_000); }
}
