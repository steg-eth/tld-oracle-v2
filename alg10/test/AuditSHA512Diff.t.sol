// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

// THROWAWAY AUDIT TEST - do not commit.

import {SHA512} from "../src/SHA512.sol";

/// Differential test over EVERY message length in a contiguous range, not a sample.
/// Inputs come from an LCG that Python reproduces byte for byte; the expected value is
/// sha256-chained over the whole range, so one mismatch anywhere changes the result.
/// The chaining hash is the EVM sha256 precompile, which is independent of the code under test.
contract AuditSHA512DiffTest {
    address internal constant CONSOLE = 0x000000000000000000636F6e736F6c652e6c6f67;
    function _log(string memory s) internal view {
        (bool ok,) = CONSOLE.staticcall(abi.encodeWithSignature("log(string)", s)); ok;
    }

    function _input(uint256 L) internal pure returns (bytes memory b) {
        b = new bytes(L);
        uint256 s = 0x12345678 + L;
        for (uint256 i; i < L; i++) {
            s = (s * 1103515245 + 12345) & 0x7FFFFFFF;
            b[i] = bytes1(uint8((s >> 16) & 0xFF));
        }
    }

    function _acc(uint256 a, uint256 b) internal pure returns (bytes32 acc) {
        for (uint256 L = a; L <= b; L++) {
            acc = sha256(abi.encodePacked(acc, SHA512.hash(_input(L))));
        }
    }

    function _check(uint256 a, uint256 b, bytes32 want) internal view {
        bytes32 got = _acc(a, b);
        if (got != want) {
            _log("MISMATCH in range");
            revert("SHA-512 differential mismatch");
        }
    }

    function test_diff_0_200() public view {
        _check(0, 200, 0x6888530e89a7b073dd17d730023b1c90a9e30f044c5a7ec4910708261670c030);
    }
    function test_diff_201_400() public view {
        _check(201, 400, 0xb60ea67ce66e33556ea277e7d7cc0b798f8b6e95212a2fbd299054f759c12db8);
    }
    function test_diff_401_600() public view {
        _check(401, 600, 0x08b0b419274f7ba16555fd923d4357c420e8f316bb38d102b5f12d4f804804d8);
    }
    function test_diff_1000_1010() public view {
        _check(1000, 1010, 0x989bd502bdf88395030a49f21a414a29e817cffada8b11f705b08fc9924bdec9);
    }
    function test_diff_4096() public view {
        _check(4096, 4096, 0x285b27d8153022596c4b97a46bd0a02d94170a73b1fd536d0ee45175e2cc032a);
    }
    function test_diff_16384() public view {
        _check(16384, 16384, 0x3538fe9a499cb6ea1abd88cb5b7f8c38aa3b68f79a4f1ab4041e855a9dc3cfd6);
    }

    /// Cost of the 16 KiB case, to size the gas ceiling.
    function test_gas_16384() public view {
        bytes memory m = _input(16384);
        uint256 g0 = gasleft();
        SHA512.hash(m);
        uint256 used = g0 - gasleft();
        _log(_u(used));
    }
    function test_gas_profile() public view {
        uint256[6] memory sizes = [uint256(128), 1024, 4096, 8192, 16384, 32768];
        for (uint256 i; i < sizes.length; i++) {
            bytes memory m = new bytes(sizes[i]);
            uint256 g0 = gasleft();
            SHA512.hash(m);
            uint256 used = g0 - gasleft();
            _log(string.concat(_u(sizes[i]), " bytes: ", _u(used), " gas, ", _u(used / sizes[i]), " gas/byte"));
        }
    }
    function _u(uint256 v) internal pure returns (string memory) {
        if (v == 0) return "0";
        uint256 n = v; uint256 d;
        while (n != 0) { d++; n /= 10; }
        bytes memory b = new bytes(d);
        while (v != 0) { b[--d] = bytes1(uint8(48 + (v % 10))); v /= 10; }
        return string(b);
    }
}
