// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {SHA512} from "../src/SHA512.sol";

/// Cost of `SHA512.hash` by message size. The padding rule puts the boundary at 112 bytes, so
/// 0 and 111 are one block and 112 is two. The per-block figure is the difference between
/// consecutive sizes, which isolates the compression function from the fixed setup.
abstract contract Console {
    address internal constant CONSOLE = 0x000000000000000000636F6e736F6c652e6c6f67;
    function _log(string memory s) internal view {
        (bool ok,) = CONSOLE.staticcall(abi.encodeWithSignature("log(string)", s));
        ok;
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
}

contract SHA512GasTest is Console {
    function test_sha512GasBySize() public view {
        uint256[7] memory sizes = [uint256(0), 111, 112, 239, 240, 495, 1007];
        _log("bytes   blocks        gas   per block");
        uint256 prevGas;
        uint256 prevBlocks;
        for (uint256 i; i < sizes.length; i++) {
            bytes memory m = new bytes(sizes[i]);
            uint256 g0 = gasleft();
            SHA512.hash(m);
            uint256 used = g0 - gasleft();
            uint256 blocks = ((sizes[i] + 17 + 127) / 128);
            string memory per = "-";
            if (i > 0 && blocks > prevBlocks) {
                per = _u((used - prevGas) / (blocks - prevBlocks));
            }
            _log(
                string.concat(
                    _pad(_u(sizes[i]), 5), _pad(_u(blocks), 8),
                    _pad(_u(used), 11), "   ", per
                )
            );
            prevGas = used; prevBlocks = blocks;
        }
    }
}
