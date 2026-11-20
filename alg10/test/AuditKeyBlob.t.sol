// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

// THROWAWAY AUDIT TEST - do not commit.

import {RSASHA512Algorithm} from "../src/RSASHA512Algorithm.sol";
import {RSASHA256Algorithm} from "../src/contracts/dnssec-oracle/algorithms/RSASHA256Algorithm.sol";
import {SHA512} from "../src/SHA512.sol";

contract AuditKeyBlobTest {
    RSASHA512Algorithm internal a10 = new RSASHA512Algorithm();
    RSASHA256Algorithm internal a8 = new RSASHA256Algorithm();

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
    function _hex(bytes memory b) internal pure returns (string memory) {
        bytes memory h = "0123456789abcdef";
        bytes memory o = new bytes(2 * b.length);
        for (uint256 i; i < b.length; i++) {
            o[2*i] = h[uint8(b[i]) >> 4];
            o[2*i+1] = h[uint8(b[i]) & 0xf];
        }
        return string(o);
    }

    /// key = flags(2) protocol(1) alg(1) explen(1) exponent modulus
    function _key(bytes memory exponent, bytes memory modulus) internal pure returns (bytes memory) {
        require(exponent.length < 256, "use long form");
        return abi.encodePacked(hex"0100", hex"03", hex"0a", uint8(exponent.length), exponent, modulus);
    }

    function _ff(uint256 n) internal pure returns (bytes memory b) {
        b = new bytes(n);
        for (uint256 i; i < n; i++) b[i] = 0xff;
    }

    /// Returns 0 = returned false, 1 = returned true, 2 = reverted; and the revert data.
    function _probe(bytes memory key, bytes memory data, bytes memory sig)
        internal view returns (uint256, bytes memory)
    {
        try a10.verify(key, data, sig) returns (bool r) {
            return (r ? 1 : 0, "");
        } catch (bytes memory err) {
            return (2, err);
        }
    }

    function _probe8(bytes memory key, bytes memory data, bytes memory sig)
        internal view returns (uint256, bytes memory)
    {
        try a8.verify(key, data, sig) returns (bool r) {
            return (r ? 1 : 0, "");
        } catch (bytes memory err) {
            return (2, err);
        }
    }

    bytes internal constant DATA = hex"deadbeef";

    // ---------------------------------------------------------------- F-1
    // modulus of length 0: `result[0]` indexes an empty array.
    function test_F1_zeroLengthModulus() public view {
        bytes memory key = _key(hex"03", "");
        (uint256 r, bytes memory err) = _probe(key, DATA, _ff(128));
        _log(string.concat("F1 zero-length modulus  -> ", _u(r), " err=0x", _hex(err)));
        require(r == 0, "F1: short modulus must return false, not revert (H-1)");
    }

    // ---------------------------------------------------------------- F-2
    // 2..63 byte modulus with e=1: result.length - 64 underflows.
    function test_F2_shortModulusUnderflow() public view {
        bytes memory modulus = _ff(32);                 // n = 2**256-1
        bytes memory key = _key(hex"01", modulus);      // e = 1
        bytes memory sig = new bytes(32);
        sig[0] = 0x00; sig[1] = 0x01;
        for (uint256 i = 2; i < 32; i++) sig[i] = 0xff;
        (uint256 r, bytes memory err) = _probe(key, DATA, sig);
        _log(string.concat("F2 32-byte modulus      -> ", _u(r), " err=0x", _hex(err)));
        require(r == 0, "F2: 32-byte modulus must return false, not revert (H-1)");
    }

    // ---------------------------------------------------------------- F-3
    // Sweep every modulus length and record revert vs false, for alg 10 and alg 8.
    function test_F3_sweepModulusLengths() public view {
        _log("len  alg10  alg8   (0=false 1=true 2=REVERT)");
        for (uint256 len = 0; len <= 96; len++) {
            bytes memory modulus = _ff(len);
            bytes memory key10 = _key(hex"01", modulus);
            bytes memory sig = new bytes(len);
            if (len > 0) sig[0] = 0x00;
            if (len > 1) sig[1] = 0x01;
            for (uint256 i = 2; i < len; i++) sig[i] = 0xff;
            (uint256 r10,) = _probe(key10, DATA, sig);
            bytes memory key8 = abi.encodePacked(hex"0100", hex"03", hex"08", uint8(1), hex"01", modulus);
            (uint256 r8,) = _probe8(key8, DATA, sig);
            if (r10 == 2 || r8 == 2) {
                _log(string.concat(_u(len), "    ", _u(r10), "      ", _u(r8)));
            }
        }
    }

    // ---------------------------------------------------------------- F-4
    // key shorter than 5 bytes reverts in readUint8.
    function test_F4_shortKey() public view {
        for (uint256 n = 0; n < 8; n++) {
            bytes memory key = new bytes(n);
            (uint256 r, bytes memory err) = _probe(key, DATA, _ff(128));
            _log(string.concat("F4 key len ", _u(n), " -> ", _u(r), " err=0x", _hex(err)));
        }
    }

    // ---------------------------------------------------------------- F-5
    // Long-exponent form: explen byte 0, then a 16-bit length.
    function test_F5_longExponentForm() public view {
        // declared exponent length 0xFFFF but key is short -> revert
        bytes memory key = abi.encodePacked(hex"0100", hex"03", hex"0a", uint8(0), uint16(0xFFFF));
        (uint256 r, bytes memory err) = _probe(key, DATA, _ff(128));
        _log(string.concat("F5a explen=0xffff short key -> ", _u(r), " err=0x", _hex(err)));

        // declared exponent length 0 in long form -> empty exponent, modexp gives 1
        bytes memory key2 = abi.encodePacked(hex"0100", hex"03", hex"0a", uint8(0), uint16(0), _ff(128));
        (uint256 r2, bytes memory err2) = _probe(key2, DATA, _ff(128));
        _log(string.concat("F5b explen=0 long form      -> ", _u(r2), " err=0x", _hex(err2)));

        // long form with key.length == 7 exactly -> zero length modulus
        bytes memory key3 = abi.encodePacked(hex"0100", hex"03", hex"0a", uint8(0), uint16(0));
        (uint256 r3, bytes memory err3) = _probe(key3, DATA, _ff(128));
        _log(string.concat("F5c explen=0, no modulus    -> ", _u(r3), " err=0x", _hex(err3)));
    }

    // ---------------------------------------------------------------- F-6
    // Minimum modulus that the PKCS#1 checker will accept for SHA-512: 94 bytes = 752 bits.
    // With e=1 the recovered value is the signature itself, so this shows the checker's
    // acceptance boundary without needing a real key.
    function test_F6_acceptanceBoundary() public view {
        bytes memory digest = SHA512.hash(DATA);
        bytes memory di = hex"3051300d060960864801650304020305000440";
        for (uint256 k = 90; k <= 96; k++) {
            if (k < 2 + 1 + di.length + 64) { _log(string.concat("F6 k=", _u(k), " too small to encode")); continue; }
            uint256 padLen = k - 3 - di.length - 64;
            bytes memory em = abi.encodePacked(hex"0001", _ff(padLen), hex"00", di, digest);
            require(em.length == k, "em length");
            bytes memory modulus = _ff(k);
            bytes memory key = _key(hex"01", modulus);
            (uint256 r,) = _probe(key, DATA, em);
            _log(string.concat("F6 k=", _u(k), " padLen=", _u(padLen), " -> ", _u(r)));
        }
    }

    // ---------------------------------------------------------------- F-7
    // Signature longer than the modulus: RFC 8017 8.2.2 step 1 says reject.
    // Here s and s+n recover identically, so a valid signature has infinitely many encodings.
    function test_F7_signatureMalleability() public view {
        bytes memory digest = SHA512.hash(DATA);
        bytes memory di = hex"3051300d060960864801650304020305000440";
        uint256 k = 128;
        uint256 padLen = k - 3 - di.length - 64;
        bytes memory em = abi.encodePacked(hex"0001", _ff(padLen), hex"00", di, digest);
        bytes memory modulus = _ff(k);          // n = 2**1024 - 1
        bytes memory key = _key(hex"01", modulus);
        (uint256 r1,) = _probe(key, DATA, em);
        // s' = s + n, encoded in 129 bytes. s + n = s + 2**1024 - 1.
        bytes memory big = new bytes(129);
        // 129-byte big-endian of (em + n). Add manually.
        uint256 carry = 0;
        for (uint256 i = 0; i < 128; i++) {
            uint256 idx = 127 - i;
            uint256 s = uint256(uint8(em[idx])) + 0xff + carry;
            big[idx + 1] = bytes1(uint8(s & 0xff));
            carry = s >> 8;
        }
        big[0] = bytes1(uint8(carry));
        (uint256 r2,) = _probe(key, DATA, big);
        _log(string.concat("F7 s -> ", _u(r1), " ; s+n (129 bytes) -> ", _u(r2)));
        require(r1 == 1, "F7: base signature should verify");
    }
}
