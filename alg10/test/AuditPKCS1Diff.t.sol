// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

// THROWAWAY AUDIT TEST - do not commit.

import {RSAPKCS1Verify} from "../src/contracts/dnssec-oracle/algorithms/RSAPKCS1Verify.sol";
import {RSAPKCS1VerifyUpstream} from "./upstream/RSAPKCS1VerifyUpstream.sol";

/// External wrappers so a revert can be observed with try/catch.
contract W {
    function s1(bytes memory n, bytes memory e, bytes memory sig, bytes20 h) external view returns (bool) {
        return RSAPKCS1Verify.verifySHA1(n, e, sig, h);
    }
    function s256(bytes memory n, bytes memory e, bytes memory sig, bytes32 h) external view returns (bool) {
        return RSAPKCS1Verify.verifySHA256(n, e, sig, h);
    }
    function s512(bytes memory n, bytes memory e, bytes memory sig, bytes memory h) external view returns (bool) {
        return RSAPKCS1Verify.verifySHA512(n, e, sig, h);
    }
    function u1(bytes memory n, bytes memory e, bytes memory sig, bytes20 h) external view returns (bool) {
        return RSAPKCS1VerifyUpstream.verifySHA1(n, e, sig, h);
    }
    function u256(bytes memory n, bytes memory e, bytes memory sig, bytes32 h) external view returns (bool) {
        return RSAPKCS1VerifyUpstream.verifySHA256(n, e, sig, h);
    }
}

/// Did adding `hashLen` change the pre-existing SHA-1 or SHA-256 behaviour?
/// Every case below is run against both the vendored copy and the pristine upstream copy
/// (byte-identical to ensdomains/ens-contracts staging) and the outcomes are compared,
/// including whether each reverts.
contract AuditPKCS1DiffTest {
    W internal w = new W();
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

    bytes constant DI1 = hex"3021300906052b0e03021a05000414";
    bytes constant DI256 = hex"3031300d060960864801650304020105000420";
    bytes constant DI512 = hex"3051300d060960864801650304020305000440";

    function _ff(uint256 n) internal pure returns (bytes memory b) {
        b = new bytes(n);
        for (uint256 i; i < n; i++) b[i] = 0xff;
    }

    /// 0 = false, 1 = true, 2 = revert
    function _r1(bytes memory n, bytes memory e, bytes memory sig, bytes20 h) internal view returns (uint256) {
        try w.s1(n, e, sig, h) returns (bool r) { return r ? 1 : 0; } catch { return 2; }
    }
    function _r256(bytes memory n, bytes memory e, bytes memory sig, bytes32 h) internal view returns (uint256) {
        try w.s256(n, e, sig, h) returns (bool r) { return r ? 1 : 0; } catch { return 2; }
    }
    function _q1(bytes memory n, bytes memory e, bytes memory sig, bytes20 h) internal view returns (uint256) {
        try w.u1(n, e, sig, h) returns (bool r) { return r ? 1 : 0; } catch { return 2; }
    }
    function _q256(bytes memory n, bytes memory e, bytes memory sig, bytes32 h) internal view returns (uint256) {
        try w.u256(n, e, sig, h) returns (bool r) { return r ? 1 : 0; } catch { return 2; }
    }

    /// Builds a well-formed EM of k bytes for the given DigestInfo and hash.
    function _em(uint256 k, bytes memory di, bytes memory h) internal pure returns (bytes memory) {
        uint256 padLen = k - 3 - di.length - h.length;
        return abi.encodePacked(hex"0001", _ff(padLen), hex"00", di, h);
    }

    uint256 internal diffs;
    uint256 internal fixed1;
    uint256 internal fixed256;
    uint256 internal cases;
    uint256 internal trues;

    function _cmp1(bytes memory n, bytes memory e, bytes memory sig, bytes20 h, string memory tag) internal {
        cases++;
        uint256 a = _r1(n, e, sig, h);
        uint256 b = _q1(n, e, sig, h);
        if (a == 1) trues++;
        if (a != b) {
            // Intended by the H-1 guard: upstream reverts, the patched copy returns false.
            if (b == 2 && a == 0) { fixed1++; }
            else { diffs++; _log(string.concat("SHA1 DIVERGENCE ", tag, " vendored=", _u(a), " upstream=", _u(b))); }
        }
    }
    function _cmp256(bytes memory n, bytes memory e, bytes memory sig, bytes32 h, string memory tag) internal {
        cases++;
        uint256 a = _r256(n, e, sig, h);
        uint256 b = _q256(n, e, sig, h);
        if (a == 1) trues++;
        if (a != b) {
            // Intended by the H-1 guard: upstream reverts, the patched copy returns false.
            if (b == 2 && a == 0) { fixed256++; }
            else { diffs++; _log(string.concat("SHA256 DIVERGENCE ", tag, " vendored=", _u(a), " upstream=", _u(b))); }
        }
    }

    /// Valid blocks, mutated blocks, and every modulus length 0..130, for both legacy paths.
    function test_legacyPathsUnchanged() public {
        for (uint256 k = 0; k <= 130; k++) {
            bytes memory n = _ff(k);

            // SHA-1
            bytes20 h1 = bytes20(keccak256(abi.encode(k)));
            if (k >= 3 + DI1.length + 20) {
                bytes memory em = _em(k, DI1, abi.encodePacked(h1));
                _cmp1(n, hex"01", em, h1, string.concat("valid k=", _u(k)));
                // wrong hash
                _cmp1(n, hex"01", em, bytes20(uint160(uint160(h1) ^ 1)), string.concat("badhash k=", _u(k)));
                // corrupt a padding byte
                bytes memory bad = em; bad[3] = 0xfe;
                _cmp1(n, hex"01", bad, h1, string.concat("badpad k=", _u(k)));
                // corrupt the separator
                bytes memory bad2 = _em(k, DI1, abi.encodePacked(h1));
                bad2[k - 20 - DI1.length - 1] = 0x01;
                _cmp1(n, hex"01", bad2, h1, string.concat("badsep k=", _u(k)));
                // corrupt the DigestInfo
                bytes memory bad3 = _em(k, DI1, abi.encodePacked(h1));
                bad3[k - 20 - DI1.length] = 0x31;
                _cmp1(n, hex"01", bad3, h1, string.concat("baddi k=", _u(k)));
                // DigestInfo for SHA-256 presented to the SHA-1 verifier
                if (k >= 3 + DI256.length + 32) {
                    _cmp1(n, hex"01", _em(k, DI256, abi.encodePacked(bytes32(keccak256(abi.encode(k, 1))))), h1,
                          string.concat("sub256into1 k=", _u(k)));
                }
            }
            // short/odd moduli, arbitrary sig
            _cmp1(n, hex"01", _ff(k), h1, string.concat("ffsig k=", _u(k)));
            bytes memory s01 = new bytes(k);
            if (k > 1) { s01[1] = 0x01; for (uint256 i = 2; i < k; i++) s01[i] = 0xff; }
            _cmp1(n, hex"01", s01, h1, string.concat("0001sig k=", _u(k)));

            // SHA-256
            bytes32 h2 = keccak256(abi.encode(k, 2));
            if (k >= 3 + DI256.length + 32) {
                bytes memory em = _em(k, DI256, abi.encodePacked(h2));
                _cmp256(n, hex"01", em, h2, string.concat("valid k=", _u(k)));
                _cmp256(n, hex"01", em, bytes32(uint256(h2) ^ 1), string.concat("badhash k=", _u(k)));
                bytes memory bad = em; bad[3] = 0xfe;
                _cmp256(n, hex"01", bad, h2, string.concat("badpad k=", _u(k)));
                bytes memory bad2 = _em(k, DI256, abi.encodePacked(h2));
                bad2[k - 32 - DI256.length - 1] = 0x01;
                _cmp256(n, hex"01", bad2, h2, string.concat("badsep k=", _u(k)));
                _cmp256(n, hex"01", _em(k, DI1, abi.encodePacked(bytes20(keccak256(abi.encode(k, 3))))), h2,
                        string.concat("sub1into256 k=", _u(k)));
            }
            _cmp256(n, hex"01", _ff(k), h2, string.concat("ffsig k=", _u(k)));
            _cmp256(n, hex"01", s01, h2, string.concat("0001sig k=", _u(k)));

            // exponent 3 and 65537, sig = k bytes of pseudorandom
            bytes memory rs = new bytes(k);
            for (uint256 i; i < k; i++) rs[i] = bytes1(uint8(uint256(keccak256(abi.encode(k, i)))));
            _cmp1(n, hex"03", rs, h1, string.concat("e3 k=", _u(k)));
            _cmp256(n, hex"010001", rs, h2, string.concat("e65537 k=", _u(k)));
        }
        _log(string.concat("cases=", _u(cases), " true-results=", _u(trues),
             " unexpected-divergences=", _u(diffs),
             " revert-to-false SHA1=", _u(fixed1), " SHA256=", _u(fixed256)));
        require(diffs == 0, "vendored copy diverges from upstream in a way H-1 does not explain");
        require(fixed1 == 39, "expected 39 revert-to-false fixes on the SHA-1 path");
        require(fixed256 == 55, "expected 55 revert-to-false fixes on the SHA-256 path");
        require(trues > 0, "no case ever returned true, the test proves nothing");
    }

    /// Does the SHA-512 path reject every PKCS#1 mutation?
    function test_sha512Mutations() public view {
        uint256 k = 128;
        bytes memory n = _ff(k);
        bytes memory h = new bytes(64);
        for (uint256 i; i < 64; i++) h[i] = bytes1(uint8(i + 1));
        bytes memory em = _em(k, DI512, h);
        require(_r512(n, hex"01", em, h) == 1, "baseline must verify");

        // every single-byte mutation of the whole encoded message must be rejected
        uint256 accepted;
        for (uint256 p = 0; p < k; p++) {
            bytes memory bad = _em(k, DI512, h);
            bad[p] = bytes1(uint8(uint8(bad[p]) ^ 0xff));
            if (_r512(n, hex"01", bad, h) == 1) { accepted++; _log(string.concat("ACCEPTED mutation at byte ", _u(p))); }
        }
        // appending/removing a trailing byte
        bytes memory shortSig = new bytes(k - 1);
        for (uint256 i; i < k - 1; i++) shortSig[i] = em[i];
        uint256 rShort = _r512(n, hex"01", shortSig, h);
        // DigestInfo for SHA-256 with a 64-byte "hash"
        uint256 rSub = _r512(n, hex"01", _em(k, DI256, h), h);
        _log(string.concat("sha512 mutations accepted=", _u(accepted), " shortSig=", _u(rShort), " sub256=", _u(rSub)));
        require(accepted == 0, "a mutated PKCS#1 block was accepted");
        require(rSub != 1, "SHA-256 DigestInfo accepted by the SHA-512 verifier");
    }
    function _r512(bytes memory n, bytes memory e, bytes memory sig, bytes memory h) internal view returns (uint256) {
        try w.s512(n, e, sig, h) returns (bool r) { return r ? 1 : 0; } catch { return 2; }
    }

    /// A 64-byte hash handed to verifySHA512 at every modulus length: where does it revert?
    function test_sha512ModulusSweep() public view {
        bytes memory h = new bytes(64);
        for (uint256 i; i < 64; i++) h[i] = bytes1(uint8(i + 1));
        uint256 firstOk = type(uint256).max;
        uint256 lastRevert;
        for (uint256 k = 0; k <= 140; k++) {
            bytes memory n = _ff(k);
            bytes memory s01 = new bytes(k);
            if (k > 1) { s01[1] = 0x01; for (uint256 i = 2; i < k; i++) s01[i] = 0xff; }
            uint256 r = _r512(n, hex"01", s01, h);
            if (r == 2) lastRevert = k;
            if (r != 2 && firstOk == type(uint256).max) firstOk = k;
        }
        _log(string.concat("verifySHA512: reverts for modulus length <= ", _u(lastRevert),
                           ", first non-revert at ", _u(firstOk)));
    }
}
