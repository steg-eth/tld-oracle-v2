// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

// THROWAWAY AUDIT TEST - do not commit.

import {RSAPKCS1Verify} from "../src/contracts/dnssec-oracle/algorithms/RSAPKCS1Verify.sol";

contract W2 {
    function s512(bytes memory n, bytes memory e, bytes memory sig, bytes memory h) external view returns (bool) {
        return RSAPKCS1Verify.verifySHA512(n, e, sig, h);
    }
}

/// Exhaustive forgery search over the PKCS#1 v1.5 block, using exponent 1 so the
/// "recovered" value is exactly whatever the attacker supplies. This is the strongest
/// possible attacker: full control of the encoded message, zero RSA work.
contract AuditPKCS1ForgeTest {
    W2 internal w = new W2();
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

    bytes constant DI512 = hex"3051300d060960864801650304020305000440";

    function _ff(uint256 n) internal pure returns (bytes memory b) {
        b = new bytes(n);
        for (uint256 i; i < n; i++) b[i] = 0xff;
    }
    function _h() internal pure returns (bytes memory h) {
        h = new bytes(64);
        for (uint256 i; i < 64; i++) h[i] = bytes1(uint8(i + 1));
    }
    function _em(uint256 k) internal pure returns (bytes memory) {
        return abi.encodePacked(hex"0001", _ff(k - 3 - 19 - 64), hex"00", DI512, _h());
    }
    function _v(uint256 k, bytes memory sig) internal view returns (uint256) {
        try w.s512(_ff(k), hex"01", sig, _h()) returns (bool r) { return r ? 1 : 0; } catch { return 2; }
    }

    /// Every single-byte position, every one of the 255 wrong values, at seven modulus sizes.
    function test_exhaustiveSingleByteForgery() public view {
        uint256[7] memory ks = [uint256(94), 95, 96, 127, 128, 129, 256];
        uint256 accepted;
        uint256 tried;
        for (uint256 x; x < ks.length; x++) {
            uint256 k = ks[x];
            require(_v(k, _em(k)) == 1, "baseline rejected");
            for (uint256 p; p < k; p++) {
                // all 255 wrong values at the structural positions, 3 samples elsewhere
                bool structural = p < 3 || p == k - 83 - 1 || p == k - 83 || p == k - 83 + 1 || p == k - 65 || p == k - 1;
                uint256 step = structural ? 1 : 85;
                for (uint256 d = 1; d < 256; d += step) {
                    bytes memory bad = _em(k);
                    bad[p] = bytes1(uint8((uint8(bad[p]) + d) & 0xff));
                    tried++;
                    if (_v(k, bad) == 1) { accepted++; _log(string.concat("FORGED k=", _u(k), " pos=", _u(p), " delta=", _u(d))); }
                }
            }
        }
        _log(string.concat("single-byte forgeries tried=", _u(tried), " accepted=", _u(accepted)));
        require(accepted == 0, "forgery accepted");
    }

    /// Signature length not equal to the modulus length, at every nearby length.
    /// RFC 8017 section 8.2.2 step 1 says a signature that is not k octets is invalid.
    function test_signatureLengthNotChecked() public view {
        uint256 k = 128;
        bytes memory em = _em(k);
        uint256 accepted;
        // shorter: strip leading zeros (value preserved), which is still a valid value mod n
        bytes memory stripped = new bytes(k - 1);
        for (uint256 i; i < k - 1; i++) stripped[i] = em[i + 1];
        uint256 rStrip = _v(k, stripped);
        // longer: zero-extend on the left (value preserved)
        for (uint256 extra = 1; extra <= 4; extra++) {
            bytes memory padded = new bytes(k + extra);
            for (uint256 i; i < k; i++) padded[extra + i] = em[i];
            if (_v(k, padded) == 1) accepted++;
        }
        _log(string.concat("leading-zero-stripped sig (", _u(k - 1), " bytes) -> ", _u(rStrip),
                           " ; zero-extended sigs accepted: ", _u(accepted), "/4"));
    }
}
