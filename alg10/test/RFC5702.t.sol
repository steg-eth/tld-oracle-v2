// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {RSASHA512Algorithm} from "../src/RSASHA512Algorithm.sol";

/// RFC 5702 section 6.2, the standard's own RSA/SHA-512 key and signature.
///
/// The neighbouring RSASHA256 vector in `ens-contracts` comes from section 6.1 of the same RFC.
/// This is its sibling: the same `example.net` key owner, the same
/// `www.example.net. 3600 IN A 192.0.2.91` record, and the same 2000 to 2030 validity. It has no
/// expiry, so it cannot rot the way a captured live chain does.
contract RFC5702Test {
    bytes constant KEY = hex"0100030a03010001d1e8353396f9eb7ce8ab89396443a75a6776fc1be98f379d25575f22c0dc32eba1139490de97d0eea99d69e3250ba35ff03286a143c63d77b4e9c3f6eff591383b715eab92532b643b49090e4f0a5fc3ed034fb2056c32ed49d90f20a4ca73b4d14ba4f073d5b5978c3b5a47b6500656773c5635d994d29dca2b7df7069a138b";
    bytes constant DATA = hex"00010a0300000e1070dbd880386d43800e9c076578616d706c65036e65740003777777076578616d706c65036e6574000001000100000e100004c000025b";
    bytes constant SIG = hex"b6c6f8c278d15039c1d41522fade933135d38635671be782916aa3bef8e1cd02f5774611a0e7b409bc6b54361dd310edb2e25169e530d5ea7de0fcc45b3af48866206415a6ff3a6afbd7ceb9a8182517c3a9f45e281cccc1e38b0e235af223f983dbcc869bafe8e3e5be95f09bd49af595c86cd9753011a4d1fb613e0c5d0cbc";

    RSASHA512Algorithm internal algo = new RSASHA512Algorithm();

    function test_rfc5702_validSignature() public view {
        require(algo.verify(KEY, DATA, SIG), "RFC 5702 section 6.2 vector rejected");
    }

    /// Mirrors the invalid case the upstream table runs for every algorithm: one byte appended
    /// to the signed data.
    function test_rfc5702_invalidSignature() public view {
        require(!algo.verify(KEY, abi.encodePacked(DATA, hex"00"), SIG), "tampered data accepted");
    }

    /// A truncated signature must be refused rather than revert.
    function test_rfc5702_shortSignature() public view {
        bytes memory short = new bytes(SIG.length - 1);
        for (uint256 i; i < short.length; i++) short[i] = SIG[i];
        require(!algo.verify(KEY, DATA, short), "short signature accepted");
    }
}
