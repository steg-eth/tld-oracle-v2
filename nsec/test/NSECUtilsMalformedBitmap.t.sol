// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {DNSSECImpl} from "../src/contracts/dnssec-oracle/DNSSECImpl.sol";
import {NSECUtils} from "../src/NSECUtils.sol";
import {RootAbsencePredicate} from "../src/RootAbsencePredicate.sol";
import {SyntheticChainBuilder} from "./SyntheticChainBuilder.sol";

/// `NSECUtils.hasType`'s own documented safety property: a malformed bitmap must revert, never
/// silently answer `false`. "If a misread length byte made the reader skip the window that holds
/// the NS bit, the reader would report NS as absent, and the caller would release a live
/// delegation." These drive the check through `RootAbsencePredicate.hasType` (a real external
/// call, needed so `try/catch` can observe the revert of an otherwise-internal library call).
contract NSECUtilsMalformedBitmapTest is SyntheticChainBuilder {
    function _selector(bytes memory reason) internal pure returns (bytes4 sel) {
        require(reason.length >= 4, "revert reason too short to carry a selector");
        assembly {
            sel := mload(add(reason, 32))
        }
    }

    function _try(bytes memory bitmap, uint16 dnstype) internal returns (bool reverted, bytes4 sel) {
        RootAbsencePredicate predicate = new RootAbsencePredicate(_freshOracle());
        try predicate.hasType(bitmap, dnstype) {
            reverted = false;
        } catch (bytes memory reason) {
            reverted = true;
            sel = _selector(reason);
        }
    }

    function _freshOracle() internal returns (DNSSECImpl oracle) {
        (oracle, , ) = _zoneKeyChain(hex"00", 0);
    }

    /// An empty bitmap must revert, not report the type absent.
    function test_EmptyBitmapReverts() external {
        (bool reverted, bytes4 sel) = _try(hex"", NSECUtils.DNSTYPE_NS);
        require(reverted, "CONTROL FAILED: an empty bitmap must revert");
        require(sel == NSECUtils.EmptyTypeBitmap.selector, "expected EmptyTypeBitmap");
    }

    /// A window/length header that does not even fit in the remaining bytes must revert.
    function test_TruncatedHeaderReverts() external {
        (bool reverted, bytes4 sel) = _try(hex"00", NSECUtils.DNSTYPE_NS);
        require(reverted, "CONTROL FAILED: a one-byte bitmap (no room for a length byte) must revert");
        require(sel == NSECUtils.TruncatedTypeBitmap.selector, "expected TruncatedTypeBitmap");
    }

    /// A length byte that claims more data than is actually present must revert, not silently
    /// stop reading early.
    function test_TruncatedDataReverts() external {
        // window 0, length 5, but only 3 data bytes follow.
        (bool reverted, bytes4 sel) = _try(hex"0005000000", NSECUtils.DNSTYPE_NS);
        require(reverted, "CONTROL FAILED: a block whose declared length overruns the buffer must revert");
        require(sel == NSECUtils.TruncatedTypeBitmap.selector, "expected TruncatedTypeBitmap");
    }

    /// A zero-length window block is malformed per RFC 4034 4.1.2 (every block must carry at
    /// least one byte).
    function test_ZeroLengthBlockReverts() external {
        (bool reverted, bytes4 sel) = _try(hex"0000", NSECUtils.DNSTYPE_NS);
        require(reverted, "CONTROL FAILED: a zero-length window block must revert");
        require(sel == NSECUtils.InvalidTypeBitmapBlock.selector, "expected InvalidTypeBitmapBlock");
    }

    /// A window block longer than the 32 bytes a window can hold (256 bits) must revert.
    function test_OversizedBlockReverts() external {
        (bool reverted, bytes4 sel) = _try(hex"0021", NSECUtils.DNSTYPE_NS); // length 33
        require(reverted, "CONTROL FAILED: a 33-byte window block must revert");
        require(sel == NSECUtils.InvalidTypeBitmapBlock.selector, "expected InvalidTypeBitmapBlock");
    }

    /// Window numbers must strictly increase. A repeated (or descending) window could otherwise
    /// hide a set bit behind a clear one read from an earlier block.
    function test_NonIncreasingWindowOrderReverts() external {
        // window 1, length 1, data 0x00, twice in a row -- the second window does not increase.
        (bool reverted, bytes4 sel) = _try(hex"010100010100", NSECUtils.DNSTYPE_NS);
        require(reverted, "CONTROL FAILED: a repeated window number must revert");
        require(sel == NSECUtils.TypeBitmapWindowsOutOfOrder.selector, "expected TypeBitmapWindowsOutOfOrder");
    }

    /// Sanity: a well-formed two-window bitmap (strictly increasing windows) is accepted, so the
    /// revert above is attributable to the ordering, not to using two blocks at all.
    function test_AttributionTwoIncreasingWindowsAccepted() external {
        // window 0 (length 1, data 0x00), window 1 (length 1, data 0x80 -> bit 256+0 set).
        bytes memory bitmap = hex"000100010180";
        RootAbsencePredicate predicate = new RootAbsencePredicate(_freshOracle());
        require(!predicate.hasType(bitmap, NSECUtils.DNSTYPE_NS), "window 0 has no bits set");
        require(predicate.hasType(bitmap, 256), "window 1 bit 0 (type 256) must read as set");
    }
}
