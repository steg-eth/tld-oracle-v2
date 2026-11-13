//SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {RRUtils} from "./contracts/dnssec-oracle/RRUtils.sol";
import {BytesUtils} from "./contracts/utils/BytesUtils.sol";

/// @title NSECUtils
/// @notice Readers for DNSSEC NSEC records, per RFC 4034 section 4.
/// @dev The ENS DNSSEC oracle authenticates an NSEC record. It does not read one.
///      `dnssec-oracle/DNSSECImpl.sol` line 15 puts NSEC out of scope. That line is about the
///      conclusion the oracle draws, not about what it authenticates. The oracle returns the
///      authenticated record, and this library reads it. The oracle needs no change.
///
///      Two functions here are the parts that bite. `coversName` is the wrap-aware comparator.
///      `hasType` is the type-bitmap reader. Both are pure. `RootAbsencePredicate` makes both
///      available as public pure functions, for direct calls and for fuzzing.
///
///      The readers are strict. A malformed name or a malformed bitmap makes a reader revert.
///      It does not make a reader report a type as absent. A record that releases a live
///      top-level domain must not come from a misread byte.
library NSECUtils {
    using BytesUtils for bytes;

    /// @dev Type numbers used by the predicate. NS is the signal. DS is here only to be read
    ///      by tests, because `aq.` and `zw.` are live delegations with no DS.
    uint16 internal constant DNSTYPE_NS = 2;
    uint16 internal constant DNSTYPE_DS = 43;
    uint16 internal constant DNSTYPE_RRSIG = 46;
    uint16 internal constant DNSTYPE_NSEC = 47;

    /// @dev Limits from RFC 1035 section 2.3.4.
    uint256 internal constant MAX_NAME_LENGTH = 255;
    uint256 internal constant MAX_LABEL_LENGTH = 63;

    /// @dev The wire form of the DNS root.
    bytes internal constant ROOT_NAME = hex"00";

    /// @dev The name is not a well formed, uncompressed, wire format DNS name.
    error MalformedName(bytes name);

    /// @dev The name holds an uppercase ASCII letter. DNS canonical order treats uppercase as
    ///      lowercase, and `RRUtils.compareNames` compares raw bytes. An uppercase query name
    ///      would therefore sort into the wrong gap.
    error NonCanonicalName(bytes name);

    /// @dev The type bitmap has no bytes. An NSEC record always lists at least RRSIG and NSEC.
    error EmptyTypeBitmap();

    /// @dev A bitmap window block runs past the end of the record.
    error TruncatedTypeBitmap(uint256 offset);

    /// @dev A window block length is 0, or is more than the 32 bytes that one window holds.
    error InvalidTypeBitmapBlock(uint8 window, uint8 length);

    /// @dev Window blocks must be in increasing window order, per RFC 4034 section 4.1.2.
    ///      A repeated window could otherwise hide a set bit behind a clear one.
    error TypeBitmapWindowsOutOfOrder(uint8 previousWindow, uint8 window);

    // -------------------------------------------------------------- the wrap-aware comparator

    /// @notice Does one NSEC record deny the existence of `name`, inside the zone whose apex is
    ///         `zoneApex`?
    /// @dev The record states that no name exists between its owner name and its next-owner
    ///      name. Two forms exist.
    ///
    ///      1. An ordinary gap. `owner < name` and `name < next`.
    ///      2. The record that closes the zone. Its next-owner name is the zone apex, per
    ///         RFC 4034 section 4.1.1, and the apex sorts lowest of all names in the zone. The
    ///         root zone closes with `zw. NSEC .`. The test `owner < name AND name < next` is
    ///         then false for a name that is genuinely absent, because every name is above the
    ///         apex. So the closing record covers every name above its owner name.
    ///
    ///      **The closing form is keyed on the apex, not on the order of the two endpoints.**
    ///      An earlier revision took the closing branch whenever `next <= owner`. Two shapes
    ///      then read as the record that closes the zone, and each one released live names.
    ///
    ///      - `com. NSEC com.`, where `next == owner`, covered every name above `com.`, so it
    ///        reported `net.` absent.
    ///      - `. NSEC .`, where both names are the apex, covered every name above the apex, so
    ///        it reported every top-level domain absent.
    ///
    ///      Both conditions below are needed. `next == zoneApex` alone leaves `. NSEC .` open,
    ///      because the apex is its own next-owner name there. The apex can never own the
    ///      closing record, because it is the lowest name in the zone and its record always
    ///      points forward.
    ///
    ///      Measured against the published root zone, serial 2026111203 of 12 November 2026,
    ///      1437 NSEC records: exactly one takes the closing branch, `zw. NSEC .`, and its
    ///      next-owner name is the apex. No record has `next == owner`. The one apex-owned
    ///      record is `. NSEC aaa.`, which points forward. The chain is one closed cycle of
    ///      1437 steps over 1437 distinct owner names. So both conditions cost no liveness.
    ///
    ///      The form must not over-accept. A name below the owner name of the closing record is
    ///      not covered by it. Control: `com.` is not covered by the `zw.` record.
    ///
    ///      A name equal to the owner name, or equal to the next-owner name, exists. This
    ///      function returns false for both. Read the type bitmap of the matching record
    ///      instead, with `hasType`.
    ///
    ///      The comparator is `RRUtils.compareNames`, which is the upstream comparator that
    ///      the 17 measurement tests exercise. This function adds the wrap and nothing else.
    ///
    ///      Use this for names at one level below the zone apex, which is what a top-level
    ///      domain is. The span of an NSEC record that is a delegation point does not deny
    ///      names below that delegation. `RootAbsencePredicate` holds the queried name, the
    ///      owner name and the next-owner name to one label for that reason, and the depth rule
    ///      stays there because it is a rule about the root zone's own shape rather than about
    ///      the comparison. The apex rule is here instead, because it is what the comparison
    ///      means: without it this function over-accepts for any caller.
    /// @param owner The owner name of the NSEC record, in wire format.
    /// @param next The next-owner name from the record's rdata, in wire format.
    /// @param name The queried name, in wire format.
    /// @param zoneApex The apex of the zone that signed the record, in wire format. For a
    ///        root-signed record this is the root. `RootAbsencePredicate` passes the RRSIG
    ///        signer name, which the oracle authenticates.
    /// @return True if the record denies that `name` exists.
    function coversName(
        bytes memory owner,
        bytes memory next,
        bytes memory name,
        bytes memory zoneApex
    ) internal pure returns (bool) {
        requireWireName(owner);
        requireWireName(next);
        requireWireName(name);
        requireWireName(zoneApex);
        if (RRUtils.compareNames(owner, name) >= 0) {
            // The name is the owner name, or sorts below it. Neither form covers it.
            return false;
        }
        if (next.equals(zoneApex)) {
            // The record closes the zone, and it covers every name above its owner name. The
            // apex itself cannot own that record, so `. NSEC .` covers nothing.
            return !owner.equals(zoneApex);
        }
        // An ordinary gap. A record whose next-owner name sorts below its owner name without
        // being the apex is not a closing record, and this test then covers nothing.
        return RRUtils.compareNames(name, next) < 0;
    }

    // ------------------------------------------------------------- the type bitmap reader

    /// @notice Does the type bitmap in `data`, starting at `offset`, list `dnstype`?
    /// @dev The bitmap is a sequence of window blocks, per RFC 4034 section 4.1.2. One block is
    ///      a window number byte, a length byte, and that many bitmap bytes. A type number is
    ///      `window * 256 + bit`, and bit 0 is the most significant bit of the first byte.
    ///
    ///      The bitmap runs to the end of `data`. NSEC rdata is the next-owner name followed by
    ///      the bitmap, so the end of the rdata is the end of the bitmap.
    ///
    ///      This function reads every block, even after it finds the answer. A malformed block
    ///      anywhere makes it revert: an empty bitmap, a truncated one, a length byte of zero or
    ///      above 32, or windows out of order. The reason is the failure mode. If a misread length
    ///      byte made the reader skip the window that holds the NS bit, the reader would report NS
    ///      as absent, and the caller would release a live delegation. A revert is safe. A false is
    ///      not.
    ///
    ///      A well formed block that is too short to hold the wanted bit is not malformed, and
    ///      returns false. RFC 4034 section 4.1.2 lets a signer omit trailing zero bytes, so a bit
    ///      beyond the block's length is a zero bit and not a missing one.
    ///
    ///      Trailing zero bytes inside a block are read as zero bits, per RFC 4034 section
    ///      4.1.2. RFC 4034 asks a signer to omit them. A root-signed record that carries one is
    ///      still read, because a zero byte cannot hide a set bit.
    /// @param data The bytes that hold the bitmap. Usually the rdata of an NSEC record.
    /// @param offset The offset of the first window block.
    /// @param dnstype The type number to look for.
    /// @return found True if the bitmap lists the type.
    function hasType(
        bytes memory data,
        uint256 offset,
        uint16 dnstype
    ) internal pure returns (bool found) {
        uint256 end = data.length;
        if (offset >= end) {
            revert EmptyTypeBitmap();
        }
        uint256 wantWindow = uint256(dnstype) >> 8;
        uint256 wantBit = uint256(dnstype) & 0xFF;
        uint8 previousWindow;
        bool first = true;
        uint256 i = offset;
        while (i < end) {
            if (i + 2 > end) {
                revert TruncatedTypeBitmap(i);
            }
            uint8 window = uint8(data[i]);
            uint8 length = uint8(data[i + 1]);
            if (length == 0 || length > 32) {
                revert InvalidTypeBitmapBlock(window, length);
            }
            if (!first && window <= previousWindow) {
                revert TypeBitmapWindowsOutOfOrder(previousWindow, window);
            }
            uint256 nextBlock = i + 2 + uint256(length);
            if (nextBlock > end) {
                revert TruncatedTypeBitmap(i);
            }
            if (
                uint256(window) == wantWindow &&
                wantBit < uint256(length) * 8
            ) {
                uint8 b = uint8(data[i + 2 + (wantBit >> 3)]);
                found = ((b >> (7 - (wantBit & 7))) & 1) != 0;
            }
            previousWindow = window;
            first = false;
            i = nextBlock;
        }
    }

    /// @notice Does the NSEC record with this rdata list `dnstype`?
    /// @dev Reads the next-owner name to find where the bitmap starts, then reads the bitmap.
    /// @param rdata The rdata of an NSEC record.
    /// @param dnstype The type number to look for.
    /// @return True if the bitmap lists the type.
    function rdataHasType(
        bytes memory rdata,
        uint16 dnstype
    ) internal pure returns (bool) {
        (, uint256 bitmapOffset) = nextOwnerName(rdata);
        return hasType(rdata, bitmapOffset, dnstype);
    }

    // ------------------------------------------------------------------------- record reading

    /// @notice Reads the next-owner name from the rdata of an NSEC record.
    /// @dev The rdata of an NSEC record is an uncompressed name, then the type bitmap. This
    ///      walks the labels with its own bounds checks. A length byte of 192 or more is a
    ///      compression pointer, which RFC 4034 section 6.2 does not allow in signed rdata, and
    ///      which this rejects as malformed.
    /// @param rdata The rdata of an NSEC record.
    /// @return next The next-owner name, in wire format.
    /// @return bitmapOffset The offset of the first window block of the type bitmap.
    function nextOwnerName(
        bytes memory rdata
    ) internal pure returns (bytes memory next, uint256 bitmapOffset) {
        uint256 end = rdata.length;
        uint256 i;
        while (true) {
            if (i >= end) {
                revert MalformedName(rdata);
            }
            uint8 labelLength = uint8(rdata[i]);
            if (labelLength == 0) {
                i += 1;
                break;
            }
            if (labelLength > MAX_LABEL_LENGTH) {
                revert MalformedName(rdata);
            }
            i += 1 + uint256(labelLength);
        }
        if (i > MAX_NAME_LENGTH) {
            revert MalformedName(rdata);
        }
        next = rdata.substring(0, i);
        bitmapOffset = i;
    }

    // ----------------------------------------------------------------------- name validation

    /// @notice Checks that `name` is a well formed, uncompressed, wire format DNS name.
    /// @dev `RRUtils.compareNames` walks a name with `assert`. A malformed name therefore gives
    ///      a panic, or a comparison against bytes that are not a name. Both are worse than a
    ///      named error. The name must end at the terminating zero byte, with no extra bytes
    ///      after it.
    /// @param name The name to check, in wire format.
    /// @return labels The number of labels in the name. The root has zero.
    function requireWireName(
        bytes memory name
    ) internal pure returns (uint256 labels) {
        uint256 end = name.length;
        if (end > MAX_NAME_LENGTH) {
            revert MalformedName(name);
        }
        uint256 i;
        while (true) {
            if (i >= end) {
                revert MalformedName(name);
            }
            uint8 labelLength = uint8(name[i]);
            if (labelLength == 0) {
                i += 1;
                break;
            }
            if (labelLength > MAX_LABEL_LENGTH) {
                revert MalformedName(name);
            }
            i += 1 + uint256(labelLength);
            labels += 1;
        }
        if (i != end) {
            revert MalformedName(name);
        }
    }

    /// @notice Checks that `name` is well formed and in DNS canonical form.
    /// @dev DNS canonical order treats uppercase ASCII as lowercase, per RFC 4034 section 6.1.
    ///      `RRUtils.compareNames` compares raw bytes and does no case folding. The root zone
    ///      publishes lowercase names. A caller that supplies `COM.` would therefore sort it
    ///      into a different gap from `com.`, and could prove the absence of a name that is
    ///      live. This rejects the uppercase form instead of rewriting it, because the caller
    ///      and the predicate must agree on which exact name was proven.
    /// @param name The name to check, in wire format.
    /// @return labels The number of labels in the name.
    function requireCanonicalName(
        bytes memory name
    ) internal pure returns (uint256 labels) {
        labels = requireWireName(name);
        uint256 end = name.length;
        uint256 i;
        while (i < end) {
            uint8 labelLength = uint8(name[i]);
            if (labelLength == 0) {
                break;
            }
            for (uint256 j = i + 1; j <= i + uint256(labelLength); ++j) {
                uint8 c = uint8(name[j]);
                if (c >= 0x41 && c <= 0x5A) {
                    revert NonCanonicalName(name);
                }
            }
            i += 1 + uint256(labelLength);
        }
    }

    /// @notice The wildcard name directly below `zone`.
    /// @dev `*.` for the root. A complete denial of existence proof also denies the wildcard,
    ///      per RFC 4035 section 5.4. `RootAbsencePredicate` reports whether the supplied
    ///      records deny it.
    /// @param zone The zone name, in wire format.
    /// @return The wildcard name, in wire format.
    function wildcardName(
        bytes memory zone
    ) internal pure returns (bytes memory) {
        requireWireName(zone);
        return abi.encodePacked(hex"012a", zone);
    }
}
