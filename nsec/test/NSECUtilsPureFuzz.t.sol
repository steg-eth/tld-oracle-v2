// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {RRUtils} from "../src/contracts/dnssec-oracle/RRUtils.sol";
import {NSECUtils} from "../src/NSECUtils.sol";
import {RootAbsencePredicate} from "../src/RootAbsencePredicate.sol";
import {SyntheticChainBuilder} from "./SyntheticChainBuilder.sol";
import {DNSSEC} from "../src/contracts/dnssec-oracle/DNSSEC.sol";
import {DNSSECImpl} from "../src/contracts/dnssec-oracle/DNSSECImpl.sol";

/// The synthetic "NS bit clear" case, and fuzz coverage for the two pure functions that have
/// already produced bugs: the type-bitmap reader (`hasType`) and the wrap-aware comparator
/// (`coversName`). No forge-std is available in this project (see BUILD-BRIEF.md and
/// foundry.toml's `src = "empty"`), so inputs here are bounded by hand instead of `bound()`.
contract NSECUtilsPureFuzzTest is SyntheticChainBuilder {
    // ---------------------------------------------------------- required case: NS bit clear

    /// SYNTHETIC. There is no live root fixture for a TLD present in the zone with the NS bit
    /// clear, because the root only carries delegations (every TLD it lists has NS). This
    /// bitmap is hand-built: window 0, length 6, RRSIG(46) and NSEC(47) set, NS(2) clear.
    function test_Synthetic_NsBitClear_PureReaderDirect() external pure {
        bytes memory bitmap = hex"0006000000000003";
        require(!NSECUtils.hasType(bitmap, 0, NSECUtils.DNSTYPE_NS), "NS must read as clear");
        require(NSECUtils.hasType(bitmap, 0, NSECUtils.DNSTYPE_RRSIG), "sanity: RRSIG must read as set");
        require(NSECUtils.hasType(bitmap, 0, NSECUtils.DNSTYPE_NSEC), "sanity: NSEC must read as set");
    }

    /// Same bitmap through the predicate's own public wrapper, so the wrapper's offset handling
    /// (hasType(typeBitmap, dnstype) == NSECUtils.hasType(typeBitmap, 0, dnstype)) is covered too.
    function test_Synthetic_NsBitClear_ThroughPredicateWrapper() external {
        RootAbsencePredicate predicate = new RootAbsencePredicate(_dummyAnyOracle());
        bytes memory bitmap = hex"0006000000000003";
        require(!predicate.hasType(bitmap, NSECUtils.DNSTYPE_NS), "NS must read as clear");
        require(predicate.hasType(bitmap, NSECUtils.DNSTYPE_RRSIG), "sanity: RRSIG must read as set");
    }

    /// SYNTHETIC end-to-end. Same construction as PredicateGuards.t.sol's forged-signer case,
    /// but signed by the root itself (so the signer guard does not fire) and with the owner
    /// equal to the queried name (so the predicate reads the record's own bitmap instead of
    /// treating it as a covering record). Exercises route NoNsBit, which no real fixture can,
    /// since every TLD the live root lists carries NS.
    function test_Synthetic_NsBitClear_FullRouteThroughPredicate() external {
        bytes memory rootName = hex"00";
        bytes memory xxName = hex"02787800"; // xx.
        bytes memory yyName = hex"02797900"; // yy.

        (DNSSECImpl oracle, DNSSEC.RRSetWithSignature memory dnskeySet, uint16 keytag) = _zoneKeyChain(
            rootName,
            0
        );
        DNSSEC.RRSetWithSignature memory nsecSet = _nsecRecord(
            xxName,
            yyName,
            hex"0006000000000003", // NS clear, RRSIG+NSEC set
            rootName,
            1,
            keytag
        );
        DNSSEC.RRSetWithSignature[] memory chain = new DNSSEC.RRSetWithSignature[](2);
        chain[0] = dnskeySet;
        chain[1] = nsecSet;
        DNSSEC.RRSetWithSignature[][] memory proofs = new DNSSEC.RRSetWithSignature[][](1);
        proofs[0] = chain;

        RootAbsencePredicate predicate = new RootAbsencePredicate(oracle);
        vm.warp(SYNTH_AT);
        RootAbsencePredicate.Result memory result = predicate.proveNoDelegation(xxName, proofs);

        require(result.proven, "xx. must be proven absent via its own cleared NS bit");
        require(result.route == RootAbsencePredicate.Route.NoNsBit, "expected NoNsBit");
    }

    function _dummyAnyOracle() internal returns (DNSSECImpl oracle) {
        (oracle, , ) = _zoneKeyChain(hex"00", 0);
    }

    // ------------------------------------------------------------------- fuzz: hasType

    function _clampLength(uint8 raw) internal pure returns (uint8) {
        return uint8(1 + (uint256(raw) % 32));
    }

    /// An all-ones window block must report every type inside its range as present, for any
    /// window number, any valid length, and any bit position the fuzzer finds.
    function testFuzz_HasType_AllOnesWindowReportsEveryBitSet(
        uint8 window,
        uint8 lengthRaw,
        uint8 bitRaw
    ) external pure {
        uint8 length = _clampLength(lengthRaw);
        uint16 bit = uint16(uint256(bitRaw) % (uint256(length) * 8));

        bytes memory data = new bytes(uint256(length) + 2);
        data[0] = bytes1(window);
        data[1] = bytes1(length);
        for (uint256 i = 0; i < length; i++) {
            data[2 + i] = bytes1(uint8(0xFF));
        }

        uint16 dnstype = uint16(window) * 256 + bit;
        require(
            NSECUtils.hasType(data, 0, dnstype),
            "an all-ones window must report every in-range type as present"
        );
    }

    /// The exact complement: an all-zero window block must report every type inside its range
    /// as absent.
    function testFuzz_HasType_AllZeroWindowReportsEveryBitClear(
        uint8 window,
        uint8 lengthRaw,
        uint8 bitRaw
    ) external pure {
        uint8 length = _clampLength(lengthRaw);
        uint16 bit = uint16(uint256(bitRaw) % (uint256(length) * 8));

        bytes memory data = new bytes(uint256(length) + 2); // zero-initialized
        data[0] = bytes1(window);
        data[1] = bytes1(length);

        uint16 dnstype = uint16(window) * 256 + bit;
        require(
            !NSECUtils.hasType(data, 0, dnstype),
            "an all-zero window must report every in-range type as absent"
        );
    }

    /// Exact bit addressing. Sets exactly one bit and checks it reads back set, and that its
    /// immediate neighbours (when they exist) read back clear. Catches an off-by-one in either
    /// the byte index (bit >> 3) or the in-byte shift (7 - bit & 7), which is exactly the class
    /// of bug that silently flips which type a bit means.
    function testFuzz_HasType_ExactSingleBitAddressing(
        uint8 window,
        uint8 lengthRaw,
        uint8 bitRaw
    ) external pure {
        uint8 length = _clampLength(lengthRaw);
        uint256 totalBits = uint256(length) * 8;
        uint16 bit = uint16(uint256(bitRaw) % totalBits);

        bytes memory data = new bytes(uint256(length) + 2);
        data[0] = bytes1(window);
        data[1] = bytes1(length);
        uint8 byteIdx = uint8(bit / 8);
        uint8 bitInByte = uint8(bit % 8);
        data[2 + byteIdx] = bytes1(uint8(0x80) >> bitInByte);

        uint16 dnstype = uint16(window) * 256 + bit;
        require(NSECUtils.hasType(data, 0, dnstype), "the exact set bit must read as present");

        if (bit > 0) {
            require(
                !NSECUtils.hasType(data, 0, uint16(window) * 256 + (bit - 1)),
                "the bit before the set one must read as absent"
            );
        }
        if (bit + 1 < totalBits) {
            require(
                !NSECUtils.hasType(data, 0, uint16(window) * 256 + (bit + 1)),
                "the bit after the set one must read as absent"
            );
        }
    }

    // ----------------------------------------------------------------- fuzz: coversName

    function _singleLabelName(uint256 seed, uint8 lenRaw) internal pure returns (bytes memory) {
        uint8 len = uint8(1 + (uint256(lenRaw) % 20)); // 1..20 lowercase letters
        bytes memory label = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            label[i] = bytes1(uint8(97 + (uint256(keccak256(abi.encode(seed, i))) % 26)));
        }
        return abi.encodePacked(uint8(len), label, uint8(0));
    }

    /// Independent boundary property, not a restatement of the formula: a record never covers
    /// its own owner name or its own next-owner name, for any random owner/next pair.
    function testFuzz_CoversName_NeverCoversItsOwnEndpoints(
        uint256 ownerSeed,
        uint8 ownerLen,
        uint256 nextSeed,
        uint8 nextLen
    ) external pure {
        bytes memory owner = _singleLabelName(ownerSeed, ownerLen);
        bytes memory next = _singleLabelName(nextSeed, nextLen);
        require(
            !NSECUtils.coversName(owner, next, owner, NSECUtils.ROOT_NAME),
            "a record must not cover its own owner name"
        );
        require(
            !NSECUtils.coversName(owner, next, next, NSECUtils.ROOT_NAME),
            "a record must not cover its own next-owner name"
        );
    }

    /// Full-formula consistency check across random triples: whatever `coversName` returns must
    /// match the gap/apex definition stated in its own doc comment, assembled independently in
    /// this test from the `compareNames`/`equals` calls it is built from. Catches a flipped
    /// comparison operator or a swapped branch.
    ///
    /// G1 migration: the closing branch is now keyed on `next == zoneApex`, not on
    /// `next <= owner`. Pinned to the root here (`NSECUtils.ROOT_NAME`), which preserves this
    /// test's original intent -- the fuzzed single-label names this generates are never equal
    /// to the (zero-label) root, so `nextIsApex` is always false in this domain and the formula
    /// always falls through to the ordinary-gap half, exactly as the pre-G1 version did. The
    /// apex-closing branch itself is exercised separately, in Regressions.t.sol.
    function testFuzz_CoversName_MatchesGapOrWrapDefinition(
        uint256 ownerSeed,
        uint8 ownerLen,
        uint256 nextSeed,
        uint8 nextLen,
        uint256 nameSeed,
        uint8 nameLen
    ) external pure {
        bytes memory owner = _singleLabelName(ownerSeed, ownerLen);
        bytes memory next = _singleLabelName(nextSeed, nextLen);
        bytes memory name = _singleLabelName(nameSeed, nameLen);
        bytes memory apex = NSECUtils.ROOT_NAME;

        bool ownerBelowName = RRUtils.compareNames(owner, name) < 0;
        bool nextIsApex = keccak256(next) == keccak256(apex);
        bool ordinaryGapHolds = RRUtils.compareNames(name, next) < 0;

        bool expected = ownerBelowName &&
            (nextIsApex ? keccak256(owner) != keccak256(apex) : ordinaryGapHolds);
        bool actual = NSECUtils.coversName(owner, next, name, apex);
        require(expected == actual, "coversName diverged from the gap/apex definition");
    }

    /// A direct, forced-apex case: `next` is fixed to the root and the apex argument is the root
    /// too, so `next == zoneApex` always holds and the closing branch always fires; every name
    /// that sorts above `owner` must then be covered. This is the exact shape of the real
    /// zw./root closing record, fuzzed over random labels instead of the one fixture tested in
    /// the main suite. G1 migration: forcing the branch is now about matching the apex argument,
    /// not about `next`'s sort position relative to `owner` (which is why the old name,
    /// "ForcedWrap", undersells what's being forced after G1 -- kept as-is per "keep every
    /// test").
    function testFuzz_CoversName_ForcedWrapCoversEverythingAboveOwner(
        uint256 ownerSeed,
        uint8 ownerLen,
        uint256 nameSeed,
        uint8 nameLen
    ) external pure {
        bytes memory owner = _singleLabelName(ownerSeed, ownerLen);
        bytes memory name = _singleLabelName(nameSeed, nameLen);
        // The root itself always sorts at or below any single-label owner, forcing the wrap.
        bytes memory next = hex"00";

        bool covered = NSECUtils.coversName(owner, next, name, NSECUtils.ROOT_NAME);
        bool shouldCover = RRUtils.compareNames(owner, name) < 0;
        require(covered == shouldCover, "a forced-wrap record must cover exactly everything above its owner");
    }
}
