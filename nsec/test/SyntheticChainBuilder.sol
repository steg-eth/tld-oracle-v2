// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {DNSSEC} from "../src/contracts/dnssec-oracle/DNSSEC.sol";
import {DNSSECImpl} from "../src/contracts/dnssec-oracle/DNSSECImpl.sol";
import {RRUtils} from "../src/contracts/dnssec-oracle/RRUtils.sol";
import {DummyAlgorithm} from "../src/contracts/dnssec-oracle/algorithms/DummyAlgorithm.sol";
import {DummyDigest} from "../src/contracts/dnssec-oracle/digests/DummyDigest.sol";
import {Cheats} from "./Cheats.sol";

/// Not a test file. Builds fully synthetic DNSSEC chains for tests that must isolate
/// `RootAbsencePredicate`'s own logic from real RSA signatures.
///
/// `DummyAlgorithm.verify` and `DummyDigest.verify` always return true, so a chain built here
/// validates end to end through the real, unmodified `DNSSECImpl` based purely on field
/// consistency (owner names, keytag, class, type), with no real cryptography involved. That is
/// the point: it lets a test construct a chain the *oracle* fully accepts, so that when the
/// *predicate* still refuses it, the refusal is attributable to the predicate's own check and
/// not to a signature failure.
///
/// Every record produced here is marked synthetic in the reports of the tests that use it. None
/// of it is root-signed, and none of it says anything about what the real root has ever published.
abstract contract SyntheticChainBuilder is Cheats {
    uint8 internal constant DUMMY_ALGO_ID = 253;
    uint8 internal constant DUMMY_DIGEST_ID = 253;
    uint16 internal constant DNSTYPE_DNSKEY = 48;
    uint16 internal constant DNSTYPE_DS = 43;
    uint16 internal constant DNSTYPE_NSEC = 47;
    uint32 internal constant SYNTH_TTL = 3600;
    uint32 internal constant SYNTH_INCEPTION = 0;
    uint32 internal constant SYNTH_EXPIRATION = 2_000_000_000;
    uint256 internal constant SYNTH_AT = 1_700_000_000;

    /// One self-signed DNSKEY RRset owned by `zoneName`, verifiable against a DS of the same
    /// owner using a fresh oracle wired to the dummy algorithm and digest.
    function _zoneKeyChain(
        bytes memory zoneName,
        uint8 labels
    )
        internal
        returns (
            DNSSECImpl oracle,
            DNSSEC.RRSetWithSignature memory dnskeySet,
            uint16 keytag
        )
    {
        oracle = new DNSSECImpl(_anchorsFor(zoneName));
        oracle.setAlgorithm(DUMMY_ALGO_ID, new DummyAlgorithm());
        oracle.setDigest(DUMMY_DIGEST_ID, new DummyDigest());

        bytes memory keyrdata = abi.encodePacked(
            uint16(0x0100),
            uint8(3),
            uint8(DUMMY_ALGO_ID),
            hex"aa"
        );
        keytag = RRUtils.computeKeytag(keyrdata);

        bytes memory dnskeyRR = abi.encodePacked(
            zoneName,
            uint16(DNSTYPE_DNSKEY),
            uint16(1), // class IN
            SYNTH_TTL,
            uint16(keyrdata.length),
            keyrdata
        );
        bytes memory rrsigPrefix = abi.encodePacked(
            uint16(DNSTYPE_DNSKEY),
            uint8(DUMMY_ALGO_ID),
            labels,
            SYNTH_TTL,
            SYNTH_EXPIRATION,
            SYNTH_INCEPTION,
            keytag,
            zoneName
        );
        dnskeySet = DNSSEC.RRSetWithSignature(
            abi.encodePacked(rrsigPrefix, dnskeyRR),
            hex"00"
        );
    }

    /// The DS anchors for `zoneName`'s own synthetic key, with a keytag/algorithm that match
    /// whatever `_zoneKeyChain` for the same zone produces. Computed independently here so the
    /// anchors do not silently depend on the key-building order.
    function _anchorsFor(bytes memory zoneName) internal pure returns (bytes memory) {
        bytes memory keyrdata = abi.encodePacked(
            uint16(0x0100),
            uint8(3),
            uint8(DUMMY_ALGO_ID),
            hex"aa"
        );
        uint16 keytag = RRUtils.computeKeytag(keyrdata);
        bytes memory dsRdata = abi.encodePacked(
            keytag,
            uint8(DUMMY_ALGO_ID),
            uint8(DUMMY_DIGEST_ID),
            hex"bb" // "digest" -- arbitrary, DummyDigest never reads it
        );
        return
            abi.encodePacked(
                zoneName,
                uint16(DNSTYPE_DS),
                uint16(1),
                SYNTH_TTL,
                uint16(dsRdata.length),
                dsRdata
            );
    }

    /// One NSEC record owned by `owner`, next-owner `next`, bitmap `bitmap` (already window +
    /// length + data), signed by `signerName` using the keytag of whichever zone key is meant to
    /// cover it. The caller chooses `signerName` and `labels` independently of `owner`, which is
    /// exactly the degree of freedom a forged proof needs and a correct predicate must close off.
    function _nsecRecord(
        bytes memory owner,
        bytes memory next,
        bytes memory bitmap,
        bytes memory signerName,
        uint8 labels,
        uint16 keytag
    ) internal pure returns (DNSSEC.RRSetWithSignature memory nsecSet) {
        bytes memory rdata = abi.encodePacked(next, bitmap);
        bytes memory nsecRR = abi.encodePacked(
            owner,
            uint16(DNSTYPE_NSEC),
            uint16(1),
            SYNTH_TTL,
            uint16(rdata.length),
            rdata
        );
        bytes memory rrsigPrefix = abi.encodePacked(
            uint16(DNSTYPE_NSEC),
            uint8(DUMMY_ALGO_ID),
            labels,
            SYNTH_TTL,
            SYNTH_EXPIRATION,
            SYNTH_INCEPTION,
            keytag,
            signerName
        );
        nsecSet = DNSSEC.RRSetWithSignature(
            abi.encodePacked(rrsigPrefix, nsecRR),
            hex"00"
        );
    }

    /// Two NSEC records sharing one owner name and one signature (I25's shape): a single RRSIG
    /// prefix followed by two separate NSEC resource records, both owned by `owner`. DNS allows
    /// this (an RRset is every record sharing a name/type/class, and `DNSSECImpl.validateRRs`
    /// only requires that), but RFC 4035 section 2.3 says one owner name has exactly one NSEC
    /// record. The predicate's `ProofNotOneRecord` check closes the gap between what the wire
    /// format permits and what the protocol promises.
    function _twoNsecRecordsOneSignature(
        bytes memory owner,
        bytes memory next1,
        bytes memory bitmap1,
        bytes memory next2,
        bytes memory bitmap2,
        bytes memory signerName,
        uint8 labels,
        uint16 keytag
    ) internal pure returns (DNSSEC.RRSetWithSignature memory nsecSet) {
        bytes memory rdata1 = abi.encodePacked(next1, bitmap1);
        bytes memory rr1 = abi.encodePacked(
            owner,
            uint16(DNSTYPE_NSEC),
            uint16(1),
            SYNTH_TTL,
            uint16(rdata1.length),
            rdata1
        );
        bytes memory rdata2 = abi.encodePacked(next2, bitmap2);
        bytes memory rr2 = abi.encodePacked(
            owner,
            uint16(DNSTYPE_NSEC),
            uint16(1),
            SYNTH_TTL,
            uint16(rdata2.length),
            rdata2
        );
        bytes memory rrsigPrefix = abi.encodePacked(
            uint16(DNSTYPE_NSEC),
            uint8(DUMMY_ALGO_ID),
            labels,
            SYNTH_TTL,
            SYNTH_EXPIRATION,
            SYNTH_INCEPTION,
            keytag,
            signerName
        );
        nsecSet = DNSSEC.RRSetWithSignature(
            abi.encodePacked(rrsigPrefix, rr1, rr2),
            hex"00"
        );
    }
}
