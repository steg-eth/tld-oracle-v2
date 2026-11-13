// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {DNSSEC} from "src/contracts/dnssec-oracle/DNSSEC.sol";
import {DNSSECImpl} from "src/contracts/dnssec-oracle/DNSSECImpl.sol";
import {RRUtils} from "src/contracts/dnssec-oracle/RRUtils.sol";
import {RootAbsencePredicate} from "src/RootAbsencePredicate.sol";
import {NSECUtils} from "src/NSECUtils.sol";
import {Harness3} from "./Harness3.sol";
import {RootFixtures as F} from "../RootFixtures.sol";

/// @notice ROUND 3, inputs T31 to T36 and T38 to R40, R42. The new surface the fix created.
///         Root-signed material throughout, except where the input is about calldata shape and
///         carries no DNS data at all.
contract T5NewSurface is Harness3 {
    /// The signature strings of the entry points as round 1 measured them. The struct
    /// `DNSSEC.RRSetWithSignature { bytes rrset; bytes sig; }` is `(bytes,bytes)` in an ABI
    /// signature, and an array of arrays of it is `(bytes,bytes)[][]`.
    string internal constant SIG_PROVE_OLD =
        "proveNoDelegation(bytes,(bytes,bytes)[][],uint256)";
    string internal constant SIG_REQUIRE_OLD =
        "requireNoDelegation(bytes,(bytes,bytes)[][],uint256)";
    string internal constant SIG_PROVE_NEW = "proveNoDelegation(bytes,(bytes,bytes)[][])";
    string internal constant SIG_REQUIRE_NEW = "requireNoDelegation(bytes,(bytes,bytes)[][])";
    string internal constant SIG_PROVE_NOW = "proveNoDelegationNow(bytes,(bytes,bytes)[][])";
    string internal constant SIG_COVERS_IN_ZONE = "coversNameInZone(bytes,bytes,bytes,bytes)";

    function _sel(string memory sig) internal pure returns (bytes4) {
        return bytes4(keccak256(bytes(sig)));
    }

    /// @dev Labels in a wire-format name, counted here so that the assertion does not depend on
    ///      the library under audit.
    function _labels(bytes memory name) internal pure returns (uint256 n) {
        uint256 i;
        while (i < name.length) {
            uint8 l = uint8(name[i]);
            if (l == 0) break;
            n += 1;
            i += 1 + uint256(l);
        }
    }

    // ============================================= F1, closed by construction or not closed

    /// T31. The removed selectors must not be reachable, including by raw calldata.
    ///      Four things are measured.
    ///      1. The signature-string convention is correct, proved by the new selector matching
    ///         what the compiler produced. Without this the rest would prove nothing.
    ///      2. The two three-argument selectors differ from every selector the contract has.
    ///      3. A raw call carrying a three-argument selector and three-argument arguments
    ///         fails with empty return data, which is a dispatch miss and not a revert from
    ///         inside the contract.
    ///      4. There is no fallback and no receive, so an unknown selector cannot be absorbed.
    function test_T31_three_argument_selectors_are_unreachable() external {
        // 1. the convention
        require(
            _sel(SIG_PROVE_NEW) == RootAbsencePredicate.proveNoDelegation.selector,
            "signature-string convention is wrong, so the rest of this input proves nothing"
        );
        require(
            _sel(SIG_REQUIRE_NEW) == RootAbsencePredicate.requireNoDelegation.selector,
            "signature-string convention is wrong for requireNoDelegation"
        );
        require(
            _sel(SIG_COVERS_IN_ZONE) == RootAbsencePredicate.coversNameInZone.selector,
            "signature-string convention is wrong for coversNameInZone"
        );

        bytes4 proveOld = _sel(SIG_PROVE_OLD);
        bytes4 requireOld = _sel(SIG_REQUIRE_OLD);
        emit log_named_bytes32("T31 old proveNoDelegation/3 selector", bytes32(proveOld));
        emit log_named_bytes32("T31 old requireNoDelegation/3 selector", bytes32(requireOld));
        emit log_named_bytes32(
            "T31 new proveNoDelegation/2 selector",
            bytes32(RootAbsencePredicate.proveNoDelegation.selector)
        );

        // 2. the old selectors are not any of the contract's selectors
        bytes4 proveNowGone = _sel(SIG_PROVE_NOW);
        bytes4[8] memory live = [
            RootAbsencePredicate.proveNoDelegation.selector,
            RootAbsencePredicate.requireNoDelegation.selector,
            RootAbsencePredicate.coversName.selector,
            RootAbsencePredicate.coversNameInZone.selector,
            RootAbsencePredicate.hasType.selector,
            RootAbsencePredicate.rdataHasType.selector,
            RootAbsencePredicate.nextOwnerName.selector,
            _sel("oracle()")
        ];
        for (uint256 i; i < live.length; ++i) {
            require(live[i] != proveOld, "an old 3-arg selector collides with a live one");
            require(live[i] != requireOld, "an old 3-arg selector collides with a live one");
            require(live[i] != proveNowGone, "the removed proveNoDelegationNow collides");
            for (uint256 j = i + 1; j < live.length; ++j) {
                require(live[i] != live[j], "two live selectors collide");
            }
        }

        // 3. raw calldata with the old selector and the old argument tuple
        bytes memory oldArgs = abi.encode(
            F.N_DOOSAN,
            _one(F.DOMAINS_SET, F.DOMAINS_SIG),
            F.INSIDE
        );
        (bool ok, bytes memory ret) = address(predicate).staticcall(
            abi.encodePacked(proveOld, oldArgs)
        );
        require(!ok, "the old three-argument proveNoDelegation is still reachable");
        require(ret.length == 0, "the call reached code inside the contract");

        (ok, ret) = address(predicate).staticcall(abi.encodePacked(requireOld, oldArgs));
        require(!ok, "the old three-argument requireNoDelegation is still reachable");
        require(ret.length == 0, "the call reached code inside the contract");

        // 4. no fallback, no receive
        (ok, ret) = address(predicate).staticcall(hex"deadbeef");
        require(!ok && ret.length == 0, "an unknown selector was absorbed by a fallback");
        (ok, ret) = address(predicate).staticcall("");
        require(!ok && ret.length == 0, "an empty call was absorbed by a receive");

        emit log("T31 both three-argument selectors are dispatch misses with empty return data");
    }

    /// T32. The other direction. A caller that keeps the old three-argument encoding but uses
    ///      the NEW selector. The ABI decoder reads the two heads it wants and does not reject
    ///      the trailing word, so the call succeeds and the old time argument is ignored. That
    ///      is the safe direction: the argument is dropped, not reinterpreted as something
    ///      else. Measured, because the opposite would be a silent misread.
    function test_T32_new_selector_with_old_three_argument_calldata() external {
        bytes memory threeArgs = abi.encode(
            F.N_DOOSAN,
            _one(F.DOMAINS_SET, F.DOMAINS_SIG),
            uint256(1925000000) // a 2031 time, which round 1 would have honoured
        );
        (bool ok, bytes memory ret) = address(predicate).staticcall(
            abi.encodePacked(RootAbsencePredicate.proveNoDelegation.selector, threeArgs)
        );
        require(ok, "the new selector refused the old argument tuple");
        RootAbsencePredicate.Result memory r = abi.decode(ret, (RootAbsencePredicate.Result));
        _report("T32 new selector, old three-argument calldata, 2031 in the third word", r);
        _expect(r, true, RootAbsencePredicate.Route.NoName, 1);

        // identical to the two-argument call at the same block
        RootAbsencePredicate.Result memory clean = predicate.proveNoDelegation(
            F.N_DOOSAN,
            _one(F.DOMAINS_SET, F.DOMAINS_SIG)
        );
        require(
            keccak256(abi.encode(r)) == keccak256(abi.encode(clean)),
            "the trailing word changed the answer"
        );
        emit log("T32 the trailing time word is ignored, not read. The answer is the block's.");
    }

    /// T33. The whole dispatch table, printed, so that a stranger can diff it against round 1.
    function test_T33_selector_table() external {
        emit log_named_bytes32("oracle()", bytes32(_sel("oracle()")));
        emit log_named_bytes32(
            "proveNoDelegation(bytes,(bytes,bytes)[][])",
            bytes32(RootAbsencePredicate.proveNoDelegation.selector)
        );
        emit log_named_bytes32(
            "coversNameInZone(bytes,bytes,bytes,bytes)",
            bytes32(RootAbsencePredicate.coversNameInZone.selector)
        );
        emit log_named_bytes32(
            "requireNoDelegation(bytes,(bytes,bytes)[][])",
            bytes32(RootAbsencePredicate.requireNoDelegation.selector)
        );
        emit log_named_bytes32("coversName", bytes32(RootAbsencePredicate.coversName.selector));
        emit log_named_bytes32("hasType", bytes32(RootAbsencePredicate.hasType.selector));
        emit log_named_bytes32(
            "rdataHasType",
            bytes32(RootAbsencePredicate.rdataHasType.selector)
        );
        emit log_named_bytes32(
            "nextOwnerName",
            bytes32(RootAbsencePredicate.nextOwnerName.selector)
        );
        emit log_named_bytes32("removed proveNoDelegationNow", bytes32(_sel(SIG_PROVE_NOW)));
        emit log("T33 eight live selectors. proveNoDelegationNow is no longer one of them.");
    }

    // ================================================================= F2, the new guard

    /// T34. The `TimestampOutOfRange` boundary. The guard refuses when `block.timestamp` does
    ///      not fit in `uint32`, which is from 2106-02-07 06:28:16Z. One second earlier it
    ///      passes the guard and the proof is then refused on its own expiration, which is the
    ///      right reason. Root-signed proof in both halves.
    function test_T34_timestamp_guard_boundary() external {
        vm.warp(uint256(type(uint32).max) + 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                RootAbsencePredicate.TimestampOutOfRange.selector,
                uint256(type(uint32).max) + 1
            )
        );
        predicate.proveNoDelegation(F.N_DOOSAN, _one(F.DOMAINS_SET, F.DOMAINS_SIG));

        // One second below the boundary the guard passes and the oracle decides. The reason
        // it gives is not expiration. `RRUtils.serialNumberGte` does RFC 1982 arithmetic in
        // int32, and int32(4294967295) is -1, so a 2026 signature reads as not yet valid
        // rather than expired. That is a refusal either way. Measured, because the docstring
        // predicts the opposite reason.
        vm.warp(uint256(type(uint32).max));
        vm.expectRevert(
            abi.encodeWithSelector(
                DNSSECImpl.SignatureNotValidYet.selector,
                uint32(1794268800),
                type(uint32).max
            )
        );
        predicate.proveNoDelegation(F.N_DOOSAN, _one(F.DOMAINS_SET, F.DOMAINS_SIG));

        // The hazard the guard exists to stop, shown on the oracle, which still takes a time.
        // A value above 2^32 is narrowed by `DNSSECImpl.verifyRRSetAt` and aliases back into
        // the signature window, so the expired proof verifies. The predicate can no longer
        // reach this, because it never passes anything but `block.timestamp` and refuses
        // above 2^32.
        vm.warp(F.INSIDE);
        RRUtils.SignedSet[] memory sets = oracle.verifyRRSetAt(
            _proof(F.DOMAINS_SET, F.DOMAINS_SIG),
            F.INSIDE + 2 ** 32
        );
        require(sets.length == 2, "the oracle refused the aliased time");
        emit log("T34 the oracle still accepts an aliased time above 2^32. The guard is why");
        emit log("T34 the predicate cannot. The guard is load-bearing, not decoration.");
    }

    /// T35. Where the guard sits in the order. At a post-2106 block it fires before the name
    ///      check and before the proof loop, so a caller sees the clock and not a second,
    ///      unrelated complaint. No DNS data is needed for two of the three halves.
    function test_T35_timestamp_guard_fires_first() external {
        vm.warp(uint256(type(uint32).max) + 1);
        uint256 t = uint256(type(uint32).max) + 1;

        // an empty proof array, which at a normal block returns Unproven rather than reverting
        DNSSEC.RRSetWithSignature[][] memory none = new DNSSEC.RRSetWithSignature[][](0);
        vm.expectRevert(
            abi.encodeWithSelector(RootAbsencePredicate.TimestampOutOfRange.selector, t)
        );
        predicate.proveNoDelegation(F.N_DOOSAN, none);

        // a malformed name, which at a normal block gives NonCanonicalName
        vm.expectRevert(
            abi.encodeWithSelector(RootAbsencePredicate.TimestampOutOfRange.selector, t)
        );
        predicate.proveNoDelegation(F.N_COM_UPPER, none);

        // and through the two other entry points
        vm.expectRevert(
            abi.encodeWithSelector(RootAbsencePredicate.TimestampOutOfRange.selector, t)
        );
        predicate.requireNoDelegation(F.N_DOOSAN, none);
        emit log("T35 the clock guard is first, on both surviving entry points");
    }

    /// T36. The liveness control for `RecordNameTooDeep`. Every NSEC record the root publishes
    ///      must pass the depth check. The four root-signed fixtures are the two edge shapes
    ///      and two ordinary ones: a zero-label owner, a zero-label next-owner, and two records
    ///      with one label on both sides. Their label counts are counted here without using the
    ///      library under audit. `output/root-depth-survey.log` extends this to all 1437
    ///      records in the published root zone.
    function test_T36_depth_check_passes_every_real_record_shape() external {
        // the apex record: owner `.` has zero labels, next `aaa.` has one
        require(_labels(F.N_ROOT) == 0, "the root must have zero labels");
        require(_labels(F.N_AAA) == 1, "aaa. must have one label");
        // the closing record: owner `zw.` has one label, next `.` has zero
        require(_labels(F.N_ZW) == 1 && _labels(F.N_ROOT) == 0, "zw. NSEC . shape");
        // the ordinary gaps
        require(_labels(F.N_DOMAINS) == 1 && _labels(F.N_DOT) == 1, "domains. NSEC dot. shape");
        require(_labels(F.N_AQ) == 1, "aq. has one label");

        // and each one reaches a verdict rather than a revert, through the real oracle
        predicate.proveNoDelegation(F.N_AA, _one(F.ROOT_SET, F.ROOT_SIG)); // 0-label owner
        predicate.proveNoDelegation(F.N_ZZZZZZZZ, _one(F.ZW_SET, F.ZW_SIG)); // 0-label next
        predicate.proveNoDelegation(F.N_DOOSAN, _one(F.DOMAINS_SET, F.DOMAINS_SIG));
        predicate.proveNoDelegation(hex"0461717561" hex"00", _one(F.AQ_SET, F.AQ_SIG));
        emit log("T36 all four real record shapes pass the depth check and reach a verdict");
    }

    /// T38. Can `ProofNotOneRecord` fire on root-signed material? The RRSIG covers the
    ///      de-duplicated canonical RRset, per RFC 4034 section 6.3, so adding a second copy of
    ///      the record changes the signed bytes. The oracle refuses before the counter is read.
    ///      Root-signed material with the record duplicated.
    function test_T38_one_record_check_is_unreachable_from_the_real_root() external {
        bytes memory header = hex"002f0801000151806b0519d06af3e840223b00";
        bytes memory rr = hex"07646f6d61696e7300002f000100015180000d03646f74000006200000000013";
        require(
            keccak256(abi.encodePacked(header, rr)) == keccak256(F.DOMAINS_SET),
            "the split of DOMAINS_SET into header and record is wrong"
        );
        bytes memory doubled = abi.encodePacked(header, rr, rr);

        vm.expectRevert(
            abi.encodeWithSelector(DNSSECImpl.NoMatchingProof.selector, hex"00")
        );
        predicate.proveNoDelegation(F.N_DOOSAN, _one(doubled, F.DOMAINS_SIG));
        emit log("T38 the signature path refuses a duplicated record before the count is read");
    }

    /// T39. One unusable proof in the array destroys a proof that is good. Proof 0 is the
    ///      genuine covering record for `.doosan`. Proof 1 is the root DNSKEY set, which is
    ///      root-signed and valid but is not NSEC. The whole call reverts, and the absence that
    ///      proof 0 proves is not reported. The same array without proof 1 proves it.
    ///      Root-signed throughout.
    function test_T39_one_bad_proof_in_the_array_kills_a_good_one() external {
        RootAbsencePredicate.Result memory good = predicate.proveNoDelegation(
            F.N_DOOSAN,
            _one(F.DOMAINS_SET, F.DOMAINS_SIG)
        );
        _expect(good, true, RootAbsencePredicate.Route.NoName, 1);

        DNSSEC.RRSetWithSignature[][] memory poisoned = new DNSSEC.RRSetWithSignature[][](2);
        poisoned[0] = _proof(F.DOMAINS_SET, F.DOMAINS_SIG);
        DNSSEC.RRSetWithSignature[] memory keyOnly = new DNSSEC.RRSetWithSignature[](1);
        keyOnly[0] = DNSSEC.RRSetWithSignature(F.DNSKEY_SET, F.DNSKEY_SIG);
        poisoned[1] = keyOnly;

        vm.expectRevert(
            abi.encodeWithSelector(
                RootAbsencePredicate.ProofNotNSEC.selector,
                uint256(1),
                uint16(48)
            )
        );
        predicate.proveNoDelegation(F.N_DOOSAN, poisoned);
        emit log("T39 proof 0 proves absence, proof 1 reverts the call, nothing is reported");
    }

    /// T40. The order the checks fire in, written down. Each case violates two things at once.
    ///      Root-signed where DNS data is needed.
    function test_T40_check_precedence() external {
        // the clock beats the name
        vm.warp(uint256(type(uint32).max) + 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                RootAbsencePredicate.TimestampOutOfRange.selector,
                uint256(type(uint32).max) + 1
            )
        );
        predicate.proveNoDelegation(F.N_COM_UPPER, _one(F.ZW_SET, F.ZW_SIG));
        vm.warp(F.INSIDE);

        // the name beats the empty chain
        DNSSEC.RRSetWithSignature[][] memory oneEmpty = new DNSSEC.RRSetWithSignature[][](1);
        oneEmpty[0] = new DNSSEC.RRSetWithSignature[](0);
        vm.expectRevert(
            abi.encodeWithSelector(NSECUtils.NonCanonicalName.selector, F.N_COM_UPPER)
        );
        predicate.proveNoDelegation(F.N_COM_UPPER, oneEmpty);

        // the empty chain beats the oracle
        vm.expectRevert(
            abi.encodeWithSelector(RootAbsencePredicate.EmptyProof.selector, uint256(0))
        );
        predicate.proveNoDelegation(F.N_DOOSAN, oneEmpty);

        // the oracle beats every check this contract makes on the record
        vm.expectRevert(
            abi.encodeWithSelector(DNSSECImpl.NoMatchingProof.selector, hex"00")
        );
        predicate.proveNoDelegation(F.N_DOT, _one(F.CORRUPT_SET, F.DOMAINS_SIG));

        emit log("T40 order: clock, name, empty chain, oracle, set type, signer, record, count");
    }

    /// T42. `proveNoDelegationNow` is REMOVED. Round 2 measured it as a second selector for
    ///      one behaviour, with a docstring describing the parameter that had already gone.
    ///      It is now absent from the dispatch table. Calldata written against round 1 or
    ///      round 2 for that name, which worked in both rounds, is now a dispatch miss.
    ///      This is a breaking change for an integrator who used it, and it is the third
    ///      selector removed across the three rounds.
    function test_T42_prove_now_is_removed() external {
        bytes4 gone = _sel(SIG_PROVE_NOW);
        bytes memory args = abi.encode(F.N_DOOSAN, _one(F.DOMAINS_SET, F.DOMAINS_SIG));
        (bool ok, bytes memory ret) = address(predicate).staticcall(
            abi.encodePacked(gone, args)
        );
        require(!ok, "proveNoDelegationNow is still reachable");
        require(ret.length == 0, "the call reached code inside the contract");

        // The two-argument calldata it used is valid for proveNoDelegation, so the migration
        // for a caller is a selector change and nothing else.
        (ok, ret) = address(predicate).staticcall(
            abi.encodePacked(RootAbsencePredicate.proveNoDelegation.selector, args)
        );
        require(ok, "the same arguments must work on proveNoDelegation");
        RootAbsencePredicate.Result memory r = abi.decode(ret, (RootAbsencePredicate.Result));
        _expect(r, true, RootAbsencePredicate.Route.NoName, 1);
        emit log_named_bytes32("T42 removed selector", bytes32(gone));
        emit log("T42 a dispatch miss now. The same arguments work on proveNoDelegation.");
    }

    /// T46. `records` now counts DISTINCT records, by keccak256 over the bytes the oracle
    ///      authenticated. Round 2 measured the same record sent twice as `records = 2`.
    ///      **This outcome changed.** The genuine pair still counts two. Root-signed.
    function test_T46_records_counts_distinct_records() external {
        RootAbsencePredicate.Result memory twice = predicate.proveNoDelegation(
            F.N_DOOSAN,
            _two(F.DOMAINS_SET, F.DOMAINS_SIG, F.DOMAINS_SET, F.DOMAINS_SIG)
        );
        _report("T46 the covering record supplied twice", twice);
        _expect(twice, true, RootAbsencePredicate.Route.NoName, 1);
        require(!twice.apexWildcardDenied, "one record twice cannot deny the apex wildcard");

        RootAbsencePredicate.Result memory real = predicate.proveNoDelegation(
            F.N_DOOSAN,
            _two(F.DOMAINS_SET, F.DOMAINS_SIG, F.ROOT_SET, F.ROOT_SIG)
        );
        _report("T46 the genuine pair", real);
        _expect(real, true, RootAbsencePredicate.Route.NoName, 2);
        require(real.apexWildcardDenied, "the genuine pair denies the apex wildcard");

        // Three proofs, two of them the same record.
        DNSSEC.RRSetWithSignature[][] memory three = new DNSSEC.RRSetWithSignature[][](3);
        three[0] = _proof(F.DOMAINS_SET, F.DOMAINS_SIG);
        three[1] = _proof(F.ROOT_SET, F.ROOT_SIG);
        three[2] = _proof(F.DOMAINS_SET, F.DOMAINS_SIG);
        RootAbsencePredicate.Result memory mixed = predicate.proveNoDelegation(F.N_DOOSAN, three);
        _report("T46 three proofs, two of them the same record", mixed);
        _expect(mixed, true, RootAbsencePredicate.Route.NoName, 2);
        emit log("T46 CHANGED from round 2. records is now a count of distinct records.");
    }
}
