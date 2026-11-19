//SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {DNSSEC} from "./contracts/dnssec-oracle/DNSSEC.sol";
import {RRUtils} from "./contracts/dnssec-oracle/RRUtils.sol";
import {BytesUtils} from "./contracts/utils/BytesUtils.sol";
import {NSECUtils} from "./NSECUtils.sol";
import {NSEC3Utils} from "./NSEC3Utils.sol";

/// @title ApexAbsencePredicate
/// @notice Reads NSEC3 records signed by a top-level domain's own zone and reports whether that
///         zone publishes a TXT record at one named label below its apex, which for this project
///         is `_ens.<tld>`.
/// @dev The sibling of `RootAbsencePredicate`, and the reason the two are separate contracts.
///      `RootAbsencePredicate` asks the DNS root whether it still delegates a name. This asks
///      the delegated zone itself whether the commitment inside it is gone. **The two cases this
///      exists for keep the TLD delegated in the root**, so the root predicate never fires on
///      them: an EBERO transition, where the registry operator is replaced and the zone keeps
///      being served, and an abandoned handover, where the operator stops maintaining the
///      commitment and the delegation stays. See `survey/ISSUE-8-SCOPE-2026-11-19.md`.
///
///      NSEC3 is not optional here. The census of 19 November 2026 counted NSEC3 in 1,308 of the
///      1,436 names in the root, and in all seven EBERO names. An NSEC-only predicate reaches
///      none of the cases this contract exists for.
///
///      Absence has two forms, and both mean the commitment is gone.
///
///      1. NXDOMAIN. The name is not in the zone at all. One NSEC3 record covers the hash of
///         the name, per RFC 5155 section 8.4.
///      2. NODATA. The name is in the zone, and its own type bitmap does not list TXT, per
///         RFC 5155 section 8.5. An empty bitmap is legal in NSEC3 and is this form: see the
///         note on `NSEC3Utils.rdataHasType`.
///
///      **Three checks in `RootAbsencePredicate` are wrong here, and each would revert on every
///      NSEC3 call.** They are the reason this is a separate contract and not a flag.
///
///      1. That contract requires the signed set to cover type NSEC, 47. This one requires
///         NSEC3, 50.
///      2. That contract requires the RRSIG signer name to be the root. Here the root is the
///         wrong signer, because the root does not sign the inside of a delegated zone. The
///         signer must be the top-level zone itself, and the zone is derived from the name
///         being proven rather than taken from the caller. Measured on the captured fixtures:
///         the signer name of each NSEC3 set is `desi.`, `firmdale.` or `nowruz.`.
///      3. That contract requires the queried name to be exactly one label below the root.
///         `_ens.<tld>` is two labels. This one requires exactly two, and requires the second
///         to be the zone that signed the proof.
///
///      This contract holds no state and no roles. The oracle address is immutable. It reads
///      and reports. The authority to act on the report belongs to the consumer.
///
///      **Time.** Every entry point validates the signatures at `block.timestamp`. No entry
///      point takes a time from the caller. This is `RootAbsencePredicate`'s F1 fix, and the
///      reasoning carries over without change: a release decision acts now, so the only sound
///      validation time is now. An earlier revision of the root predicate took an `at`
///      parameter and passed it straight to the oracle, which let a caller present a captured
///      proof at a much later block and get `proven` for a name whose zone had published the
///      record again in the years between. The parameter is gone, not bounded, because its only
///      sound value was `block.timestamp`. For an answer as of an earlier time, call at an
///      earlier block, where the chain supplies the time. A test sets the time with `vm.warp`,
///      which exercises the same path a consumer uses.
///
///      **Strictness.** A malformed record reverts with a named error. It never returns
///      "absent". A false positive releases a live top-level domain, so a misread byte must
///      stop the call rather than answer it. The one place the readers are deliberately lenient
///      is the empty NSEC3 type bitmap, which is legal and which reports every type absent:
///      `NSEC3Utils.rdataHasType` carries that note, and this contract does not undo it.
///
///      The ENS DNSSEC oracle is unchanged. `DNSSECImpl` authenticates an NSEC3 RRset today,
///      and `test/NSEC3FixtureCheck.t.sol` measures three captured four-link chains through an
///      unmodified copy of it. Needing no upstream change is the point of this.
///
///      Cost, measured with `gasleft()` against an already deployed oracle, on the captured
///      fixtures of 19 November 2026. `ApexAbsenceGasTest` in
///      `test/ApexAbsencePredicate.t.sol` reproduces the table.
///
///      | call | gas | of which the oracle |
///      | --- | --- | --- |
///      | `requireAbsence`, 1 proof, `desi`, 0 iterations | 658,925 | 467,683 |
///      | `requireAbsence`, 1 proof, `firmdale`, 20 iterations | 2,936,926 | 847,718 |
///      | `requireAbsence`, 3 proofs, `desi`, the complete denial | 1,637,498 | 1,403,049 |
///
///      **A four-link chain is most of the bill at the counts that exist.** The root predicate
///      reads a two-link, root-signed chain for 281k; a chain into a delegated zone adds the
///      zone's DS and DNSKEY, and `firmdale` signs with a 4096-bit key, which is why its
///      oracle column is almost twice `desi`'s. The rest of `firmdale`'s number is `SHA1.sol`:
///      three hashed names at 20 iterations, which is about 2.02M. The three-proof row is the
///      per-parameter cache working: three oracle verifications plus **one** set of three
///      hashes, not three. Deployment is 2.01M.
contract ApexAbsencePredicate {
    using RRUtils for *;
    using BytesUtils for bytes;

    /// @notice How the question was answered.
    /// @dev `Unproven` means that no supplied record decides the question.
    ///      `NoName` means that a record denies that the name exists in the zone at all, which
    ///      is the NXDOMAIN form of RFC 5155 section 8.4.
    ///      `NoTxtBit` means that a record matches the name, and that record's own type bitmap
    ///      has no TXT, which is the NODATA form of RFC 5155 section 8.5.
    ///      `Present` means that a record matches the name and lists TXT, so the zone still
    ///      publishes the commitment. `Present` outranks the other outcomes and cannot be
    ///      overturned by another record in the same call.
    enum Route {
        Unproven,
        NoName,
        NoTxtBit,
        Present
    }

    /// @notice The result of reading the supplied proofs.
    /// @param proven True only for `NoName` and `NoTxtBit`.
    /// @param route How the question was answered.
    /// @param owner The owner name of the record that decided it, in wire format. That name is
    ///        the base32hex hash label followed by the zone.
    /// @param ownerHash The decoded owner hash of the record that decided it.
    /// @param nextHash The next-hashed-owner field of the record that decided it.
    /// @param nameHash The hash of the queried name, under the deciding record's own salt and
    ///        iteration count. A consumer that stores a release can record this.
    /// @param inception The RRSIG inception of the record that decided it. A consumer that
    ///        stores a release can use this to refuse an older proof later.
    /// @param optOut True if the deciding record sets the Opt-Out flag. Reported, never
    ///        required and never refused. Opt-Out narrows a span to "no signed delegation
    ///        exists in it", per RFC 5155 section 6, and the name asked about here is a TXT
    ///        name and never a delegation, so the span still proves it absent. Six of the seven
    ///        EBERO zones set this bit. See `NSEC3Utils.readRdata`.
    /// @param apexMatched True if a supplied record matches the zone apex, which is the closest
    ///        encloser of a name one label below it. Reported, not required. See `proveAbsence`.
    /// @param wildcardDenied True if a supplied record covers the wildcard `*.<tld>`. Reported,
    ///        not required. See `proveAbsence`.
    /// @param records The number of distinct NSEC3 records read. A record sent twice counts
    ///        once. Records are compared by the bytes the oracle authenticated.
    struct Result {
        bool proven;
        Route route;
        bytes owner;
        bytes20 ownerHash;
        bytes20 nextHash;
        bytes20 nameHash;
        uint32 inception;
        bool optOut;
        bool apexMatched;
        bool wildcardDenied;
        uint256 records;
    }

    /// @dev One question, and the hashes that answer it, carried through the read.
    ///
    ///      **The three hashes are the cache described on `proveAbsence`, and `key` is what
    ///      makes it safe.** The salt and the iteration count belong to each record and are
    ///      never assumed, so a hash computed under one record's parameters must never be
    ///      reused for a record that declares different ones. `_hashUnder` recomputes all three
    ///      whenever `key` changes. Grouping them in one struct is also what keeps
    ///      `proveAbsence` inside the stack limit under `via_ir`.
    /// @param name The queried name, in wire format.
    /// @param zone The zone derived from it, which every proof must be signed by.
    /// @param wildcard The wildcard directly below that zone.
    /// @param cached True once the three hashes below hold values.
    /// @param key `keccak256(abi.encode(iterations, salt))` of the record they were computed
    ///        under. `abi.encode` is length-prefixed, so a short salt cannot collide with a
    ///        long one.
    /// @param nameHash The hash of `name` under those parameters.
    /// @param wildcardHash The hash of `wildcard` under those parameters.
    /// @param apexHash The hash of `zone` under those parameters.
    struct Query {
        bytes name;
        bytes zone;
        bytes wildcard;
        bool cached;
        bytes32 key;
        bytes20 nameHash;
        bytes20 wildcardHash;
        bytes20 apexHash;
    }

    uint16 internal constant CLASS_INET = 1;

    /// @dev The queried name is one label below the zone apex, so it has exactly two labels: the
    ///      label, and the top-level zone that signs the proof. `RootAbsencePredicate` requires
    ///      one label, because the root signs for its own children. Here the signer is the
    ///      top-level zone, and a one-label query would be the zone apex itself, which no zone
    ///      proves absent from itself.
    uint256 internal constant QUERIED_NAME_LABELS = 2;

    /// @dev An NSEC3 owner name is the base32hex hash prepended as a single label to the zone
    ///      name, per RFC 5155 section 3, so it has exactly two labels in a top-level zone. The
    ///      hash label is 32 characters, which with its length byte puts the zone at byte 33 of
    ///      the owner name. `NSEC3Utils.ownerHash` is what holds the label to 32 characters.
    uint256 internal constant OWNER_ZONE_OFFSET = 33;

    /// @dev The label this project reads. The predicate does **not** pin the queried name's
    ///      first label to it: the comparison is over whatever name the caller passes, the
    ///      result reports the hash of that exact name, and a consumer that cares about
    ///      `_ens.<tld>` builds the name with `ensName`. Pinning it here would buy nothing,
    ///      because the consumer already chooses the name it acts on, and it would stop the
    ///      contract being reused for another label under the same two-label shape.
    ///
    ///      The convention itself is five years old in ENS: `DNSClaimChecker.getOwnerAddress`
    ///      has prepended `_ens` since 1 June 2021. Its extension to a bare top-level domain
    ///      arrived with ens-contracts #419 on 22 August 2026.
    bytes internal constant ENS_LABEL = hex"045f656e73";

    /// @dev The iteration ceiling this contract accepts, which is **lower than the library's**.
    ///      `NSEC3Utils.MAX_ITERATIONS` is 150 and this is 20. The two numbers disagree on
    ///      purpose. Do not make them agree.
    ///
    ///      The library is a reader and has to stay reusable, so its cap is headroom: a zone
    ///      that rezones to a higher count must not become unreadable, and 150 bounds the gas
    ///      of one hash without making a judgement about who pays for it. This contract is a
    ///      permissionless entry point, so it is the place where the bill is decided, and it
    ///      refuses a count it would not want to pay for.
    ///
    ///      **Measured in pass 1 with `gasleft()` around `NSEC3Utils.hashName`, 19 November
    ///      2026.** `SHA1.sol` is pure EVM at about 31,810 gas for each hash, so one hashed
    ///      name costs about 37,000 gas at zero iterations, 674,000 at 20, and 4,809,000 at
    ///      150. A denial hashes up to three names: the queried name, the wildcard, and the
    ///      zone apex. At the library's cap that is on the order of 15,000,000 gas for one
    ///      call, on a path anyone can call. At 20 it is about 2,000,000, and the
    ///      per-parameter cache in `proveAbsence` holds it at that figure however many records
    ///      the proof carries.
    ///
    ///      **20 is also the highest count that exists.** The census of 19 November 2026 read
    ///      all 1,308 NSEC3 zones in the root: 1,222 publish zero iterations, and the highest
    ///      value anywhere is 20, which is `firmdale`. RFC 9276 asks signers to use zero. So
    ///      the cap costs no liveness today, and a zone that rezones above it becomes
    ///      unprovable **here** while staying readable by the library. Unprovable refuses a
    ///      release. It does not grant one.
    uint256 internal constant MAX_ITERATIONS = 20;

    /// @notice The DNSSEC oracle. Mainnet `0x668ad4467129d49ECbe6274d95197797C0E262AA` already
    ///         has algorithm 8, digests 1 and 2, and the current root trust anchors, which is
    ///         what a four-link chain into a top-level zone needs. No redeploy.
    /// @dev 32 top-level domains sign with algorithm 10, 14 or 15, which this oracle does not
    ///      support, and 86 more are unsigned. Those zones cannot be read by any path that
    ///      reads a top-level domain's own zone, the admission claim included. This contract
    ///      does not pretend to cover them: their proofs fail inside the oracle.
    DNSSEC public immutable oracle;

    /// @dev The oracle address is zero.
    error OracleRequired();

    /// @dev Proof `index` holds no signed sets. An empty chain must not reach the oracle.
    ///      `DNSSEC.verifyRRSet` answers an empty chain with the trust anchors themselves,
    ///      which are DS records, and a caller that iterated that answer would be reading
    ///      unsigned configuration as if it were a proof.
    error EmptyProof(uint256 index);

    /// @dev The last signed set in proof `index` does not cover type NSEC3.
    ///      **This is the first of the three changed checks.** `RootAbsencePredicate` requires
    ///      type 47. An NSEC3 record is type 50, and the two rdata formats share no fields:
    ///      reading one as the other would read a hash algorithm byte as the first length byte
    ///      of a name.
    error ProofNotNSEC3(uint256 index, uint16 dnstype);

    /// @dev Class is not IN.
    error ProofNotClassINET(uint256 index, uint16 class);

    /// @dev The RRSIG signer name of proof `index` is not the zone derived from the queried
    ///      name. **This is the second of the three changed checks**, and it is the inverse of
    ///      `RootAbsencePredicate.ProofNotFromRoot`.
    ///
    ///      Only the zone itself can answer for the names inside it. The root signs the
    ///      delegation and never the inside of the delegated zone, so a root-signed set is the
    ///      wrong answer to this question and is refused here. Another zone's NSEC3 chain is
    ///      hashed with that zone's own salt and iteration count over that zone's own names, so
    ///      one of its records would otherwise appear to cover a hash in this one.
    ///
    ///      The zone is derived from the name being proven, not supplied. A caller that could
    ///      name the zone could name a zone it controls, sign a chain in it, and have a hash
    ///      from that chain read as an answer about the target zone.
    error ProofNotFromZone(uint256 index, bytes signerName, bytes zone);

    /// @dev The queried name is not exactly one label below a top-level zone. **This is the
    ///      third of the three changed checks.** `RootAbsencePredicate` requires one label,
    ///      because it reads the root's own chain; `_ens.<tld>` is two.
    ///
    ///      Two is both a floor and a ceiling. A one-label name is a top-level domain, and a
    ///      zone does not deny its own apex. A three-label name such as `a._ens.<tld>` is still
    ///      inside the zone and would read correctly, but it is not the question this contract
    ///      answers, and allowing it would let a caller prove absence for a name the consumer
    ///      never asked about while the two-label commitment is live. The depth rule lives here
    ///      rather than in `NSEC3Utils`, exactly as the root predicate's does, because it is a
    ///      rule about what this predicate is for and not about the comparison.
    error NotATopLevelChildName(bytes name);

    /// @dev The owner name of a record in proof `index` is not a base32hex hash label directly
    ///      below the zone that signed it. An NSEC3 owner name is the hash prepended as one
    ///      label to the zone apex, per RFC 5155 section 3, so `<hash>.<zone>.` is the only
    ///      shape that can come from this zone's chain. A deeper owner name would belong to a
    ///      chain hashed over a different zone's names, and its span is not a span of hashes in
    ///      this zone. This is the NSEC3 form of `RootAbsencePredicate.RecordNameTooDeep`.
    error ProofOwnerNotInZone(uint256 index, bytes owner, bytes zone);

    /// @dev Proof `index` does not hold exactly one NSEC3 record. RFC 5155 section 7.1 adds one
    ///      NSEC3 RR for each hashed owner name in the zone, and the oracle holds every record
    ///      in one set to one owner name, so two records under one signature would share an
    ///      owner hash and could carry different next-hashed-owner fields. The second could
    ///      then widen the span of the first. Measured: each of the six captured fixture sets
    ///      holds exactly one record, and a denial of up to three records arrives as up to
    ///      three separately signed sets, so the check costs no liveness.
    error ProofNotOneRecord(uint256 index, uint256 records);

    /// @dev A record in proof `index` declares more iterations than this contract accepts. See
    ///      `MAX_ITERATIONS`, and note that the number is deliberately lower than the
    ///      library's.
    error IterationCountAboveCap(uint256 index, uint256 iterations, uint256 cap);

    /// @dev `block.timestamp` does not fit in the `uint32` that the oracle compares against.
    ///      `DNSSECImpl.verifyRRSetAt` narrows its time argument to `uint32`, so a block time
    ///      above that range aliases: `t + 2**32` narrows to `t`, and a November 2026 proof
    ///      would verify at a block in 2106 or later. Refuse instead of aliasing.
    ///
    ///      Inside the `uint32` range the narrowing is the identity, so the guard belongs at
    ///      `2**32` and not lower. The note on `RootAbsencePredicate.TimestampOutOfRange`
    ///      records what the oracle does above `2**31`, which is RFC 1982 serial arithmetic in
    ///      `int32` and is the oracle's behaviour rather than this contract's.
    error TimestampOutOfRange(uint256 timestamp);

    /// @dev `requireAbsence` found no proof of absence.
    error AbsenceNotProven(bytes name, Route route);

    /// @param _oracle The DNSSEC oracle to verify against.
    constructor(DNSSEC _oracle) {
        if (address(_oracle) == address(0)) {
            revert OracleRequired();
        }
        oracle = _oracle;
    }

    // ----------------------------------------------------------------------- the entry point

    /// @notice Reads an array of independent NSEC3 proofs signed by a top-level zone, and
    ///         reports whether that zone publishes a TXT record at `name`.
    /// @dev Each element of `proofs` is a complete chain from the trust anchors to one NSEC3
    ///      record, which inside a delegated zone is four links: root DNSKEY, the zone's DS,
    ///      the zone's DNSKEY, the NSEC3 set. Each chain gets its own oracle verification. Two
    ///      NSEC3 records never share one chain, because `verifyRRSetAt` folds its input and
    ///      verifies each set against the set before it, so an NSEC3 set cannot act as the
    ///      proof for the set that follows it.
    ///
    ///      **The record count is not fixed.** RFC 5155 sections 8.4 and 8.5 allow up to three
    ///      records in a denial: one matching the closest encloser, one covering the queried
    ///      name, one covering the wildcard. One record can hold more than one of those roles.
    ///      The three captured zones return three, one and two, and a reader that assumes a
    ///      count is wrong. `firmdale` publishes exactly one NSEC3 record, because Opt-Out
    ///      hides every delegation in the zone, and that record points at itself and so answers
    ///      all three obligations alone.
    ///
    ///      The queried name must be exactly two labels, and the second label must be the zone
    ///      whose RRSIG signed each proof. Each record's owner name is held to
    ///      `<hash>.<zone>.`, and each proof must hold exactly one NSEC3 record. None of the
    ///      refused shapes can come from the zone's own chain, and all of them are refused
    ///      rather than ignored, so that an input the zone cannot have produced fails where it
    ///      is read.
    ///
    ///      A record that neither matches nor covers the name is read and ignored. It is not an
    ///      error, because a denial carries records that answer the other two obligations.
    ///
    ///      `apexMatched` and `wildcardDenied` are reported and neither is required for
    ///      `proven`, exactly as `RootAbsencePredicate` reports the apex wildcard. RFC 5155
    ///      section 8.4 asks a complete NXDOMAIN proof for all three records, and RFC 4035
    ///      section 5.4 is the same requirement for NSEC. A consumer that wants the complete
    ///      form can require both flags.
    ///
    ///      **Why a live wildcard cannot defeat the answer.** If `*.<tld>` carried a TXT set, a
    ///      resolver would synthesize an answer for `_ens.<tld>` and the commitment would look
    ///      live even though the name does not exist. That synthesized RRset cannot be proven
    ///      to the ENS oracle: `DNSSECImpl.validateSignedSet` requires the RRSIG labels field
    ///      to equal `RRUtils.labelCount` of the owner name, and a wildcard-expanded RRSIG
    ///      carries the label count of the wildcard owner without its `*`, which is smaller. So
    ///      the oracle answers a wildcard-expanded TXT set with `InvalidLabelCount`, and no
    ///      wildcard can produce an `_ens.<tld>` claim this project would accept. The flag is
    ///      the completeness of the DNS proof, not a gate on the release.
    ///
    ///      `wildcardDenied` is set only when a record **covers** the wildcard. A zone that
    ///      publishes a real wildcard needs the different proof shape of RFC 5155 section 8.7,
    ///      which this contract does not read, and the flag reports false rather than true.
    ///
    ///      **The salt and the iteration count come from each record, never from this
    ///      contract.** The three hashes a denial needs are computed once for each distinct
    ///      parameter pair a proof carries, and reused while the pair does not change. The
    ///      cache key is `keccak256(abi.encode(iterations, salt))`, which is length-prefixed
    ///      and so cannot collide between a short salt and a long one. Every zone measured
    ///      publishes one `NSEC3PARAM`, so in practice the three hashes are computed once for a
    ///      whole call; a proof that mixes parameters recomputes them and still reads each
    ///      record under its own.
    /// @param name The queried name, in wire format, lowercase, exactly two labels, such as
    ///        `_ens.desi.`. Build it with `ensName` to get this project's label.
    /// @param proofs One chain for each NSEC3 record.
    /// @return result What the records say, as of `block.timestamp`.
    function proveAbsence(
        bytes memory name,
        DNSSEC.RRSetWithSignature[][] memory proofs
    ) public view returns (Result memory result) {
        uint256 at = block.timestamp;
        if (at > type(uint32).max) {
            revert TimestampOutOfRange(at);
        }
        // `zoneOf` holds the name to canonical, lowercase wire form and to exactly two labels,
        // and returns the second. Both refusals therefore happen here, before any proof is
        // read, exactly as `RootAbsencePredicate` refuses the shape of its own queried name.
        // The check lives in `zoneOf` and not also here, so that there is one place to read it
        // and one place to change it.
        Query memory query;
        query.name = name;
        query.zone = zoneOf(name);
        query.wildcard = NSECUtils.wildcardName(query.zone);

        // One record for each proof, so one fingerprint slot for each proof.
        bytes32[] memory fingerprints = new bytes32[](proofs.length);

        for (uint256 i; i < proofs.length; ++i) {
            _readProof(result, query, proofs[i], fingerprints, i, at);
        }

        result.proven =
            result.route == Route.NoName ||
            result.route == Route.NoTxtBit;
    }

    /// @notice `proveAbsence`, and a revert if the records do not prove absence.
    /// @dev For a consumer that wants the failure to stop the transaction.
    /// @param name The queried name, in wire format.
    /// @param proofs One chain for each NSEC3 record.
    /// @return result What the records say.
    function requireAbsence(
        bytes memory name,
        DNSSEC.RRSetWithSignature[][] memory proofs
    ) external view returns (Result memory result) {
        result = proveAbsence(name, proofs);
        if (!result.proven) {
            revert AbsenceNotProven(name, result.route);
        }
    }

    // --------------------------------------------------- the pure functions, for direct use

    /// @notice The zone that must have signed a proof about `name`.
    /// @dev The name with its first label removed. `_ens.desi.` gives `desi.`. The caller does
    ///      not name the zone, for the reason on `ProofNotFromZone`.
    ///
    ///      **This is where changed check 3 lives, and `proveAbsence` calls it before it reads
    ///      any proof.** `requireCanonicalName` refuses a malformed name and an uppercase one,
    ///      and the label count is held to exactly two. See `NotATopLevelChildName` for why
    ///      two is a ceiling as well as a floor.
    /// @param name The queried name, in wire format, exactly two labels.
    /// @return The zone apex, in wire format.
    function zoneOf(bytes memory name) public pure returns (bytes memory) {
        if (NSECUtils.requireCanonicalName(name) != QUERIED_NAME_LABELS) {
            revert NotATopLevelChildName(name);
        }
        uint256 offset = 1 + uint256(uint8(name[0]));
        return name.substring(offset, name.length - offset);
    }

    /// @notice This project's queried name for a top-level domain, `_ens.<tld>`.
    /// @dev The counterpart of `NSECUtils.wildcardName`. The predicate does not pin the label
    ///      itself: see `ENS_LABEL`.
    /// @param zone The top-level zone, in wire format, one label, such as `desi.`.
    /// @return The name `_ens.<zone>`, in wire format.
    function ensName(bytes memory zone) public pure returns (bytes memory) {
        if (NSECUtils.requireCanonicalName(zone) != 1) {
            revert NotATopLevelChildName(zone);
        }
        return abi.encodePacked(ENS_LABEL, zone);
    }

    /// @notice The wildcard name directly below `zone`. See `NSECUtils.wildcardName`.
    /// @param zone The zone name, in wire format.
    /// @return The wildcard name, in wire format.
    function wildcardName(
        bytes memory zone
    ) public pure returns (bytes memory) {
        return NSECUtils.wildcardName(zone);
    }

    /// @notice The hash-order comparator. See `NSEC3Utils.coversHash`.
    /// @dev Public and pure, so that a test can call it with any three hashes, and so that it
    ///      can be fuzzed. **Its closing-record rule is the opposite of
    ///      `RootAbsencePredicate.coversName`'s, and each rule is wrong in the other's
    ///      context.** NSEC3 owner names are hashes, so the chain is in hash order and the apex
    ///      has its own record somewhere in that order rather than at the start: there is no
    ///      apex hash to key the closing branch on, and RFC 5155 section 7.1 step 7 says only
    ///      that the last record's next-hashed-owner is the first owner hash of the chain. So
    ///      `next <= owner` is the test here, and `next == owner` is a legitimate one-record
    ///      chain rather than the bug the NSEC comparator describes. Do not make the two agree.
    /// @param ownerHashValue The decoded owner hash of the NSEC3 record.
    /// @param nextHashValue The record's next-hashed-owner field.
    /// @param nameHashValue The hash of the queried name.
    /// @return True if the record denies that a name with that hash exists in the zone.
    function coversHash(
        bytes20 ownerHashValue,
        bytes20 nextHashValue,
        bytes20 nameHashValue
    ) public pure returns (bool) {
        return
            NSEC3Utils.coversHash(ownerHashValue, nextHashValue, nameHashValue);
    }

    /// @notice Does this record deny that `name` exists? See `NSEC3Utils.recordCoversName`.
    /// @param ownerName The owner name of the NSEC3 record, in wire format.
    /// @param rdata The rdata of the NSEC3 record.
    /// @param name The queried name, in wire format, lowercase.
    /// @return True if the record denies that `name` exists in the zone.
    function recordCoversName(
        bytes memory ownerName,
        bytes memory rdata,
        bytes memory name
    ) public pure returns (bool) {
        return NSEC3Utils.recordCoversName(ownerName, rdata, name);
    }

    /// @notice Is `name` the name this record is the record for? See
    ///         `NSEC3Utils.recordMatchesName`.
    /// @param ownerName The owner name of the NSEC3 record, in wire format.
    /// @param rdata The rdata of the NSEC3 record.
    /// @param name The queried name, in wire format, lowercase.
    /// @return True if the record's owner hash is the hash of `name`.
    function recordMatchesName(
        bytes memory ownerName,
        bytes memory rdata,
        bytes memory name
    ) public pure returns (bool) {
        return NSEC3Utils.recordMatchesName(ownerName, rdata, name);
    }

    /// @notice The iterated hash of RFC 5155 section 5. See `NSEC3Utils.hashName`.
    /// @dev Public and pure so that a test can show the library accepting an iteration count
    ///      that this contract's entry point refuses. The library's cap is 150 and the entry
    ///      point's is `MAX_ITERATIONS`, which is 20. This function is the library's.
    /// @param name The name to hash, in wire format, lowercase.
    /// @param salt The salt from the record, which may be empty.
    /// @param iterations The additional iterations from the record.
    /// @return The 20-byte hash.
    function hashName(
        bytes memory name,
        bytes memory salt,
        uint256 iterations
    ) public pure returns (bytes20) {
        return NSEC3Utils.hashName(name, salt, iterations);
    }

    /// @notice The owner hash of an NSEC3 record, decoded from its owner name. See
    ///         `NSEC3Utils.ownerHash`.
    /// @param ownerName The owner name of an NSEC3 record, in wire format.
    /// @return The 20-byte owner hash.
    function ownerHash(bytes memory ownerName) public pure returns (bytes20) {
        return NSEC3Utils.ownerHash(ownerName);
    }

    /// @notice Reads the rdata of an NSEC3 record into its fields. See `NSEC3Utils.readRdata`.
    /// @param rdata The rdata of an NSEC3 record.
    /// @return The fields, and the offset where the type bitmap starts.
    function readRdata(
        bytes memory rdata
    ) public pure returns (NSEC3Utils.NSEC3Record memory) {
        return NSEC3Utils.readRdata(rdata);
    }

    /// @notice Does the NSEC3 record with this rdata list `dnstype`? See
    ///         `NSEC3Utils.rdataHasType`.
    /// @dev An empty NSEC3 bitmap reports every type absent and does not revert, which is legal
    ///      and is the NODATA proof for an empty non-terminal. A bitmap that is present and
    ///      malformed still reverts.
    /// @param rdata The rdata of an NSEC3 record.
    /// @param dnstype The type number to look for.
    /// @return True if the bitmap lists the type.
    function rdataHasType(
        bytes memory rdata,
        uint16 dnstype
    ) public pure returns (bool) {
        return NSEC3Utils.rdataHasType(rdata, dnstype);
    }

    /// @notice The iteration ceiling this contract accepts. See `MAX_ITERATIONS`.
    /// @return The cap, which is lower than `NSEC3Utils.MAX_ITERATIONS`.
    function maxIterations() external pure returns (uint256) {
        return MAX_ITERATIONS;
    }

    // ------------------------------------------------------------------------------- internal

    /// @dev Verifies one chain and reads the one NSEC3 record it carries. Split out of
    ///      `proveAbsence` so that the whole read fits inside the stack limit under `via_ir`.
    ///      Every refusal in here is a shape the zone itself cannot have published.
    function _readProof(
        Result memory result,
        Query memory query,
        DNSSEC.RRSetWithSignature[] memory chain,
        bytes32[] memory fingerprints,
        uint256 index,
        uint256 at
    ) private view {
        if (chain.length == 0) {
            revert EmptyProof(index);
        }

        // One verification for each record.
        RRUtils.SignedSet[] memory sets = oracle.verifyRRSetAt(chain, at);
        RRUtils.SignedSet memory signedSet = sets[sets.length - 1];

        // Changed check 1: NSEC3, not NSEC.
        if (signedSet.typeCovered != NSEC3Utils.DNSTYPE_NSEC3) {
            revert ProofNotNSEC3(index, signedSet.typeCovered);
        }
        // Changed check 2: the signer is the zone being asked about, not the root.
        if (!signedSet.signerName.equals(query.zone)) {
            revert ProofNotFromZone(index, signedSet.signerName, query.zone);
        }

        // Count distinct records, not reads. The same record sent twice is one record. The
        // fingerprint is over the bytes the oracle authenticated.
        bytes32 fingerprint = keccak256(signedSet.data);
        bool seen;
        for (uint256 j; j < result.records; ++j) {
            if (fingerprints[j] == fingerprint) {
                seen = true;
                break;
            }
        }
        if (!seen) {
            fingerprints[result.records] = fingerprint;
            result.records += 1;
        }

        uint256 inProof;
        for (
            RRUtils.RRIterator memory iter = RRUtils.iterateRRs(
                signedSet.data,
                0
            );
            !iter.done();
            iter.next()
        ) {
            // The oracle already holds every record in a set to one name, one type, and class
            // IN. These two checks keep this contract's own guarantee local.
            if (iter.dnstype != NSEC3Utils.DNSTYPE_NSEC3) {
                revert ProofNotNSEC3(index, iter.dnstype);
            }
            if (iter.class != CLASS_INET) {
                revert ProofNotClassINET(index, iter.class);
            }
            inProof += 1;
            _readRecord(
                result,
                query,
                iter.name(),
                iter.rdata(),
                index,
                signedSet.inception
            );
        }

        // One signature covers one NSEC3 record. See `ProofNotOneRecord`.
        if (inProof != 1) {
            revert ProofNotOneRecord(index, inProof);
        }
    }

    /// @dev Reads one authenticated NSEC3 record against the question, and folds what it says
    ///      into `result`. The record decides at most one of the three obligations of RFC 5155
    ///      section 8.4 by matching or covering the queried name, and it is also read for the
    ///      other two, which are reported.
    function _readRecord(
        Result memory result,
        Query memory query,
        bytes memory owner,
        bytes memory rdata,
        uint256 index,
        uint32 inception
    ) private pure {
        // Reverts for an owner name that is not well formed wire format, and for a first label
        // that is not 32 base32hex characters.
        bytes20 ownerHashValue = NSEC3Utils.ownerHash(owner);
        if (!owner.equals(OWNER_ZONE_OFFSET, query.zone)) {
            revert ProofOwnerNotInZone(index, owner, query.zone);
        }

        NSEC3Utils.NSEC3Record memory record = NSEC3Utils.readRdata(rdata);
        if (uint256(record.iterations) > MAX_ITERATIONS) {
            revert IterationCountAboveCap(
                index,
                record.iterations,
                MAX_ITERATIONS
            );
        }
        _hashUnder(query, record);

        if (ownerHashValue == query.nameHash) {
            // The name is in the zone. Its own type bitmap is the answer.
            _decide(
                result,
                NSEC3Utils.rdataHasType(rdata, NSEC3Utils.DNSTYPE_TXT)
                    ? Route.Present
                    : Route.NoTxtBit,
                owner,
                ownerHashValue,
                record,
                query.nameHash,
                inception
            );
        } else if (
            NSEC3Utils.coversHash(
                ownerHashValue,
                record.nextHashedOwner,
                query.nameHash
            )
        ) {
            // The name is not in the zone at all.
            _decide(
                result,
                Route.NoName,
                owner,
                ownerHashValue,
                record,
                query.nameHash,
                inception
            );
        }

        if (!result.apexMatched && ownerHashValue == query.apexHash) {
            result.apexMatched = true;
        }
        if (
            !result.wildcardDenied &&
            NSEC3Utils.coversHash(
                ownerHashValue,
                record.nextHashedOwner,
                query.wildcardHash
            )
        ) {
            result.wildcardDenied = true;
        }
    }

    /// @dev Makes sure the three hashes in `query` were computed under `record`'s own salt and
    ///      iteration count, recomputing all three if they were not. See `Query` for why the
    ///      key is `abi.encode` and not `abi.encodePacked`.
    function _hashUnder(
        Query memory query,
        NSEC3Utils.NSEC3Record memory record
    ) private pure {
        bytes32 key = keccak256(abi.encode(record.iterations, record.salt));
        if (query.cached && query.key == key) {
            return;
        }
        query.nameHash = NSEC3Utils.hashNameForRecord(query.name, record);
        query.wildcardHash = NSEC3Utils.hashNameForRecord(
            query.wildcard,
            record
        );
        query.apexHash = NSEC3Utils.hashNameForRecord(query.zone, record);
        query.key = key;
        query.cached = true;
    }

    /// @dev Keeps the strongest outcome seen. `Present` is a veto. A record that shows TXT on
    ///      the name itself cannot be overturned by a record that covers the name: the two
    ///      cannot both be true of one zone, and the one that reports the commitment as live is
    ///      the one that must win.
    function _decide(
        Result memory result,
        Route route,
        bytes memory owner,
        bytes20 ownerHashValue,
        NSEC3Utils.NSEC3Record memory record,
        bytes20 nameHashValue,
        uint32 inception
    ) private pure {
        if (uint8(route) <= uint8(result.route)) {
            return;
        }
        result.route = route;
        result.owner = owner;
        result.ownerHash = ownerHashValue;
        result.nextHash = record.nextHashedOwner;
        result.nameHash = nameHashValue;
        result.inception = inception;
        result.optOut = NSEC3Utils.isOptOut(record.flags);
    }
}
