// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "forge-std/Test.sol";
import "./contracts/TLDMinter.sol";
import "./contracts/interfaces/IDNSSEC.sol";
import "./contracts/interfaces/ITLDMinter.sol";

// ─────────────────────────────────────────────────────────────
// Mocks
// ─────────────────────────────────────────────────────────────

/// @dev Returns whatever data/inception we load into it — no real DNSSEC verification.
contract MockDNSSEC is IDNSSEC {
    bytes private _data;
    uint32 private _inception;

    function setResponse(bytes memory data, uint32 inception) external {
        _data = data;
        _inception = inception;
    }

    function verifyRRSet(RRSetWithSignature[] calldata)
        external view override
        returns (bytes memory, uint32)
    {
        return (_data, _inception);
    }

    function verifyRRSet(RRSetWithSignature[] calldata, uint256)
        external view override
        returns (bytes memory, uint32)
    {
        return (_data, _inception);
    }
}

/// @dev Tracks which TLD label hashes get assigned and to whom.
contract MockRoot {
    mapping(bytes32 => address) public subnodeOwner;
    mapping(address => bool) public controllers;

    function setController(address c, bool v) external { controllers[c] = v; }
    function setSubnodeOwner(bytes32 label, address owner) external returns (bytes32) {
        subnodeOwner[label] = owner;
        return label;
    }
}

/// @dev Always returns address(0) — no TLD already exists in ENS.
contract MockENS {
    function owner(bytes32) external pure returns (address) { return address(0); }
}

/// @dev Security Council with a far-future expiration.
contract MockSecurityCouncil {
    function expiration() external view returns (uint256) {
        return block.timestamp + 365 days;
    }
}

// ─────────────────────────────────────────────────────────────
// Simulation
// ─────────────────────────────────────────────────────────────

/**
 * @title ClaimSimulationTest
 * @notice Simulates the full TLD claim lifecycle:
 *
 *   submitClaim()  →  7-day veto window  →  execute()
 *
 * Uses mocks for the DNSSEC oracle, ENS Root, ENS Registry, and Security Council
 * so no mainnet fork is required. The DNSSEC oracle mock returns a hand-crafted
 * DNS wire-format TXT record containing "a=0x{CLAIMANT}" — exactly what TLDMinter
 * expects to find at _ens.nic.{tld}.
 *
 * Tests:
 *   1. Happy path  — submit → warp 7d → execute → Root assigns the TLD
 *   2. Veto path   — submit → DAO vetoes → execute reverts with ClaimWasVetoed
 *   3. SC veto     — submit → SC vetoes → execute reverts with ClaimWasVetoed
 *   4. Too early   — submit → execute immediately → reverts with TimelockNotExpired
 */
contract ClaimSimulationTest is Test {

    TLDMinter           minter;
    MockDNSSEC          oracle;
    MockRoot            root;
    MockENS             ens;
    MockSecurityCouncil sc;

    // Real mainnet addresses — used as prank targets, not actual contracts
    address constant DAO_TIMELOCK = 0xFe89cc7aBB2C4183683ab71653C4cdc9B02D44b7;
    address constant SC_MULTISIG  = 0xaA5cD05f6B62C3af58AE9c4F3F7A2aCC2Cdc2Cc7;

    // Simulated TLD operator claiming "xyz"
    address constant CLAIMANT = address(0xBEEF);

    // "xyz" in DNS wire format: \x03 x y z \x00
    bytes constant XYZ_WIRE = hex"0378797a00";
    bytes32 constant XYZ_HASH = keccak256("xyz");

    function setUp() public {
        // Deploy mocks
        oracle = new MockDNSSEC();
        root   = new MockRoot();
        ens    = new MockENS();
        sc     = new MockSecurityCouncil();

        // Deploy TLDMinter — this is what the CREATE2 call in the DAO proposal does,
        // except here we deploy directly (no deterministic address needed for simulation).
        minter = new TLDMinter(
            address(oracle),   // DNSSEC oracle
            address(root),     // ENS Root
            address(ens),      // ENS Registry
            DAO_TIMELOCK,      // stored as `daoTimelock` immutable
            SC_MULTISIG,       // stored as `securityCouncilMultisig` immutable
            address(sc),       // stored as `securityCouncil` immutable
            7 days,            // timelockDuration (veto window)
            10,                // rateLimitMax (10 claims per period)
            7 days,            // rateLimitPeriod
            14 days            // proofMaxAge
        );

        // Seed the allowlist — this is what batchAddToAllowlist calls 3-6 do in the proposal
        vm.prank(DAO_TIMELOCK);
        string[] memory tlds = new string[](1);
        tlds[0] = "xyz";
        minter.batchAddToAllowlist(tlds);

        // Prime the mock oracle with a valid DNS TXT record for _ens.nic.xyz.
        // In production, the operator publishes this themselves at their DNS registrar.
        oracle.setResponse(
            _buildTXTRecord(XYZ_WIRE, CLAIMANT),
            uint32(block.timestamp)   // inception = now (fresh proof)
        );
    }

    // ── 1. Happy path ────────────────────────────────────────────────

    function test_fullClaimLifecycle() public {
        // Empty proof array — mock oracle ignores the input
        IDNSSEC.RRSetWithSignature[] memory proof;

        // Step 1: TLD operator submits their claim.
        // TLDMinter: checks allowlist → calls oracle.verifyRRSet → parses owner
        //            → stores MintRequest → emits ClaimSubmitted
        minter.submitClaim(XYZ_WIRE, proof);

        ITLDMinter.MintRequest memory req = minter.getRequest(XYZ_HASH);
        assertEq(req.owner,    CLAIMANT,             "owner should be CLAIMANT");
        assertFalse(req.vetoed,                      "should not be vetoed");
        assertGt(req.unlockTime, block.timestamp,    "unlock must be in the future");

        emit log_named_address("Pending claim owner",   req.owner);
        emit log_named_uint  ("Unlock timestamp",       req.unlockTime);
        emit log_named_uint  ("Current timestamp",      block.timestamp);

        // Step 2: Nobody vetoes. Warp past the 7-day window.
        vm.warp(block.timestamp + 7 days + 1);

        // Step 3: Anyone can call execute() — permissionless after the window.
        // TLDMinter calls root.setSubnodeOwner(XYZ_HASH, CLAIMANT)
        minter.execute(XYZ_HASH);

        assertEq(root.subnodeOwner(XYZ_HASH), CLAIMANT, "Root should assign xyz to CLAIMANT");
        emit log_string("xyz.eth is now owned by CLAIMANT");
    }

    // ── 2. DAO veto ──────────────────────────────────────────────────

    function test_daoVetoBlocksClaim() public {
        IDNSSEC.RRSetWithSignature[] memory proof;
        minter.submitClaim(XYZ_WIRE, proof);

        // DAO Timelock vetoes during the 7-day window
        vm.prank(DAO_TIMELOCK);
        minter.veto(XYZ_HASH, "policy: disputed claim");

        assertTrue(minter.getRequest(XYZ_HASH).vetoed, "claim should be marked vetoed");

        // Even after the window expires, execute() reverts
        vm.warp(block.timestamp + 7 days + 1);
        vm.expectRevert(abi.encodeWithSelector(TLDMinter.ClaimWasVetoed.selector, XYZ_HASH));
        minter.execute(XYZ_HASH);
    }

    // ── 3. Security Council veto ─────────────────────────────────────

    function test_securityCouncilVetoBlocksClaim() public {
        IDNSSEC.RRSetWithSignature[] memory proof;
        minter.submitClaim(XYZ_WIRE, proof);

        // SC multisig vetoes — only valid before their mandate expires
        vm.prank(SC_MULTISIG);
        minter.veto(XYZ_HASH, "security council: flagged");

        vm.warp(block.timestamp + 7 days + 1);
        vm.expectRevert(abi.encodeWithSelector(TLDMinter.ClaimWasVetoed.selector, XYZ_HASH));
        minter.execute(XYZ_HASH);
    }

    // ── 4. Timelock enforced ─────────────────────────────────────────

    function test_cannotExecuteBeforeWindowExpires() public {
        IDNSSEC.RRSetWithSignature[] memory proof;
        minter.submitClaim(XYZ_WIRE, proof);

        // Attempt execute() immediately — must revert
        vm.expectRevert();
        minter.execute(XYZ_HASH);
    }

    // ─────────────────────────────────────────────────────────────────
    // DNS wire-format helper
    // ─────────────────────────────────────────────────────────────────

    /**
     * @dev Builds a single DNS TXT RR that TLDMinter's _parseOwnerFromTXT can parse.
     *
     * Wire format:
     *   <name>              DNS name: \x04_ens\x03nic + tldWire
     *   <type  = 0x0010>    TYPE_TXT
     *   <class = 0x0001>    CLASS_INET
     *   <ttl   = 3600>
     *   <rdlength>
     *   <rdata>             \x2c (length=44) + "a=0x" + 40-char lowercase hex address
     *
     * In production, this is what the DNSSEC oracle returns after verifying the
     * operator's signed TXT record at _ens.nic.{tld}.
     */
    function _buildTXTRecord(bytes memory tldWire, address owner_)
        internal pure returns (bytes memory)
    {
        // DNS name: \x04_ens\x03nic + tldWire
        bytes memory dnsName = abi.encodePacked(
            hex"045f656e73036e6963", // \x04_ens\x03nic  (9 bytes)
            tldWire
        );

        // TXT rdata: 1-byte length + "a=0x" + 40-char hex address
        string memory hexAddr = _toHexString(uint160(owner_));
        bytes memory txtStr   = abi.encodePacked("a=0x", hexAddr); // 44 bytes
        bytes memory rdata    = abi.encodePacked(uint8(txtStr.length), txtStr);

        return abi.encodePacked(
            dnsName,
            uint16(16),            // TYPE_TXT
            uint16(1),             // CLASS_INET
            uint32(3600),          // TTL
            uint16(rdata.length),  // RDLENGTH
            rdata
        );
    }

    function _toHexString(uint160 value) internal pure returns (string memory) {
        bytes memory hexChars = "0123456789abcdef";
        bytes memory result   = new bytes(40);
        for (uint256 i = 40; i > 0; i--) {
            result[i - 1] = hexChars[value & 0xf];
            value >>= 4;
        }
        return string(result);
    }
}
