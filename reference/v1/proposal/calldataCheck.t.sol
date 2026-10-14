// SPDX-License-Identifier: MIT
pragma solidity >=0.8.25 <0.9.0;

import { ENS_Governance } from "@ens/ENS_Governance.sol";
import "forge-std/StdJson.sol";

interface ITLDMinter {
    function batchAddToAllowlist(string[] calldata tlds) external;
    function allowedTLDs(bytes32 labelHash) external view returns (bool);
    function version() external pure returns (string memory);
}

interface IRoot {
    function setController(address controller, bool enabled) external;
    function controllers(address controller) external view returns (bool);
}

/**
 * @title Proposal_ENS_TLD_Oracle_V2_Test
 * @notice Pre-draft calldata review for the TLD Oracle proposal.
 *
 * TLDMinter is pre-deployed via EOA before the governance vote.
 * The proposal executes 5 calls through the DAO timelock:
 *   1. root.setController(tldMinter, true)
 *   2-5. tldMinter.batchAddToAllowlist(batch) — all 1,166 gTLDs in 4 batches
 *
 * To verify locally:
 *   Clone: git clone https://github.com/steg-eth/dao-proposals.git
 *   cp .env.example .env && echo "MAINNET_RPC_URL=<your-rpc>" >> .env
 *   Run: forge test --match-contract Proposal_ENS_TLD_Oracle_V2_Test --fork-url $MAINNET_RPC_URL -vv
 */
contract Proposal_ENS_TLD_Oracle_V2_Test is ENS_Governance {
    using stdJson for string;

    // ─────────────────────────────────────────────────────────────────
    // ENS Core (for TLDMinter constructor)
    // ─────────────────────────────────────────────────────────────────

    address constant ROOT          = 0xaB528d626EC275E3faD363fF1393A41F581c5897;
    address constant DNSSEC_IMPL   = 0x0fc3152971714E5ed7723FAFa650F86A4BaF30C5;
    address constant ENS_REGISTRY  = 0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e;
    address constant SC_MULTISIG   = 0xaA5cD05f6B62C3af58AE9c4F3F7A2aCC2Cdc2Cc7;
    address constant SC_CONTRACT   = 0xB8fA0cE3f91F41C5292D07475b445c35ddF63eE0;

    // TLDMinter constructor args
    uint256 constant TIMELOCK_DURATION = 7 days;
    uint256 constant RATE_LIMIT_MAX    = 10;
    uint256 constant RATE_LIMIT_PERIOD = 7 days;
    uint256 constant PROOF_MAX_AGE     = 14 days;

    // ─────────────────────────────────────────────────────────────────
    // State — set during setUp, used by _generateCallData
    // ─────────────────────────────────────────────────────────────────

    address public tldMinter;

    // ─────────────────────────────────────────────────────────────────
    // Setup
    // ─────────────────────────────────────────────────────────────────

    function setUp() public override {
        super.setUp();

        // Simulate EOA pre-deploy of TLDMinter with mainnet constructor args
        bytes memory initCode = abi.encodePacked(
            vm.getCode("TLDMinter.sol:TLDMinter"),
            abi.encode(
                DNSSEC_IMPL,
                ROOT,
                ENS_REGISTRY,
                address(timelock),  // DAO timelock from ENS_Governance
                SC_MULTISIG,
                SC_CONTRACT,
                TIMELOCK_DURATION,
                RATE_LIMIT_MAX,
                RATE_LIMIT_PERIOD,
                PROOF_MAX_AGE
            )
        );
        address deployed;
        assembly {
            deployed := create(0, add(initCode, 0x20), mload(initCode))
        }
        require(deployed != address(0), "TLDMinter deployment failed");
        tldMinter = deployed;
        vm.label(tldMinter, "TLDMinter");
    }

    // ─────────────────────────────────────────────────────────────────
    // ENS_Governance overrides
    // ─────────────────────────────────────────────────────────────────

    function _selectFork() public override {
        vm.createSelectFork({ urlOrAlias: "mainnet" });
    }

    function _beforeProposal() public override {
        // TLDMinter should NOT be a Root controller yet
        assertFalse(
            IRoot(ROOT).controllers(tldMinter),
            "TLDMinter should not be a controller before proposal"
        );

        // Spot-check: allowlist should be empty
        assertFalse(
            ITLDMinter(tldMinter).allowedTLDs(keccak256("link")),
            "link should not be allowlisted before proposal"
        );
    }

    function _generateCallData()
        public
        override
        returns (
            address[] memory,
            uint256[] memory,
            string[] memory,
            bytes[] memory,
            string memory
        )
    {
        // Load batches
        string[4] memory batchFiles = [
            "src/ens/proposals/tld-oracle/allowlist-batch-1.json",
            "src/ens/proposals/tld-oracle/allowlist-batch-2.json",
            "src/ens/proposals/tld-oracle/allowlist-batch-3.json",
            "src/ens/proposals/tld-oracle/allowlist-batch-4.json"
        ];

        uint256 numTransactions = 5;
        targets = new address[](numTransactions);
        values = new uint256[](numTransactions);
        calldatas = new bytes[](numTransactions);
        signatures = new string[](numTransactions);

        // Call 1: Authorize TLDMinter as Root controller
        targets[0] = ROOT;
        calldatas[0] = abi.encodeWithSelector(IRoot.setController.selector, tldMinter, true);
        values[0] = 0;
        signatures[0] = "";

        // Calls 2-5: Seed allowlist in 4 batches
        for (uint256 i = 0; i < 4; i++) {
            string memory json = vm.readFile(batchFiles[i]);
            bytes memory raw = json.parseRaw(".tlds");
            string[] memory batch = abi.decode(raw, (string[]));

            targets[i + 1] = tldMinter;
            calldatas[i + 1] = abi.encodeWithSelector(ITLDMinter.batchAddToAllowlist.selector, batch);
            values[i + 1] = 0;
            signatures[i + 1] = "";
        }

        description = "Pre-draft: TLD Oracle - authorize TLDMinter and seed 1,166 gTLD allowlist";

        return (targets, values, signatures, calldatas, description);
    }

    function _afterExecution() public override {
        // Root controller registered
        assertTrue(
            IRoot(ROOT).controllers(tldMinter),
            "TLDMinter not registered as Root controller"
        );

        // Spot-check: known valid post-2012 gTLDs are allowlisted
        string[7] memory knownValid = ["link", "click", "help", "gift", "property", "sexy", "hiphop"];
        for (uint256 i = 0; i < knownValid.length; i++) {
            assertTrue(
                ITLDMinter(tldMinter).allowedTLDs(keccak256(abi.encodePacked(knownValid[i]))),
                string.concat(knownValid[i], " should be allowlisted")
            );
        }

        // Spot-check: pre-2012 gTLDs are NOT allowlisted
        string[5] memory excluded = ["com", "net", "org", "info", "biz"];
        for (uint256 i = 0; i < excluded.length; i++) {
            assertFalse(
                ITLDMinter(tldMinter).allowedTLDs(keccak256(abi.encodePacked(excluded[i]))),
                string.concat(excluded[i], " should NOT be allowlisted")
            );
        }

        // Version check
        assertEq(ITLDMinter(tldMinter).version(), "2.0.0", "Unexpected contract version");

        // Allowlist count
        string memory json = vm.readFile("src/ens/proposals/tld-oracle/allowlist.json");
        bytes memory raw = json.parseRaw(".tlds");
        string[] memory tlds = abi.decode(raw, (string[]));
        assertEq(tlds.length, 1166, "Allowlist should contain exactly 1,166 TLDs");
    }

    function _isProposalSubmitted() public pure override returns (bool) {
        return false; // Pre-draft — not yet on-chain
    }

    function dirPath() public pure override returns (string memory) {
        return ""; // No proposalCalldata.json in Tally format yet
    }
}
