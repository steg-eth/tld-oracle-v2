// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// Not a test file. No forge-std is available in this project (`foundry.toml` sets
/// `src = "empty"`; see BUILD-BRIEF.md), so the standard Foundry cheatcode interface is declared
/// directly here, at its fixed, well-known address, instead of importing `forge-std/Vm.sol`.
/// `warp` is what the predicate suite needs, now that every entry point validates at
/// `block.timestamp` instead of a caller-supplied `at`. `skip` is needed by one file only,
/// `PresenceGas.t.sol`, which measures the **deployed** mainnet oracle and therefore cannot run
/// without `--fork-url`. Called from `setUp`, it skips that contract's tests rather than
/// failing them, so a clone of this repository runs green.
interface Vm {
    function warp(uint256 newTimestamp) external;
    function skip(bool skipTest) external;
}

abstract contract Cheats {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
}
