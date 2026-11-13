// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// Not a test file. No forge-std is available in this project (`foundry.toml` sets
/// `src = "empty"`; see BUILD-BRIEF.md), so the standard Foundry cheatcode interface is declared
/// directly here, at its fixed, well-known address, instead of importing `forge-std/Vm.sol`.
/// Only `warp` is declared: it is the only cheatcode this suite needs, now that every entry
/// point validates at `block.timestamp` instead of a caller-supplied `at`.
interface Vm {
    function warp(uint256 newTimestamp) external;
}

abstract contract Cheats {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
}
