// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;
// THROWAWAY AUDIT TEST - do not commit.
import {RSASHA512Algorithm} from "../src/RSASHA512Algorithm.sol";

contract AuditU16Test {
    RSASHA512Algorithm internal a = new RSASHA512Algorithm();
    address internal constant CONSOLE = 0x000000000000000000636F6e736F6c652e6c6f67;
    function _log(string memory s) internal view {
        (bool ok,) = CONSOLE.staticcall(abi.encodeWithSignature("log(string)", s)); ok;
    }
    function _hex(bytes memory b) internal pure returns (string memory) {
        bytes memory h = "0123456789abcdef";
        bytes memory o = new bytes(2 * b.length);
        for (uint256 i; i < b.length; i++) { o[2*i] = h[uint8(b[i]) >> 4]; o[2*i+1] = h[uint8(b[i]) & 0xf]; }
        return string(o);
    }
    /// explen = 0xFFFF in long form, key long enough that substring(7, 0xFFFF) succeeds.
    /// Then `exponentLen + 7` is uint16 arithmetic: 65535 + 7 overflows.
    function test_uint16OverflowInLongExponentBranch() public view {
        uint256 expLen = 65535;
        bytes memory key = new bytes(7 + expLen + 1); // one spare byte so the modulus is non-empty
        key[0] = 0x01; key[2] = 0x03; key[3] = 0x0a; key[4] = 0x00; key[5] = 0xff; key[6] = 0xff;
        for (uint256 i = 7; i < key.length; i++) key[i] = 0xff;
        try a.verify(key, hex"00", new bytes(128)) returns (bool r) {
            _log(r ? "returned true" : "returned false");
        } catch (bytes memory e) {
            _log(string.concat("REVERT 0x", _hex(e)));
        }
    }
}
