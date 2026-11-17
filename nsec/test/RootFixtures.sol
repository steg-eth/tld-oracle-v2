// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {DNSSEC} from "../src/contracts/dnssec-oracle/DNSSEC.sol";
import {DNSSECImpl} from "../src/contracts/dnssec-oracle/DNSSECImpl.sol";
import {RSASHA256Algorithm} from "../src/contracts/dnssec-oracle/algorithms/RSASHA256Algorithm.sol";
import {SHA256Digest} from "../src/contracts/dnssec-oracle/digests/SHA256Digest.sol";
import {Cheats} from "./Cheats.sol";

/// Not a test file. Shared real, root-signed NSEC fixtures for the predicate's own suite.
///
/// All bytes below are root-signed data read from root server 198.41.0.4 on 17 November 2026,
/// encoded into ENS SignedSet form, exactly as carried in `tools/nsec/*.t.sol` (which measure the
/// *upstream oracle*, not this predicate). Reusing the same signed fixtures here is reuse of DNS
/// data, not reuse of that suite: every test built on top of these constants exercises
/// `RootAbsencePredicate`, not `DNSSECImpl` in isolation.
///
/// **These fixtures expire. RRSIGs on the NSEC sets are valid 2026-11-17 19:00:00Z to
/// 2026-11-30 20:00:00Z, and `AT` sits inside that window. After 30 November 2026 every test built
/// on them fails on signature expiry, which looks exactly like a defect in the predicate and is
/// not one.** The root re-signs on a rolling schedule, so a refresh buys roughly two weeks and
/// then this comment is the only thing that tells the next reader what happened.
///
/// To refresh: run `python3 tools/mkfixture.py`, replace the four NSEC set and signature pairs
/// below, and set `AT`, `INSIDE`, `AFTER_NSEC_EXPIRY` and `BEFORE_NSEC_INCEPTION` from the new
/// window. Last refreshed 17 November 2026.
///
/// Every `RootAbsencePredicate` entry point now validates at `block.timestamp` rather than a
/// caller-supplied `at` (the predicate's fix for F1, the stale-proof replay). `AT` and the window
/// constants below are still the times to warp to with `vm.warp`, inherited through `Cheats`;
/// `_acceptsAt` is the one exception, since it drives `DNSSECImpl.verifyRRSetAt` directly, and
/// that function keeps its own explicit time argument.
abstract contract RootFixtures is Cheats {
    uint256 internal constant AT = 1795505400; // 2026-11-11 16:43:22Z, inside every NSEC window below

    bytes internal constant ANCHORS =
        hex"00002b000100000e1000244f660802e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d00002b000100000e10002497280802683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16";
    bytes internal constant DNSKEY_SET =
        hex"003008000002a3006b0e0e006af25e8097280000003000010002a30001080100030803010001ca2b37135cf6dd2e7b565e9cf8d5311ba3950d982c1274a51ff85cc8c76f2f6faf4ddc4711522a75a9c5e8393cbdfce03f557aa752d5b8eb1b24ec1eda1a8332373625c577cb231cc3a7671bb9a69ffe501220eed6ac62054c31d52233562efdcfaddf4775430fefe8d60b3673a7cb04eee87b9487b635b1946afc665caf12c43571d0a322a93ab3abf11dfea9deb02baf48281f3464166d917f6b744a8a264fb26178c4673674ce4005b6198d802ade02853d3d5954eba7723ac68b8dfdf02949549bd48d38ab3eb4ae8bb929916caebed53fed3da45a301484bafd86eaf5df9c9d6ec8c6c6beda519ff60372f4e3ae9e83cc4e97c85e3841dc09de82b1e1e900003000010002a30001080101030803010001acffb409bcc939f831f7a1e5ec88f7a59255ec53040be432027390a4ce896d6f9086f3c5e177fbfe118163aaec7af1462c47945944c4e2c026be5e98bbcded25978272e1e3e079c5094d573f0e83c92f02b32d3513b1550b826929c80dd0f92cac966d17769fd5867b647c3f38029abdc48152eb8f207159ecc5d232c7c1537c79f4b7ac28ff11682f21681bf6d6aba555032bf6f9f036beb2aaa5b3778d6eebfba6bf9ea191be4ab0caea759e2f773a1f9029c73ecb8d5735b9321db085f1b8e2d8038fe2941992548cee0d67dd4547e11dd63af9c9fc1c5466fb684cf009d7197c2cf79e792ab501e6a8a1ca519af2cb9b5f6367e94c0d47502451357be1b500003000010002a30001080101030803010001af7a8deba49d995a792aefc80263e991efdbc86138a931deb2c65d5682eab5d3b03738e3dfdc89d96da64c86c0224d9ce02514d285da3068b19054e5e787b2969058e98e12566c8c808c40c0b769e1db1a24a1bd9b31e303184a31fc7bb56b85bbba8abc02cd5040a444a36d47695969849e16ad856bb58e8fac8855224400319bdab224d83fc0e66aab32ff74bfeaf0f91c454e6850a1295207bbd4cdde8f6ffb08faa9755c2e3284efa01f99393e18786cb132f1e66ebc6517318e1ce8a3b7337ebb54d035ab57d9706ecd9350d4afacd825e43c8668eece89819caf6817af62dc4fbd82f0e33f6647b2b6bda175f14607f59f4635451e6b27df282ef73d87";
    bytes internal constant DNSKEY_SIG =
        hex"4ee35bf8c188daed35ccba684a538243dd2a5ac62f28e5c8a8f9a11d65ec2acb35243ad673d6a449c204fcb0d3e66a1ba2d127f2f986202385584795376feeb0fd873ef602261f08703d40503b2bdd43c4a9323a3b9e4c27c16d7b22b6c62c9027c373c50ea90232a4a40998dc5c4bd3ebf99668bb4256f5a4cc3caf0a8bdf7d651210311c50d1345b18e2baf0b9dd5e2afb13e837569c75376f33540334edb276fa77624cd75ebe96c4032b3baaa2439519671ffd13b3d50ea59e323cc462b010057e92199dd3df73e98d65fffb774fc424b886c320bfb2c66bb2801e7fe4ee3f4ff647ef96ac09ed2a1361681c586b9202931568eecade6661592a018b0a4a";

    // zw. NSEC .  -- the last delegation in the zone; next-owner is the root. Closes the zone.
    bytes internal constant WRAP_SET =
        hex"002f0801000151806b0dd5c06afca430223b00027a7700002f0001000151800009000006200000000003";
    bytes internal constant WRAP_SIG =
        hex"3363004eb8ccac9a3429fc9b44ec50b15ccd0230c68fe6de0453a7fe3b87ab9be315f2988c91c9b3b98379395ae403ce7333c2705367236a1cbbac3dcb85fb585c35ab9739a3fe715998c5ec193cb6b0e809591585df096eaa7556b722dc019e8e39944e985aa5413809d52aace533ae4b0d4fc2abe8a43cb28bac7918fec63704a9d1e9458430ad9fefed547ff92805227ab43f0969084962d2290b1abb66f5f567526bc5a0336174ace9cec82988aa42ed511c0ace38df92252b10229919fe956a75d36fff2c029367192dbebdac13e52fbf6a05e44651c297f323a0f50185a60d5f177716a304801239a88d8e6a7a84ed4242003fc528b4b5ad4198d8fed9";

    /// WRAP_SET with one byte flipped inside the type bitmap (the fifth of the six bitmap data
    /// bytes, 0x00 -> 0x01). A different byte, and a different region, from the negative control
    /// in `tools/nsec/NegativeControl.t.sol`, which corrupts the next-owner name instead. Signed
    /// over by the same (now-mismatched) WRAP_SIG, so the oracle's signature check must catch it.
    bytes internal constant WRAP_SET_CORRUPT =
        hex"002f0801000151806b0dd5c06afca430223b00027a7700002f0001000151800009000006200000000103";

    // aq. NSEC aquarelle.  -- a live ccTLD delegated with no DS
    bytes internal constant AQ_SET =
        hex"002f0801000151806b0dd5c06afca430223b0002617100002f0001000151800013096171756172656c6c65000006200000000003";
    bytes internal constant AQ_SIG =
        hex"747b7b632145aae680c674aadf0e25d1f672e55ec637aa5e6f5c0caa4c4cd3e781de1fb96b16925c6126dc13d167fb54f89e2b7db496696b26d59ec5e0c75527659b4cca67cbc4913cf0003ac4fae3d02e130582571227cac36901e326f15cb928e2c89b0f4c5d3d885a88524f6d140810ce1625400a19f9d9642c1a3cdc5f12286d3f80496c3676d7c315d3968472f05e3aaafb316decf14347d1684d87d63508eae82289545f6636babea5920f264c36e94afd271895805ddaf109bc1cc296ebcb651f31ce5368e1d42458ae50b91371e09ae3f25ded1409644f800f1e034e8dad41addd2030734d9285d45497fb1a24959558a6deeed867c825a3a5d0b974";

    // domains. NSEC dot.  -- an ordinary gap; doosan. (the removed TLD) falls inside it
    bytes internal constant DOMAINS_SET =
        hex"002f0801000151806b0dd5c06afca430223b0007646f6d61696e7300002f000100015180000d03646f74000006200000000013";
    bytes internal constant DOMAINS_SIG =
        hex"a7223171c0bdb7e98add3bf6e1ad6fca0fae9b5a341f99a09eba37ead97db9b30e88c26ff90f476ccf2ace8a5cf42a906fcc3cf19a25d5c09d1364fb76e05b5b04eb85cf7ca15e551476ecb177796f3186c2c7ebdb6f1c42c12d23716694b3211d8cae7041acda75492914b11c864b2402542df19296256e463f39c664b5e884d406c147ea4f7e7dab807c2562cbaed9980224862e299dee49e1aa1bbd1314c3cc1319c2b25610cba6a091e21171f52d5840080a21c2a2f355b8325a68f1783a65d256e442889c0c1f8233a036eb0e4d8a94d578ca20b4a01632921c5a4488b01793d23e1815b388628ad8e475fb1e638a9602e07c2bcd9f27405cda80da8711";

    // . NSEC aaa.  -- the root's own record, denying a wildcard at the apex
    bytes internal constant ROOT_SET =
        hex"002f0800000151806b0dd5c06afca430223b0000002f000100015180000f036161610000082200000000038001";
    bytes internal constant ROOT_SIG =
        hex"91ddd189bb9b0200a113efccb1e4b5fa8f9fd4160b7eb02a4f790c838b16f3b9b4b9c3b3b7f8d6e0f51ea921a5b1cd00bdf8f46c1ccd16d3e52571610c7128972f7fa10770f9c53f9a480e2a0447d57122a02af7337ac4e989040bfb28538f184cb68d10d1d2b2729ce3960ce6d8f17b3adbdd16058376eb13ec12c6429f4d8a473cda6226211b0290a1f57fa52a4dd21b944ac56912b5bcbd2181f73918de20d6e6f8c1a19192d22d77a68e3a150afc0fccaed8c8d585a629a414ea8ea0eb28580dc3e4f361b752ca8efcf414aaa9e354ee02eacabb628b14eda2b8c893f1679158343c28e7530e96da273c416d47b3d9a5fe8662e285c4ee9f63c4c26b282b";

    // Signature validity window, from WindowAndMultiNsec.t.sol's upstream measurement.
    uint256 internal constant INSIDE = 1795505400; // 2026-11-11 16:43:22Z
    uint256 internal constant AFTER_NSEC_EXPIRY = 1796068801; // NSEC expiration + 1s
    uint256 internal constant BEFORE_NSEC_INCEPTION = 1794941999; // NSEC inception - 1s

    // Wire-format query names used across the suite.
    bytes internal constant NAME_DOOSAN = hex"06646f6f73616e00"; // doosan.
    bytes internal constant NAME_COM = hex"03636f6d00"; // com.
    bytes internal constant NAME_ZZZZZZZZ = hex"087a7a7a7a7a7a7a7a00"; // zzzzzzzz.
    bytes internal constant NAME_AQ = hex"02617100"; // aq.
    bytes internal constant NAME_ZW = hex"027a7700"; // zw.
    bytes internal constant NAME_FOO_DOT_COM = hex"03666f6f03636f6d00"; // foo.com. (two labels)
    bytes internal constant NAME_COM_UPPER = hex"03434f4d00"; // COM. (uppercase)

    function _realOracle() internal returns (DNSSECImpl oracle) {
        oracle = new DNSSECImpl(ANCHORS);
        oracle.setAlgorithm(8, new RSASHA256Algorithm());
        oracle.setDigest(2, new SHA256Digest());
    }

    function _chain(
        bytes memory set,
        bytes memory sig
    ) internal pure returns (DNSSEC.RRSetWithSignature[] memory chain) {
        chain = new DNSSEC.RRSetWithSignature[](2);
        chain[0] = DNSSEC.RRSetWithSignature(DNSKEY_SET, DNSKEY_SIG);
        chain[1] = DNSSEC.RRSetWithSignature(set, sig);
    }

    function _oneProof(
        bytes memory set,
        bytes memory sig
    ) internal pure returns (DNSSEC.RRSetWithSignature[][] memory proofs) {
        proofs = new DNSSEC.RRSetWithSignature[][](1);
        proofs[0] = _chain(set, sig);
    }

    function _twoProofs(
        bytes memory setA,
        bytes memory sigA,
        bytes memory setB,
        bytes memory sigB
    ) internal pure returns (DNSSEC.RRSetWithSignature[][] memory proofs) {
        proofs = new DNSSEC.RRSetWithSignature[][](2);
        proofs[0] = _chain(setA, sigA);
        proofs[1] = _chain(setB, sigB);
    }
}
