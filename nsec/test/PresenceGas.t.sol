// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// Gas measurement for a DNSSEC **presence** proof against the deployed mainnet oracle
/// `0x668ad4467129d49ECbe6274d95197797C0E262AA`.
///
/// Why this file exists: issue #2's expiry term is bounded below by renewal gas, and that
/// number was never measured. The absence figure in `../README.md` (~281k) is a different
/// chain and does not transfer: a presence proof walks root DNSKEY -> DS -> DNSKEY -> TXT.
///
/// The chain here is live and real, built by `tools/mkpresence.py`:
///   1 root DNSKEY (alg 8)  2 co DS  3 co DNSKEY  4 estmcmxci.co DS
///   5 estmcmxci.co DNSKEY (alg 13)  6 TXT _ens.estmcmxci.co (alg 13)
/// Six sets. A TLD presence proof is four. Measuring every prefix isolates each level, so the
/// four-set figure is derived from measurement rather than estimated.
///
/// Synthetic chains cannot answer this. `SyntheticChainBuilder.sol` signs with
/// `DummyAlgorithm`, which does no crypto, so it measures parsing and not verification.
///
/// **The chain expires 18 November 2026 at 23:30:16 UTC**, on the TXT RRSIG, which is the
/// earliest signature in it. After that this file fails for a reason that looks exactly like a
/// defect. Re-run `tools/mkpresence.py` and replace the twelve literals below from
/// `tools/presence-chain.json`.
///
/// **A refresh buys about one day.** Cloudflare re-signs `_ens.estmcmxci.co` on the fly with a
/// validity window of roughly two days, while every other set in the chain outlives it by weeks.
/// Chasing it is a treadmill. The published gas figures do not move when the chain is refreshed,
/// so this warning is the record rather than a maintenance task. The real fix is to lengthen the
/// signature validity on `estmcmxci.co`, which the author controls as the zone operator.
/// Last refreshed 17 November 2026.
///
/// **This file needs a fork and an EVM version that has the P-256 precompile.** It calls the
/// deployed oracle, so without `--fork-url` there is no code at that address. And sets 5 and 6 are
/// algorithm 13, which `P256Precompile` verifies by `staticcall` to `0x100`, EIP-7951. A call to
/// an address with no code succeeds and returns nothing, so on an EVM version below `osaka` the
/// verification silently reports invalid and the chain fails at `estmcmxci.co` with
/// `NoMatchingProof`. That looks like a defect in the fixture and is not one.
///
/// `setUp` skips this contract when no fork is present, so a clone of the repository runs green.
///
/// `foundry.toml` pins `evm_version = "osaka"`, so only the fork flag is needed here.
///
/// Run: forge test --match-path test/PresenceGas.t.sol --fork-url <mainnet> -vv

interface IDNSSEC {
    struct RRSetWithSignature {
        bytes rrset;
        bytes sig;
    }

    function verifyRRSet(RRSetWithSignature[] memory input)
        external
        view
        returns (bytes memory rrs, uint32 inception);
}

import {Cheats} from "./Cheats.sol";

/// No forge-std in this project (`foundry.toml` sets `src = "empty"`), so the console sink is
/// declared here at its well-known address, in the same style as `Cheats.sol` declares `Vm`.
abstract contract Console {
    address internal constant CONSOLE = 0x000000000000000000636F6e736F6c652e6c6f67;

    function _log(string memory s) internal view {
        (bool ok,) = CONSOLE.staticcall(abi.encodeWithSignature("log(string)", s));
        ok;
    }

    function _u(uint256 v) internal pure returns (string memory) {
        if (v == 0) return "0";
        uint256 n = v;
        uint256 d;
        while (n != 0) {
            d++;
            n /= 10;
        }
        bytes memory b = new bytes(d);
        while (v != 0) {
            b[--d] = bytes1(uint8(48 + (v - (v / 10) * 10)));
            v /= 10;
        }
        return string(b);
    }

    function _pad(string memory s, uint256 w) internal pure returns (string memory) {
        bytes memory b = bytes(s);
        if (b.length >= w) return s;
        bytes memory out = new bytes(w);
        for (uint256 i; i < w; i++) {
            out[i] = i < w - b.length ? bytes1(" ") : b[i - (w - b.length)];
        }
        return string(out);
    }
}

contract PresenceGasTest is Console, Cheats {
    /// @dev Inside the TXT RRSIG's validity window, 2026-11-16T21:30:16Z to 2026-11-18T23:30:16Z,
    ///      read from the signature in `rrsets[5]`. `setUp` warps here so that the chain's expiry
    ///      no longer fails this file. Refreshing the chain means moving this with it.
    uint256 internal constant VERIFY_AT = 1794954616;

    IDNSSEC internal constant ORACLE = IDNSSEC(0x668ad4467129d49ECbe6274d95197797C0E262AA);

    bytes[6] internal rrsets;
    bytes[6] internal sigs;
    string[6] internal labels = [
        "1. root DNSKEY (alg 8)",
        "2. co DS, signed by root (alg 8)",
        "3. co DNSKEY (alg 8)",
        "4. estmcmxci.co DS, signed by co (alg 8)",
        "5. estmcmxci.co DNSKEY (alg 13)",
        "6. the claim TXT set (alg 13)"
    ];

    function setUp() public {
        rrsets[0] = hex"003008000002a3006b0e0e006af25e8097280000003000010002a30001080100030803010001ca2b37135cf6dd2e7b565e9cf8d5311ba3950d982c1274a51ff85cc8c76f2f6faf4ddc4711522a75a9c5e8393cbdfce03f557aa752d5b8eb1b24ec1eda1a8332373625c577cb231cc3a7671bb9a69ffe501220eed6ac62054c31d52233562efdcfaddf4775430fefe8d60b3673a7cb04eee87b9487b635b1946afc665caf12c43571d0a322a93ab3abf11dfea9deb02baf48281f3464166d917f6b744a8a264fb26178c4673674ce4005b6198d802ade02853d3d5954eba7723ac68b8dfdf02949549bd48d38ab3eb4ae8bb929916caebed53fed3da45a301484bafd86eaf5df9c9d6ec8c6c6beda519ff60372f4e3ae9e83cc4e97c85e3841dc09de82b1e1e900003000010002a30001080101030803010001acffb409bcc939f831f7a1e5ec88f7a59255ec53040be432027390a4ce896d6f9086f3c5e177fbfe118163aaec7af1462c47945944c4e2c026be5e98bbcded25978272e1e3e079c5094d573f0e83c92f02b32d3513b1550b826929c80dd0f92cac966d17769fd5867b647c3f38029abdc48152eb8f207159ecc5d232c7c1537c79f4b7ac28ff11682f21681bf6d6aba555032bf6f9f036beb2aaa5b3778d6eebfba6bf9ea191be4ab0caea759e2f773a1f9029c73ecb8d5735b9321db085f1b8e2d8038fe2941992548cee0d67dd4547e11dd63af9c9fc1c5466fb684cf009d7197c2cf79e792ab501e6a8a1ca519af2cb9b5f6367e94c0d47502451357be1b500003000010002a30001080101030803010001af7a8deba49d995a792aefc80263e991efdbc86138a931deb2c65d5682eab5d3b03738e3dfdc89d96da64c86c0224d9ce02514d285da3068b19054e5e787b2969058e98e12566c8c808c40c0b769e1db1a24a1bd9b31e303184a31fc7bb56b85bbba8abc02cd5040a444a36d47695969849e16ad856bb58e8fac8855224400319bdab224d83fc0e66aab32ff74bfeaf0f91c454e6850a1295207bbd4cdde8f6ffb08faa9755c2e3284efa01f99393e18786cb132f1e66ebc6517318e1ce8a3b7337ebb54d035ab57d9706ecd9350d4afacd825e43c8668eece89819caf6817af62dc4fbd82f0e33f6647b2b6bda175f14607f59f4635451e6b27df282ef73d87";
        sigs[0]   = hex"4ee35bf8c188daed35ccba684a538243dd2a5ac62f28e5c8a8f9a11d65ec2acb35243ad673d6a449c204fcb0d3e66a1ba2d127f2f986202385584795376feeb0fd873ef602261f08703d40503b2bdd43c4a9323a3b9e4c27c16d7b22b6c62c9027c373c50ea90232a4a40998dc5c4bd3ebf99668bb4256f5a4cc3caf0a8bdf7d651210311c50d1345b18e2baf0b9dd5e2afb13e837569c75376f33540334edb276fa77624cd75ebe96c4032b3baaa2439519671ffd13b3d50ea59e323cc462b010057e92199dd3df73e98d65fffb774fc424b886c320bfb2c66bb2801e7fe4ee3f4ff647ef96ac09ed2a1361681c586b9202931568eecade6661592a018b0a4a";
        rrsets[1] = hex"002b0801000151806b0dd5c06afca430223b0002636f00002b00010001518000241e6a0802eb84f864cbe86e913796d2c8dd81933aa2c94bbcfb73419a42250bc4650b081b";
        sigs[1]   = hex"22f97e278c3f7e6450930a70bd838553f1854d44b484af216a768396da03c384a4bc56e4267bc270f9f5a260a0fe8c9473d302e46e81d50aed3e6d2953efae36b28142d84890875315cd3bdb25506e814fc73dad2d0d8cef4127256b92afff62423aaa911fdb138ec0697276c03c359cf7aeb856623b5a9604e4306b3778223dfeb8fd9d8f6477d06dbc0c52157f7c76abee063fdf310cda30804046e9d704c70a207cd8c2dc926e34a67434e86ad86f6990b46263811810aafa6f117f8e30e46b2c1ff26e3d1a838524b74ff6c4969b9e645cc7039a72917cf5d848fad976c710bff9e6d6a253b325d719fab7771d049560b14f4282d14f8fe380a2860dca56";
        rrsets[2] = hex"0030080100000e106b13fd3b6aec5b231e6a02636f0002636f000030000100000e1000a80100030803010001950dc30961b1792beb37b8160f308e5ef6c40ffc71b33d5cd507015eaa131787511a501ff0de5a5d4c68269b61808649eb7fe997959b38c2ba3ad9f5c9a04abae7fa009d0053106c501880da012ca2f81295d97257d06ab13ac7b99f784bd10091f41494a946026522babbc52e1dd75120d71278e5727df88823a8b8340ff77d003c4fff4a62381739715b21631e6e436417e530a847e63de6139a8919a7b73702636f000030000100000e1000880100030803010001d305937d7ec5312bfe712cd6ec15c65d4170c16d51a193472c36f8b30e83f2f22f91f9d2ca30c5354ab8a6a0d9e83656be2d11e63cff2a8687cd2bc24b153de623ec502ddc17f1e8c14cae62110c6de91ee8a879c29f2c5125c80abf6ec7226fc30d90287f7e6faefd656851574211671bfa284715a444820632c33dbcc42d2302636f000030000100000e10010801010308030100019e0aba74a7496ba5454451867c96324fea1af0a4bbfadf42b8852e8827d01d02a7819a075658152e5dab80bd96cf7200dbe64a83850ac544a3afd3cb95672e7c7debf5b91094ed25dedd7453df2e655a56747fdf95fdd12b6bd3fef0774d87e0e74debdabb8a1011c7d72fee032046220211f514ee8a176f75808943c7e6a180c00b4edc2f392fec097cf2e90101711c70c5d803a6c15dc32fb5ef6227a4dcbacf614d17f7424ee006f2520eafc3be329df11095976a1f0fffb8df7942dcb72c6fa294cf7b34637d9e608bb1c0cf6b00d791d8821ab53336965449213e700cbddb27797c41d5e0e97e3e22ecdecc7a9524484bf43545d68b8e3dc23d88f00deb02636f000030000100000e1001080101030803010001ccc00664f4a08f2a93ff2107ce9d28e462f2606ff661cf9c83d8342a43c0afe53e32f28d8151feba92af789d7ba4ef13a173e0bb7513a0abd1c112f7c31020f3576dbe3423fd90b80846feae96a5d5c01f8590775a918aa6987d042c0a66bde1c90499b4858c0b32900b093bd6bf46168af10dda6cf899644cf25c4f8a5d2fb2833b441673f906056e68e0ef430083875908155f0295bdbd7339ac6032e3c5cdcdd545e3d2908770ff89b458e10c059b34c7bb607d4642c60803410ed95abc828cc88fb4948063bae31000f48ad3ef0562a14130c4b1626a5cb81b6dc2c4b5007ee3a9eaef3a7d98fa6f14279f0b5993d6b22641eee14a2945526d1d1e506cd3";
        sigs[2]   = hex"25b7baeabe29482c797a883cf45b8bd902d33a81b29a4ffa1ece3beb1f1d9e2f9a4e4965c44ae66246b861fbc297d18c2a8b783f25c4663f541bf2e23b77eaf211f38480f9a17f038089b2d5480cc1a6bb5d660607f9cc6d940344b938ba59eaccbb27c4739ef451b69cbf89ddf4e5752280f5f6700a8b9cb35e03c26d5ac5ec4a4e50c3ebbfb6d579415ea552cbe2ac72efd4b13b7c68f1ee42037c1523e7652e34bab47455d5ea19f61e30fda036ae740c7caa10ea297b7c2e63f4da8c9c643e25dd02e370b4925344a83c2835e50c7813b49c81c434d5f166099199c268977e6cc9ba7e1c1106ab05a84f08e2c195de3fce8c82eebca84eb140e07429affa";
        rrsets[3] = hex"002b080200000e106b13fd3b6aec5b2341d702636f00096573746d636d78636902636f00002b000100000e10002409430d029874ae465411de0e03c47569669c9041f5664da0cad12fac524d7366411631d9";
        sigs[3]   = hex"54ea764cd9ed3322fdcc947106cc50132288dc78b77bff1ffd8dae43f90faeb3b684727573ae27ba4ad88173c0a03165bc894cf87e5d5195be5e5a7c997a841e835e3cd7e8cabb2457887fe3fe88f4e7e82ee85f4a4c43cc91043dc3eb79f04682361fd3c71dadaed5a7b568fbe7dccf30b349af141b6cf3ce1c1a4cae83b2c3aecb614e3ce66d6df9fe3888c38ab21a2c7ea704376685d7a548d676d1cd3bbb";
        rrsets[4] = hex"00300d0200000e106b35bb346ae54fb40943096573746d636d78636902636f00096573746d636d78636902636f000030000100000e1000440100030da09311112cf9138818cd2feae970ebbd4d6a30f6088c25b325a39abbc5cd1197aa098283e5aaf421177c2aa5d714992a9957d1bcc18f98cd71f1f1806b65e148096573746d636d78636902636f000030000100000e1000440101030d99db2cc14cabdc33d6d77da63a2f15f71112584f234e8d1dc428e39e8a4a97e1aa271a555dc90701e17e2a4c4b6f120b7c32d44f4ac02bd894cf2d4be7778a19";
        sigs[4]   = hex"0b90354fde8764939d5bfecc5f0bee00b53c5cc96ea7ff6f4c01820fc224f15e112d0d9f22f94c345c5302587537ce5ac7ac05aca856b73da26ee1e6a1f35a18";
        rrsets[5] = hex"00100d030000003c6afe35086afb75e886c9096573746d636d78636902636f00045f656e73096573746d636d78636902636f00001000010000003c002d2c613d307837303361653033664231323065433931653945643664303843653830343445343938434337383942045f656e73096573746d636d78636902636f00001000010000003c004f4e706f6c6963795f686173683d307835636436356663353032383137306136626632326235323835636333313263356236376332303239316232393161376266363332643662626136336531326536045f656e73096573746d636d78636902636f00001000010000003c007574706f6c6963793d68747470733a2f2f7261772e67697468756275736572636f6e74656e742e636f6d2f737465672d6574682f67746c642d706f6c6963792d617263686976652f6d61737465722f66697874757265732f73706563696d656e2d6465707265636174696f6e2d706f6c6963792e6d64";
        sigs[5]   = hex"ec81d395257a42a9f12b3eb231e5ef6161b28ce61d88937351688e280320edc8abefd96134181dc5d1649a2f939c6d0b39684e2770c79d6839c5afe58780d37b";

        // This file measures the deployed oracle, so it needs `--fork-url`. Without one there is
        // no code at that address and every call reverts, which reads as a defect in the chain.
        // Skip instead, so a clone runs green.
        if (address(ORACLE).code.length == 0) {
            vm.skip(true);
            return;
        }
        // Pin verification inside the TXT RRSIG window. Without this the file fails on signature
        // expiry from 18 November 2026, and that failure also reads as a defect.
        vm.warp(VERIFY_AT);
    }

    function _prefix(uint256 n) internal view returns (IDNSSEC.RRSetWithSignature[] memory input) {
        input = new IDNSSEC.RRSetWithSignature[](n);
        for (uint256 i; i < n; i++) {
            input[i] = IDNSSEC.RRSetWithSignature(rrsets[i], sigs[i]);
        }
    }

    /// Every prefix of the chain, with the incremental cost of each level.
    function test_presenceChainGasByPrefix() public view {
        _log("sets  cumulative   this level   what the level is");
        uint256 prev;
        for (uint256 n = 1; n <= 6; n++) {
            IDNSSEC.RRSetWithSignature[] memory input = _prefix(n);
            uint256 g0 = gasleft();
            ORACLE.verifyRRSet(input);
            uint256 used = g0 - gasleft();
            _log(
                string.concat(
                    _pad(_u(n), 4),
                    _pad(_u(used), 13),
                    _pad(_u(used - prev), 13),
                    "   ",
                    labels[n - 1]
                )
            );
            prev = used;
        }
    }

    /// The whole chain must actually verify, or the gas above is the cost of a revert.
    function test_fullChainVerifies() public view {
        (bytes memory rrs, uint32 inception) = ORACLE.verifyRRSet(_prefix(6));
        require(rrs.length > 0, "empty rrs: the chain did not verify");
        require(inception > 0, "zero inception");
        _log(string.concat("verified: rrs=", _u(rrs.length), " bytes, inception=", _u(inception)));
    }
}
