// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title RootFixtures
/// @notice Every byte string in this library came from the DNS root server 198.41.0.4 on
///         11 November 2026 and is signed by the root zone. Nothing here is synthetic.
///
///         Provenance: the sets and signatures are copied from the upstream-behaviour
///         measurements in `tools/nsec/*.t.sol` (RootProof.t.sol, AbsencePredicate.t.sol,
///         WindowAndMultiNsec.t.sol, NegativeControl.t.sol). Those files predate the predicate
///         and are not its test suite. This audit re-decoded every field independently with
///         `scripts/decode_fixtures.py` before using it; that script prints the table in
///         REPORT.md section "Fixtures".
///
///         Decoded, verified facts:
///           ANCHORS      two DS RRs at `.`, key tags 20326 and 38696, algorithm 8, digest 2.
///           DNSKEY_SET   type 48 at `.`, signer `.`, key tag 38696,
///                        valid 2026-11-10 00:00:00Z .. 2026-12-01 00:00:00Z.
///           ZW_SET       `zw. NSEC .`      bitmap NS RRSIG NSEC        (no DS; live ccTLD)
///           AQ_SET       `aq. NSEC aquarelle.` bitmap NS RRSIG NSEC    (no DS; live ccTLD)
///           DOMAINS_SET  `domains. NSEC dot.`  bitmap NS DS RRSIG NSEC (ordinary gap)
///           ROOT_SET     `. NSEC aaa.`     bitmap NS SOA RRSIG NSEC DNSKEY ZONEMD (apex)
///           CORRUPT_SET  DOMAINS_SET with next-owner `dot.` -> `dou.`, one byte, same RRSIG.
///         Every NSEC RRSIG above: signer `.`, key tag 8763, algorithm 8,
///         valid 2026-11-11 04:00:00Z .. 2026-11-24 05:00:00Z.
library RootFixtures {
    /// @dev Unix times. The NSEC window is strictly inside the DNSKEY window, so a refusal just
    ///      outside the NSEC window is attributable to the NSEC set and not to the key set.
    uint256 internal constant INSIDE = 1794415402; // 2026-11-11 16:43:22Z
    uint32 internal constant NSEC_INCEPTION = 1794369600; // 2026-11-11 04:00:00Z
    uint32 internal constant NSEC_EXPIRATION = 1795496400; // 2026-11-24 05:00:00Z

    bytes internal constant ANCHORS =
        hex"00002b000100000e1000244f660802e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d00002b000100000e10002497280802683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16";

    bytes internal constant DNSKEY_SET =
        hex"003008000002a3006b0e0e006af25e8097280000003000010002a30001080100030803010001ca2b37135cf6dd2e7b565e9cf8d5311ba3950d982c1274a51ff85cc8c76f2f6faf4ddc4711522a75a9c5e8393cbdfce03f557aa752d5b8eb1b24ec1eda1a8332373625c577cb231cc3a7671bb9a69ffe501220eed6ac62054c31d52233562efdcfaddf4775430fefe8d60b3673a7cb04eee87b9487b635b1946afc665caf12c43571d0a322a93ab3abf11dfea9deb02baf48281f3464166d917f6b744a8a264fb26178c4673674ce4005b6198d802ade02853d3d5954eba7723ac68b8dfdf02949549bd48d38ab3eb4ae8bb929916caebed53fed3da45a301484bafd86eaf5df9c9d6ec8c6c6beda519ff60372f4e3ae9e83cc4e97c85e3841dc09de82b1e1e900003000010002a30001080101030803010001acffb409bcc939f831f7a1e5ec88f7a59255ec53040be432027390a4ce896d6f9086f3c5e177fbfe118163aaec7af1462c47945944c4e2c026be5e98bbcded25978272e1e3e079c5094d573f0e83c92f02b32d3513b1550b826929c80dd0f92cac966d17769fd5867b647c3f38029abdc48152eb8f207159ecc5d232c7c1537c79f4b7ac28ff11682f21681bf6d6aba555032bf6f9f036beb2aaa5b3778d6eebfba6bf9ea191be4ab0caea759e2f773a1f9029c73ecb8d5735b9321db085f1b8e2d8038fe2941992548cee0d67dd4547e11dd63af9c9fc1c5466fb684cf009d7197c2cf79e792ab501e6a8a1ca519af2cb9b5f6367e94c0d47502451357be1b500003000010002a30001080101030803010001af7a8deba49d995a792aefc80263e991efdbc86138a931deb2c65d5682eab5d3b03738e3dfdc89d96da64c86c0224d9ce02514d285da3068b19054e5e787b2969058e98e12566c8c808c40c0b769e1db1a24a1bd9b31e303184a31fc7bb56b85bbba8abc02cd5040a444a36d47695969849e16ad856bb58e8fac8855224400319bdab224d83fc0e66aab32ff74bfeaf0f91c454e6850a1295207bbd4cdde8f6ffb08faa9755c2e3284efa01f99393e18786cb132f1e66ebc6517318e1ce8a3b7337ebb54d035ab57d9706ecd9350d4afacd825e43c8668eece89819caf6817af62dc4fbd82f0e33f6647b2b6bda175f14607f59f4635451e6b27df282ef73d87";
    bytes internal constant DNSKEY_SIG =
        hex"4ee35bf8c188daed35ccba684a538243dd2a5ac62f28e5c8a8f9a11d65ec2acb35243ad673d6a449c204fcb0d3e66a1ba2d127f2f986202385584795376feeb0fd873ef602261f08703d40503b2bdd43c4a9323a3b9e4c27c16d7b22b6c62c9027c373c50ea90232a4a40998dc5c4bd3ebf99668bb4256f5a4cc3caf0a8bdf7d651210311c50d1345b18e2baf0b9dd5e2afb13e837569c75376f33540334edb276fa77624cd75ebe96c4032b3baaa2439519671ffd13b3d50ea59e323cc462b010057e92199dd3df73e98d65fffb774fc424b886c320bfb2c66bb2801e7fe4ee3f4ff647ef96ac09ed2a1361681c586b9202931568eecade6661592a018b0a4a";

    // zw. NSEC .  -- the record that closes the root zone. next-owner is the root.
    bytes internal constant ZW_SET =
        hex"002f0801000151806b0519d06af3e840223b00027a7700002f0001000151800009000006200000000003";
    bytes internal constant ZW_SIG =
        hex"a72a1b3af0107414aa4b218e0963dd762a7a0b48eba87b74efb9b56ff9a1af1282990750e95660cfaabbf8a093e777f981225507e9c8c574d212e3bf2978662d548124529a8adb533a7d90a20c09d66ec9386030a574a53000a749ee497a7db35b06430330586fef025bfbf5022e3ed1e4f2c1af706b065ed50ed3d2e13d085b7642fe36695f6c12c05f15c9fc9d759dba2a6c35dffc963458bda85f5e685ae2ce909307a85d01f52771a2f8557a365825cf6a9168445cbb083c10fdda5d327119a17f3dae551ddc01631fd326b889028dca0345d379b122e7fd2a10ce5577f546046cda1a33966ae7943643539b348cb1149aeb8f7ea64fc0a6c00d107fc339";

    // aq. NSEC aquarelle.  -- a live ccTLD delegated with NS and no DS.
    bytes internal constant AQ_SET =
        hex"002f0801000151806b0519d06af3e840223b0002617100002f0001000151800013096171756172656c6c65000006200000000003";
    bytes internal constant AQ_SIG =
        hex"a481acaded14f08b097514fc32974c336de12c514a82ebeb202aab08efe57aa22b052f3ae1321545f1ac6777d4075ca16daea179669cec3bba6be3956846b0a29740fa176693b0f8cf6cc8304d4587fe8c53ddaeb9c122b299a8199dddcbcc07620487aa49ecb1217a99a068f9e6ee05c883355ade4df2490082867f7c2a889f164fb0bc5db63aa4fe7d5f44d50be09e795949e246963f68b2d8f0f04492ca47af66f242dc0ac30b3dde4061b55af885660c2b8d2562f3f3db3456f55b3d32b97f2cfc7818040902d48a219bc262212cea4a16a504f7de58cac7a974ad6b15f21b7f0f9cbc532c41df88181bbb9c6edb6232aa79255f0cd1fb6b433c4027a235";

    // domains. NSEC dot.  -- an ordinary gap. `.doosan` was removed from the root in 2016.
    bytes internal constant DOMAINS_SET =
        hex"002f0801000151806b0519d06af3e840223b0007646f6d61696e7300002f000100015180000d03646f74000006200000000013";
    bytes internal constant DOMAINS_SIG =
        hex"179ad535badee5ed9ca4428f87e3424f19f7a1aef177dc17afcc28332f1f4ce2316d2e0ebf460164cc59445e410d8c7a367f4f3d918d4bc666ab9e3318db168f31112e5382bac35fa844d56142be975de37da0a6dabe4d2a8806646a101873378e943ab2ca4924a6feeb046107e4aef1a65defecd4764599e2f455bc376f0dddb3409111aee3fbb19cf9b46e2dfdb01e208500dcaffb8f05efed7bd89636c3e2924f4d39d708c4db71ebb4dc7b6747d6f59a3e9983f4309639075e3cf2d029a5814d80c254b8601517cee8cb10fccd09c63fc1a1e0a65cf20602cf3fa40cdc077716ba8889be73335a7f1936d55d1c2471156ace53c8e4215ebcc694b4f2c5df";

    // . NSEC aaa.  -- the root's own record. Returned next to the covering one for an
    //                 absent name, and the record that denies the wildcard at the apex.
    bytes internal constant ROOT_SET =
        hex"002f0800000151806b0519d06af3e840223b0000002f000100015180000f036161610000082200000000038001";
    bytes internal constant ROOT_SIG =
        hex"85e00e74699807d72c119d7eb626c21959da660798ff47d29c7430d1018a44d1c60b419a99f3f5edd7379722c552f9705d4f9216b050f511ffcd3bc23af6854e5266b42d540e60be47f81af1048462ff3f40a36411e82a6419af1c41fb527ee03faafa5f7e3b03531de4efa732ce339354942b3b05176d70fd7bd92d2dcc91a6f7b0315817daf1bd85f22e9617ea8a36a96556ead86e2908ec4e058eac6aae6c4d7252f64f0ee7e7b64313e3a4687780fcaaae486406e4d622ce2d9ce18418ce2ccb334a33a34534721ed7641d0832e8623d1171ec5a52aa712ccb6861fab306a2e5659e3dc6f2be0070c23ae18e946c610c3ab4f82285ae135f2f2a442ed9a2";

    // DOMAINS_SET with one byte changed in the record: next-owner `dot.` becomes `dou.`.
    // The RRSIG is the genuine one. This is the only mutated byte in this library.
    bytes internal constant CORRUPT_SET =
        hex"002f0801000151806b0519d06af3e840223b0007646f6d61696e7300002f000100015180000d03646f75000006200000000013";

    // ------------------------------------------------------------------- query names, wire form
    bytes internal constant N_DOOSAN = hex"06646f6f73616e00"; // doosan.   removed 2016-02-02
    bytes internal constant N_ZZZZZZZZ = hex"087a7a7a7a7a7a7a7a00"; // zzzzzzzz. sorts above zw.
    bytes internal constant N_AA = hex"02616100"; // aa.       sorts below aaa.
    bytes internal constant N_COM = hex"03636f6d00"; // com.      live
    bytes internal constant N_AQ = hex"02617100"; // aq.       live, no DS
    bytes internal constant N_ZW = hex"027a7700"; // zw.       live, no DS
    bytes internal constant N_AAA = hex"0361616100"; // aaa.      live, is the apex next-owner
    bytes internal constant N_DOT = hex"03646f7400"; // dot.      live, is the gap next-owner
    bytes internal constant N_DOMAINS = hex"07646f6d61696e7300"; // domains.  live, is the gap owner
    bytes internal constant N_COM_UPPER = hex"03434f4d00"; // COM.
    bytes internal constant N_NIC_DOOSAN = hex"036e696306646f6f73616e00"; // nic.doosan.
    bytes internal constant N_ROOT = hex"00"; // .
    bytes internal constant N_WILDCARD = hex"012a00"; // *.
}
