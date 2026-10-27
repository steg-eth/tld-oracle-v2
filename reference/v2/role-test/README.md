# Root authority after the registry handover

A rebuild of the role assertions first run on 18 October 2026. The original lived only in `/private/tmp` and was removed by the macOS tmp reaper on 23 October, leaving 5,732 empty directories and no files. The findings had survived as prose in `THOUGHT-PROVENANCE.md` (18 Oct) and `survey/ROOT-ROLE-TAXONOMY.md` §4. This is the durable version.

## Result

**7 pass, 0 fail, 36 assertions, about 12 seconds.** Green at three commits, each run first-hand on the date shown:

| Commit | What it is | Run | Result |
| --- | --- | --- | --- |
| `b1f97b91f4b28e28d8a61fa13f09da70fdca6c6a` | the commit the 18 October run used | 25 Oct 2026 | 7 pass, 0 fail |
| `0189770319b2212e4b1ed570a20ee44ac1f3dbcc` | #465 head on 25 October, 13 commits later | 25 Oct 2026 | 7 pass, 0 fail |
| `4f47cbcc11462fb413196e6b5c0f8090247a6c08` | #465 head on 26 October, after #483 and #484 | 26 Oct 2026 | 7 pass, 0 fail |

Use the full hashes. A short hash fails `git fetch --depth 1 origin <sha>` with "couldn't find remote ref".

Toolchain: bun 1.3.5, node v24.1.0, macOS. Submodule `contracts/lib/ens-contracts` at `f0151aaf8a53b5b8f725a584fc194997c8226fbd` throughout, matching the original run. Upstream baseline `registryHandover.test.ts` passes alongside it, 5 pass, 42 assertions, so the harness is known good.

That all three agree also settles the pin-drift question: nothing between `b1f97b91` and `4f47cbcc` changed the authority model Decision 2 rests on, #483's safe-transfer relaxation included, because the live registries keep the older rule.

## What it proves

| Test | Claim |
| --- | --- |
| The registry owner cannot repoint or unregister a registered entry | `setResolver`, `setSubregistry` and `unregister` all revert `EACUnauthorizedAccountRoles` for the holder of the safe root set |
| The registry owner cannot grant itself any dangerous root role | All nine halves of the dangerous set revert `EACCannotGrantRoles`, checked against `DANGEROUS_ROOT_ROLES` itself |
| Entry admin roles cannot be added after registration | Four admin bits all revert `EACCannotGrantRoles` on a registered entry. **This is the precise sense in which promotion fixes the envelope once** |
| `CAN_TRANSFER` does not take the root fallback | The root holder cannot transfer a registered entry; ownership is unchanged after the attempt |
| A retained safe admin role grants and revokes its regular bit, and regenerates the token id | States the reach in the positive direction, not only as a denial |
| An entry admin delegates repointing and takes it back | Delegation is real and withdrawable |
| The entry holder repoints the subregistry between registries, and a third party cannot | **The evidence for the standing recommendation that the Oracle hold the entry** |

## What it does not prove

Registry permission sufficiency only. Not an Oracle implementation, not proof authorization, not a DNS lifecycle. No Oracle contract exists. The same scoping the 18 October report applied to itself.

Two questions remain open and are not covered by any test here.

- Whether a root admin holder regenerating a registered entry's token id is **intended**, given those admin roles are classified safe. The suite shows it happens; it does not show it was meant to.
- Whether post-toggle CCIP resolution **fails or merely re-routes**. The 18 October DNS experiment established a routing change and explicitly not a demonstrated end-to-end resolution failure. It was never completed.

## Run it

```sh
git clone --depth 1 --branch post-audit-2 --recurse-submodules --shallow-submodules \
  https://github.com/ensdomains/contracts-v2.git cv2
cd cv2
git fetch --depth 1 origin 0189770319b2212e4b1ed570a20ee44ac1f3dbcc
git checkout FETCH_HEAD
git submodule update --init --depth 1 --recursive
cp ../rootAuthorityAfterHandover.test.ts contracts/test/e2e/
bun install
cd contracts && bun run compile --quiet
bun test --max-concurrency=1 ./test/e2e/rootAuthorityAfterHandover.test.ts
```

## Gotchas, all of which cost time here

- `handOverRegistryAdmin` and `registryHandover.test.ts` exist **only on the #465 deployment branch**, not on `post-audit-2`. Clone `post-audit-2` for the submodule set, then fetch the deployment commit.
- These are `bun:test` e2e tests driving a devnet, not Foundry. `forge test` does not reach them. The runner is `bun test`, preloaded with `test/e2e/test-setup.ts` by `bunfig.toml`.
- A delegate that sends a transaction must be a devnet signer. The named accounts are `deployer`, `owner`, `user`, `user2`, `nameOwner`. An arbitrary sentinel address can hold a role but cannot send, and fails `No Signer available`.
- Compare addresses with the custom `toEqualAddress` matcher. `getSubregistry` returns checksummed and `.address` does not, so `toBe` fails on case alone.
- A full clone of this repository is slow. The shallow clone above took under a minute against several minutes unfinished.

## Where this should live

Here, in `steg-eth/tld-oracle-v2`, committed and pinned, so a Labs engineer can run it without asking for anything. The working copy outside the repository is a scratch area and is not the record.
