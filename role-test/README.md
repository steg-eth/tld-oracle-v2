# Registry behaviour under lapse and revive

Two end-to-end tests against `ensdomains/contracts-v2`, written for the TLD lifecycle in
[issue #2](https://github.com/steg-eth/tld-oracle-v2/issues/2). They answer what a name carries
across a removal, and what a reserved entry can hold.

They change no upstream file. They run inside a clone of `contracts-v2`, using its own deployment
scripts and its own test harness.

| File | What it asserts |
| --- | --- |
| `reviveCarryover.test.ts` | What survives `unregister` then `renew`: the resource id, the token id, a prior delegate's roles, the resolver, the subregistry, the owner and the status. Then whether the name can be returned to its holder |
| `reservedEntries.test.ts` | What a RESERVED entry can hold, who can grant a role on it, and who can remove it |

## Run them

```sh
git clone --depth 1 --branch post-audit-2 --recurse-submodules --shallow-submodules \
  https://github.com/ensdomains/contracts-v2.git cv2
cd cv2
git fetch --depth 1 origin e501df6e3c05d3a657f705e0b7c6886e4b36c451   # PR #501 head
git fetch --depth 1 origin 68471ab593858708ba8af390914816972316dea7   # its base
git checkout e501df6e3c05d3a657f705e0b7c6886e4b36c451
git submodule update --init --depth 1 --recursive
cp ../role-test/*.test.ts contracts/test/e2e/
bun install
cd contracts && bun run compile --quiet
bun test --max-concurrency=1 ./test/e2e/reviveCarryover.test.ts
bun test --max-concurrency=1 ./test/e2e/reservedEntries.test.ts
```

**Run the baseline first.** `bun test ./test/e2e/registryHandover.test.ts` is upstream's own suite and
gives 5 pass and 42 assertions at both commits. A result from a tree where that does not pass means
nothing.

## Results

Measured 13 November 2026, at both commits.

**[#501](https://github.com/ensdomains/contracts-v2/pull/501) does what it says.** It makes
`unregister` clear `resolver` and `subregistry`. At the base commit a revive leaves both set, so the
next holder of the name inherits the previous holder's resolver and subregistry. At the head both
read zero. `reviveCarryover` passes at the head with 10 assertions and fails at the base on the
resolver.

Upstream's own test for this is a Foundry unit test against `PermissionedRegistry`. This one drives
`RootRegistry` after the real registry handover, with a delegate holding a role on the entry.

**Nothing else carries across a removal.** `unregister` increments `eacVersionId` and
`tokenVersionId`, so the resource id and the token id regenerate and a prior delegate's
`SET_RESOLVER` reads zero. True at both commits.

**A reserved entry cannot hold a role, by two separate guards.** `_register` reverts
`EACCannotGrantRoles` for a zero owner with a non-zero role bitmap. A later grant reverts the same
way, from the root role holder and from the token holder. A reservation can carry a `resolver` and a
`subregistry` given at creation, but no permissions.

**A reserved entry cannot be unregistered after the handover.** Both callers get
`EACUnauthorizedAccountRoles`. Root `UNREGISTER` is in `DANGEROUS_ROOT_ROLES` and is revoked at the
handover, and no entry-scoped grant is possible on an entry with no owner. The only exit is
`register` over it, which needs root `ROLE_REGISTER_RESERVED`. That call succeeds and returns the
name as REGISTERED.

## Why this matters to the Oracle

The lifecycle in issue #2 returns a lapsed TLD by `unregister` then `register`, which never enters
RESERVED. But `renew` on an already-unregistered entry needs only root `ROLE_RENEW`, which the Oracle
holds to perform renewals. That lands the TLD in RESERVED, where `UNREGISTER` does nothing.

The Oracle therefore refuses to renew an entry whose status is not REGISTERED. The stranded state is
unreachable rather than recoverable, and the authority the Oracle asks for stays at two grants: root
`REGISTRAR`, and entry-scoped `UNREGISTER`.

## Notes

- These are `bun:test` end-to-end tests driving a devnet, not Foundry. `forge test` does not reach
  them. The runner is `bun test`, preloaded by `bunfig.toml`.
- A delegate that sends a transaction must be a devnet signer. The named accounts are `deployer`,
  `owner`, `user`, `user2` and `nameOwner`.
- Compare addresses with the `toEqualAddress` matcher. `getSubregistry` returns a checksummed
  address and `.address` does not, so `toBe` fails on case alone.
