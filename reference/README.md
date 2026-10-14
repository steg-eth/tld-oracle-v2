# Reference pins

This folder records the upstream commits that the README and the spec cite. The code is not in this repository. Steg mirrors each commit in its own fork, so it survives a force-push or a deleted branch upstream.

`UPSTREAM.lock` is tab-separated: upstream repo, ref, commit, mirror branch or tag, note.

| Upstream | Ref | Commit | Mirror |
|---|---|---|---|
| ensdomains/contracts-v2 | PR #465 head | `5079ac1c` | `steg-eth/contracts-v2` branch `pin/pr465-5079ac1c` |
| ensdomains/contracts-v2 | PR #453 head | `ed37923e` | `steg-eth/contracts-v2` branch `pin/pr453-ed37923e` |
| ensdomains/contracts-v2 | PR #419 head | `3690d94` | `steg-eth/contracts-v2` branch `pin/pr419-3690d94` |
| ensdomains/ens-contracts | PR #572 head | `ebd1ce5b` | `steg-eth/ens-contracts` branch `pin/pr572-ebd1ce5b` |
| ensdomains/ens-contracts | tag `v1.7.0` | `9b034936` | `steg-eth/ens-contracts` branch `pin/v1.7.0-9b034936` |
| ensdomains/dnsprovejs | tag `v1.0.1` | `797afc5a` | `steg-eth/dnsprovejs` tag `v1.0.1` |

## Fetch a pin

```sh
git clone --depth 1 --branch pin/pr465-5079ac1c https://github.com/steg-eth/contracts-v2 reference/contracts-v2
git clone --depth 1 --branch pin/pr572-ebd1ce5b https://github.com/steg-eth/ens-contracts reference/ens-contracts
git clone --depth 1 --branch v1.0.1 https://github.com/steg-eth/dnsprovejs reference/dnsprovejs
```

Git ignores these clones. Do not commit them.

## Check the pins

```sh
scripts/check-upstream.sh
```

The script compares each pin with the live ref upstream. It exits 1 when a pin has moved or its ref is gone. It only reads.

## Mirrors

- `steg-eth/contracts-v2`: `main` follows upstream `main`. A scheduled workflow on the `steg` branch fast-forwards it every six hours and copies tags. `pin/*` branches are frozen.
- `steg-eth/ens-contracts`: `pin/*` branches are frozen. `staging` is Steg's own branch from PR #509.
- `steg-eth/dnsprovejs`: tags as upstream.
