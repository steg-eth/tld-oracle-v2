# TLD Oracle v2

<p align="center"><img src=".github/steggy-wip.gif" width="100%" alt="Steggy, the Steg mascot, holding a sign: WIP, spec coming soon"></p>

## Design intent

The TLD Oracle is a registrar for top-level domains (TLDs) in ENSv2. Purpose: let a registry operator self-assign the ENS node for its TLD with a DNSSEC proof, without a governance vote for each assignment.

The Oracle has four functions: 

1. Verifies the proof against the DNSSEC verifier.
2. It holds the assignment request for a fixed period, and the DAO can veto during that period.
3. It then promotes the reserved TLD entry in the root registry to the operator.
4. And when DNS shows a new operator, it follows: it repoints the entry on a fresh proof.

The Oracle doesn't get to decide who the operator is. DNS is the authority, at the assignment and after it. This follows the TSG's rule that the controlling entity of the TLD in ENS "MUST be the registry operator of the TLD" ([TSG §4.2, p. 9](https://itp.cdn.icann.org/en/files/generic-top-level-domains-gtlds/tsg-gtld-integrations-with-alternative-naming-systems-initial-report-10-08-2026-en.pdf#page=9)), and the Foundation's reading that "the DNSSEC proof is the controller proof" ([Foundation §III](https://www.icann.org/en/public-comment/proceeding/initial-report-of-the-tsg-on-gtld-integrations-with-alternative-naming-systems-10-08-2026/submissions/ens-foundation-21-09-2026)). 

The permission envelope of a TLD, its [role bitmap](https://github.com/ensdomains/contracts-v2/blob/62778d80038e50cb23514eab1b7d66ceb8a41e1c/contracts/src/registry/libraries/RegistryRolesLib.sol), is set once, when the entry is promoted ([PermissionedRegistry.register](https://github.com/ensdomains/contracts-v2/blob/62778d80038e50cb23514eab1b7d66ceb8a41e1c/contracts/src/registry/PermissionedRegistry.sol#L472-L506)). 

Importantly, the root cannot change it later.

The TSG requires the operator to "provide all relevant control guarantees … such that the alt-name cannot drift" ([TSG §4.6, p. 11](https://itp.cdn.icann.org/en/files/generic-top-level-domains-gtlds/tsg-gtld-integrations-with-alternative-naming-systems-initial-report-10-08-2026-en.pdf#page=11)). The Foundation asks for architectures "that let any party confirm the integration state directly" ([Foundation §IV](https://www.icann.org/en/public-comment/proceeding/initial-report-of-the-tsg-on-gtld-integrations-with-alternative-naming-systems-10-08-2026/submissions/ens-foundation-21-09-2026)). TLD Oracle maintains the minimum right it needs to follow DNS, nothing more. Which right that is, and who holds the TLD's token, is the first decision this repository makes. The DAO sets the policy, it doesn't change the rules.

## The v1 Oracle

The v1 Oracle was built against ENSv1 on two parts that ENS already runs. It verifies proofs with `DNSSECOracle`, a contract based on the ENS DNSSEC oracle `DNSSECImpl` and adapted for the P-256 precompile, through the same `verifyRRSet` call. It assigns the TLD as a controller of the ENS Root, with `setSubnodeOwner`. `DNSRegistrar` uses the same oracle and the same Root for second-level imports. The v1 Oracle stands beside it as a registrar for TLDs. It is not a fork of it. The assignment rules differ: a TLD-specific record at `_ens.nic.<tld>`, an allowlist, and a two-step assignment with a veto window. `DNSRegistrar` claims in one call. A live demo is at [dnssec.steg.eth.link/tld-oracle/](https://dnssec.steg.eth.link/tld-oracle/).

The contracts, tests and demo are in `[steg-eth/dnssec-solutions](https://github.com/steg-eth/dnssec-solutions)` under `TLD-oracle/`, beside the DNSSEC demonstrations they grew out of (gasless resolution, on-chain import, DNS claiming). The Oracle was put to the DAO twice: the [RFC](https://discuss.ens.domains/t/rfc-a-programmable-fast-path-for-tld-assignment/21859) (January 2026) and the [Temp Check](https://discuss.ens.domains/t/temp-check-authorize-tldminter-as-root-controller/22020) (April–May). The Temp Check ended on a two-phase design: each assignment request commits a policy hash, and a review window gates execution.

## Proof of Work

Two test suites verify the v1 contract. Find them here: [dnssec-solutions/TLD-oracle/test](https://github.com/steg-eth/dnssec-solutions/tree/master/TLD-oracle/test).

`TLDMinterAllowlist.t.sol` has 6 tests. They show that:

- the allowlist rejects a TLD that is not listed;
- only the DAO can add or remove a TLD;
- a removed TLD is rejected again.

`TLDMinterLifecycle.t.sol` has 16 tests. They show that:

- the full assignment runs: submit, wait, execute;
- the DAO and the Security Council can veto an assignment request, and no other account can;
- execution before the timelock fails;
- a duplicate request fails;
- a proof older than 14 days fails;
- the rate limit and the pause stop a request.

Two more test files come from the proposal package. Reference copies are in [`reference/v1/proposal`](reference/v1/proposal).

`calldataCheck.t.sol` runs on a fork of Ethereum mainnet. It sends the real proposal calldata through the ENS Governor and Timelock. It then checks that:

- the Root authorizes the contract;
- the allowlist holds all 1,166 TLDs;
- the contract reports version 2.0.0.

`ClaimSimulation.t.sol` has 4 tests and uses mocks. They run:

- the assignment lifecycle;
- both vetoes;
- an execution that is too early.

The contract runs on Sepolia. `TLDMinter` is at `0x48729B7e0bA736123a57c4B6A492BDAbedAF980F`. The verifier is at `0x31D1acba033d8A4Ab3f6334355289034d32cFD89`. Two transactions show an assignment end to end: [submitClaim](https://sepolia.etherscan.io/tx/0xe76d7ded41fd286cbfded251bebcf2ca8c5db1e18e5baccd15d701a82323e785) and [execute](https://sepolia.etherscan.io/tx/0x99998721d5e108f11c8e695e0543e5c2473f09d2fe6a04005dd51e4d329e9ec9). 

The timelock on Sepolia is 15 minutes. On mainnet it is 7 days.

## Limitations

The Sepolia deployment and the tests use a mock Root (`MockRoot`, `0x32cF38Af3c54c5D0C5305F48b6E2dE9f5191226d`). The `IRoot` interface in the contract declares a return value. The deployed ENS Root does not return one. As a result, `execute()` as shipped reverts against the real Root. 

The tests didn't find this, because the mock was written from the interface. The policy and the lifecycle are proven. The final write to the real Root isn't. The fix is one line in the interface. We didn't deploy it because we're shifting attention towards deployment on v2. 

The root KSK rolled to key tag 38696 on 11 October 2026. The Sepolia verifier was re-anchored on [12 October](https://sepolia.etherscan.io/tx/0xe7dcabae6342f63c1f1c55a471ff4b291aae07bcb2f5f06b6b94fbad1c3e2394). On 13 October a [transaction](https://sepolia.etherscan.io/tx/0x89d075f3dea283e4203228399662154c3eee3ee538a0b547eae5b4ced18a85af) sent a live proof from the ENS gateway through `verifyRRSet`, and the verifier accepted it. The ENS mainnet verifier waits on [#572](https://github.com/ensdomains/ens-contracts/pull/572).

## v1 to v2


|                            | v1 (as posted)                                                                                          | v2 (this repository)                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| -------------------------- | ------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Target                     | ENS Root. `setSubnodeOwner` as a Root controller.                                                       | ENSv2 root registry. `register` promotes the reserved TLD entry.                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Authority to act           | DAO proposal: `Root.setController(tldMinter)`.                                                          | DAO grants `REGISTER_RESERVED` on the root. The DAO receives this role at the [phase-8 handover](https://github.com/ensdomains/contracts-v2/blob/5079ac1cba2635bce8840bb43645105c20a5cbc5/contracts/docs/migration.md#phase-8-hand-the-registries-over) ([#465](https://github.com/ensdomains/contracts-v2/pull/465)).                                                                                                                                                                        |
| What the operator receives | A registry node. The owner sets its resolver and subnodes.                                              | An ERC-1155 token, a permission envelope, and a subregistry pointer. All three are set at promotion.                                                                                                                                                                                                                                                                                                                                                                                          |
| Correction after the fact  | The DAO can reassign the node through the Root ([EP 6.7](https://docs.ens.domains/dao/proposals/6.7/)). | None at the root. The envelope is set once.                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Operator change            | The DAO reassigns the node.                                                                             | After promotion, only the entry's own roles can change it. `SET_SUBREGISTRY` repoints it. `CAN_TRANSFER_ADMIN` transfers the token, and the roles move with it. `UNREGISTER` removes it. The root holds none of these. Which of them the Oracle uses to follow DNS, and who holds it, is Decision 2.                                                                                                                                                                                          |
| Eligibility                | Allowlist of 1,166 post-2012 gTLDs.                                                                     | Every public-suffix TLD is already reserved in the root. The allowlist narrows to proof policy (Decision 1).                                                                                                                                                                                                                                                                                                                                                                                  |
| Proof record               | `_ens.nic.<tld>` TXT `a=0x…`.                                                                           | `_ens.nic.<tld>`, the apex `_ens.<tld>` as [#419](https://github.com/ensdomains/contracts-v2/pull/419) reads it, or both (Decision 1).                                                                                                                                                                                                                                                                                                                                                        |
| Verifier                   | ENS `DNSSECImpl` `0x0fc3…`. No anchor update.                                                           | [#572](https://github.com/ensdomains/ens-contracts/pull/572)'s `DNSSECImpl` with `setAnchors`. The [executable](https://discuss.ens.domains/t/executable-upgrade-dnssec-oracle-and-registrar-fro-the-2026-root-ksk-rollover/22497) gives it to the DAO timelock. Whether the Oracle binds it, or its own: Decision 3.                                                                                                                                                                                                                                                                                                                                                                       |
| Assignment flow            | Submit, timelock with veto, execute.                                                                    | The same two steps. The review window is the only checkpoint.                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Proof freshness            | 14-day maximum proof age.                                                                               | Monotonic inception, as #419 and #572 do.                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Policy                     | 7-day timelock. 10 assignments per 7 days. 14-day proof age. Pause. Security Council veto.              | Carried over. The Security Council mandate is to be re-verified.                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `.eth`                     | `Root.locked["eth"]`.                                                                                   | The `eth` entry is already registered in the ENSv2 root, so the Oracle cannot promote it: `register` reverts with `LabelAlreadyRegistered`. The deployer holds the `eth` token today. At the [phase-8 handover](https://github.com/ensdomains/contracts-v2/blob/5079ac1cba2635bce8840bb43645105c20a5cbc5/contracts/docs/migration.md#phase-8-hand-the-registries-over) the token moves to the ENS DAO name-owner Safe with every role.                                                        |
| Timing                     | One 9-day governance cycle.                                                                             | Two events must happen first. The DAO executes the ENSv2 activation proposal ([t/22483](https://discuss.ens.domains/t/executable-activate-ensv2/22483), a draft today). Then the deployer runs the [phase-8 handover](https://github.com/ensdomains/contracts-v2/blob/5079ac1cba2635bce8840bb43645105c20a5cbc5/contracts/docs/migration.md#phase-8-hand-the-registries-over), which gives the DAO the root roles, `REGISTER_RESERVED` among them. Only then can the DAO authorize the Oracle. |




## Provenance

We started our design exploration with proofs, specifically updating how ENS verifies DNSSEC algorithm 13. [ens-contracts #509](https://github.com/ensdomains/ens-contracts/pull/509) (merged January 2026) moved that verification from a Solidity elliptic-curve library to the EIP-7951 P-256 precompile. A [census](https://github.com/estmcmxci/algo13-study) then measured the effect at protocol scale. One verification fell from 1.34M gas to 10.5K. Eligible imports saved 1.12B gas in total. Cheap verification made TLD-level assignment practical. The Oracle is the next step. ENS Labs told that story in [CitizENS 001](https://ens.domains/blog/post/citizens-marcus-dns-imports).

## Why now

TLD Oracle v1 asked who controls a Root node. v2 asks what a TLD is promoted with, and who holds it. Promotion sets those bits once. This repository decides them.

Five things happened in the same quarter:

1. **ENSv2 goes live soon.** nick.eth drafted the activation proposal for a DAO vote ([t/22483](https://discuss.ens.domains/t/executable-activate-ensv2/22483)). The ENSv2 root registry already holds every public-suffix TLD as a reserved entry. Each entry waits for an owner.
2. **ICANN is evaluating the 2026 gTLD round.** It closed the application window on 12 August 2026.
3. **ICANN wrote a draft rulebook for exactly this.** Its Technical Study Group published an [initial report](https://itp.cdn.icann.org/en/files/generic-top-level-domains-gtlds/tsg-gtld-integrations-with-alternative-naming-systems-initial-report-10-08-2026-en.pdf) on how a gTLD can integrate with an alternative naming system.
4. **The ENS Foundation answered it, and so did we.** The Foundation's [comment](https://www.icann.org/en/public-comment/proceeding/initial-report-of-the-tsg-on-gtld-integrations-with-alternative-naming-systems-10-08-2026/submissions/ens-foundation-21-09-2026) (21 September 2026) asks ICANN to "recognize public verifiability of blockchain-based naming systems as an assurance factor". [Our comment](https://www.icann.org/en/public-comment/proceeding/initial-report-of-the-tsg-on-gtld-integrations-with-alternative-naming-systems-10-08-2026/submissions/estmcmxcieth-21-09-2026) (estmcmxci.eth, 21 September 2026) submitted the v1 Oracle as one way to meet the report's TLD-level requirements in §4.2, §4.6 and §10, and said the binding should be re-established when operator control changes.
5. **The DNS root changed its key.** On 11 October the root rolled its key-signing key to tag 38696. Every on-chain DNSSEC verifier that anchors on the old key stopped accepting fresh proofs. ENS wrote its remedy in [ens-contracts #572](https://github.com/ensdomains/ens-contracts/pull/572). We re-anchored the Sepolia verifier the next day.

Alexander Urbelis [wrote](https://x.com/aurbelis/status/2110015700689420532) on 13 October that ENSv2 strengthens what a name can do "across chains and the DNS alike. The convergence is coming."

This repository is the ENSv2 half of that convergence. It is the contract and the policy that let a registry operator take its TLD's position in ENS, on evidence that ICANN and the DAO can both check.

## Upstream PRs We Are Tracking

Four pull requests set the terms that the v2 Oracle must meet. The table gives each one and why it matters here.


| Pull request                                                               | What it is                                                                                   | Why it matters for the Oracle                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | State                |
| -------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------- |
| [contracts-v2 #465](https://github.com/ensdomains/contracts-v2/pull/465)   | The ENSv2 mainnet deployment and the DAO handover.                                           | The DAO receives `REGISTER_RESERVED` on the root at the [phase-8 handover](https://github.com/ensdomains/contracts-v2/blob/5079ac1cba2635bce8840bb43645105c20a5cbc5/contracts/docs/migration.md#phase-8-hand-the-registries-over), with its admin role. It can "give a reserved one, such as a DNS top-level name, to its operator" and authorize registrars. That is the Oracle's entry point. The PR replaced the live root on 13 October 2026, so every address changed once more. The new `DNSTLDResolver` still binds the old verifier. | Draft                |
| [contracts-v2 #419](https://github.com/ensdomains/contracts-v2/pull/419)   | The ENS DNS claiming contract for v2, `DNSRegistrar`.                                        | It claims any name under a public suffix from an `_ens.<name>` record. It registers the name with all roles to the address in the record. It keeps registry-wide roles on the temporary registries it creates, so below a TLD it can replace a claim on a fresher proof. At the root it cannot, because no account can hold `UNREGISTER` there. Whether TLD claims belong in it is an open question on the PR. The answer decides whether the Oracle stands beside it or inside it.                                                          | Draft                |
| [ens-contracts #572](https://github.com/ensdomains/ens-contracts/pull/572) | A new v1 `DNSSECImpl` with `setAnchors`, and a new `DNSRegistrar` and `OffchainDNSResolver`. | It is the ENS remedy for the 2026 root key rollover. It is the verifier the Oracle should bind to. It also re-points every v1 TLD node to the new resolver.                                                                                                                                                                                                                                                                                                                                                                                  | Merged 15 Oct 2026   |
| [contracts-v2 #471](https://github.com/ensdomains/contracts-v2/pull/471)   | A bump of the `ens-contracts` submodule in `contracts-v2`.                                   | It brings the #572 verifier into the v2 `DNSTLDResolver`. It is the point where the v1 fix and the v2 deployment meet. ENSv2 now builds on a verifier that can be re-anchored. | Merged 16 Oct 2026   |




## The decisions

| | What we decide | Can it change later? |
|---|---|---|
| 1. Proof location | Which DNS record proves control of a TLD: `_ens.nic.<tld>`, the apex `_ens.<tld>`, or both. | Yes. A new Oracle deployment reads a different record. |
| 2. Promotion envelope and the holder | Which roles the TLD entry gets at promotion — `CAN_TRANSFER_ADMIN`, `SET_SUBREGISTRY`, `UNREGISTER` — and who holds its token: the operator, the Oracle, or a third party. | No. Promotion sets them once. No root role reaches a registered entry, so only the holder of the entry's own admin roles can change them afterwards. |
| 3. The verifier | Which contract verifies the proofs — the ENS verifier from #572 or one the Oracle deploys — and who can update its trust anchors. | Yes. A new Oracle deployment binds a different verifier. |

### 1. Proof location

Which DNS record proves control of a TLD? Option A uses `_ens.nic.<tld>`, the v1 record. ICANN reserves the `nic` label for the operator only in post-2012 gTLDs, so this option needs an allowlist. Option B uses the apex record `_ens.<tld>`, the record that #419 reads. Only the zone operator can place it, so it needs no allowlist. Option C uses both. This choice decides which TLDs are eligible and whether the allowlist survives.

### 2. Promotion envelope and the holder

Who holds the token after promotion, and with which roles? When the Oracle promotes a TLD, it sets the entry's roles and gives the token to one account. Three roles matter. `CAN_TRANSFER_ADMIN` lets the holder transfer the token, and the roles move with it. `SET_SUBREGISTRY` lets the holder repoint the entry to a new registry. `UNREGISTER` lets the holder remove the entry. The token can go to the operator, to the Oracle, or to a third party. The root cannot change any of this later.

#419 shows one shape: the registrar owns the parent registry, and the operator owns the entry with all roles. That shape works below a TLD. At the root the registrar cannot own the parent. Decision 2 picks what replaces it at TLD level: the operator holds the entry, or the Oracle holds it and delegates. This choice decides whether DNS can still move a TLD after promotion, and what happens when an operator stops.

Below a TLD this self-corrects. #419's `claim` reads the owner from the DNS record on every call and overwrites the entry, so a fresh proof moves the name to the current DNS owner. Anyone can submit the proof, because the owner comes from the record, not the sender. At the root there is no such path. Promotion sets the entry once, and no root role reaches it afterwards, so DNS cannot move a promoted TLD unless Decision 2 gives the entry a role that lets its holder act. This is the asymmetry the decision resolves: a 2LD follows DNS on its own; a TLD follows DNS only through whoever holds the entry.

ENS set a precedent for the holder at the root. In the ENSv2 migration the `.eth` token first sat with the endowment. A calldata review flagged that this placed it under Foundation control, and the ENS DAO meta-governance call recorded the change: the token now goes to a [1-of-1 Safe](https://etherscan.io/address/0x5B716D6587d241166bC8914858640F8684F3A2F3) whose only owner is the DAO timelock, with the endowment kept as the fee beneficiary alone. For Decision 2 this sets the holder when the operator does not hold a TLD: a Safe under the DAO timelock, not the endowment. The same [executable](https://discuss.ens.domains/t/executable-upgrade-dnssec-oracle-and-registrar-fro-the-2026-root-ksk-rollover/22497) shows the pattern in use: the DAO authorizes a contract that checks DNS ownership as a root controller, and removes the previous one in the same proposal. The power is narrow and it is revocable.

The role model splits each power in two. `ROLE_SET_SUBREGISTRY` repoints the entry. `ROLE_SET_SUBREGISTRY_ADMIN`, the same bit shifted by 128, decides who can grant or withdraw it, and `grantRoles` and `revokeRoles` act on one entry at a time. So the question is not only whether the operator or the Oracle can repoint a TLD, but which of them holds the admin bit. If the operator holds the entry and grants the Oracle the power to repoint, the operator keeps the admin bit and can take it back. If the Oracle holds the entry, a fresh proof repoints the subregistry with no act by the outgoing operator. That is what #419 already does one level down: `_claim` grants the registrar all roles on each temporary registry it deploys, so a newer proof overwrites the claim.

The Oracle holding the entry is the better default. It is the only arrangement that reproduces that behavior at the root, where no root role reaches a registered entry. The cost is real. The operator cannot transfer or unregister the TLD alone, and the Oracle mediates. That cost fits the level, because a gTLD is reassigned by ICANN, not by its operator. Decision 2 can still give the entry to the operator, but it must then accept that a TLD stops following DNS as soon as its operator stops cooperating.

### 3. The verifier

Which contract verifies the proofs, and who can update its trust anchors? Option A uses the ENS verifier from #572. The [executable](https://discuss.ens.domains/t/executable-upgrade-dnssec-oracle-and-registrar-fro-the-2026-root-ksk-rollover/22497) deploys it with `setAnchors` and transfers ownership to the DAO timelock `0xFe89…44b7`, so the DAO re-anchors it at each rollover. Option B uses a verifier that the Oracle deploys, and a multisig or the DAO owns it. The root key rolls. A verifier that nobody can update stops accepting proofs. A verifier that one key can update is a single point of failure. Two updates matter here, and they are not the same. A swap to a different verifier contract needs a redeploy, because #419 and `DNSTLDResolver` bind the verifier as an immutable. An update to the trust anchors inside the bound verifier does not: #578 gives `DNSSECImpl` a `setAnchors`, so its owner re-anchors it in place at each rollover. A verifier without `setAnchors` forces a redeploy at every rollover. One with it needs only an owner who acts. So the choice is not only which verifier, but whether it can be re-anchored, and who holds that key. This choice decides who must act at the next rollover.

