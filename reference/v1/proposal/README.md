# v1 proposal tests

Reference copies of the two test files from the v1 DAO proposal package. They are here so the claims in the main README can be read against the code. They do not build in this repository: their imports point at the proposal package and at ENS v1 contracts.

| File | What it checks |
|---|---|
| `calldataCheck.t.sol` | Runs the real proposal calldata through the ENS Governor and Timelock on a fork of Ethereum mainnet, then checks Root authorization, the 1,166-entry allowlist, and `version()`. |
| `ClaimSimulation.t.sol` | Four lifecycle scenarios on mocks: submit, timelock, execute, veto. |
