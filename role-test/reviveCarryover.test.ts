/**
 * What survives an unregister-then-renew (revive) on a root entry?
 *
 * ensdomains/contracts-v2 #501 clears `resolver` and `subregistry` on unregister.
 * This asserts the whole entry, not those two fields: the resource id, a prior
 * delegate's roles, the settings, the owner and the status.
 *
 * Why it matters here: the TLD lifecycle ends by returning the token to the Safe,
 * and the next operator claims it. That assumes the name comes back clean. This
 * states what "clean" is, in code, at #501's head and at its base.
 */
import { describe, expect, it } from "bun:test";
import { getAddress, zeroAddress } from "viem";

import {
  DANGEROUS_ROOT_ROLES,
  DEPLOYMENT_ROLES,
  MAX_EXPIRY,
  ROLES,
  STATUS,
} from "../../script/deploy-constants.js";
import { handOverRegistryAdmin } from "../../script/migrate.js";
import { writeDeploymentNamespace } from "../utils/deploymentArtifacts.js";
import { idFromLabel } from "../utils/utils.js";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TEST_TIMEOUT_MS = 120_000;
const NETWORK = "mainnet";
const NAMESPACE = "mainnet";

describe("revive carryover", () => {
  const { env, setupEnv } = process.TEST_GLOBALS!;
  const workDir = mkdtempSync(join(tmpdir(), "claim-succession-"));
  const deploymentsDir = join(workDir, "v2");

  setupEnv({ resetOnEach: true });

  const deployer = () => getAddress(env.namedAccounts.deployer.address);
  const owner = () => getAddress(env.namedAccounts.owner.address);
  const nameOwner = () => getAddress(env.namedAccounts.nameOwner.address);

  function context() {
    rmSync(deploymentsDir, { recursive: true, force: true });
    writeDeploymentNamespace(
      deploymentsDir,
      NAMESPACE,
      (
        [
          "RootRegistry",
          "ETHRegistry",
          "ETHRegistrar",
          "BatchRegistrar",
          "RootBatchRegistrar",
        ] as const
      ).flatMap((name) => {
        const deployment = env.rocketh.deployments[name];
        return deployment ? [[name, deployment] as const] : [];
      }),
    );
    return {
      network: NETWORK,
      rpcUrl: `http://${env.hostPort}`,
      chainId: "1",
      deploymentsDir,
      deploymentNetwork: NAMESPACE,
      owner: owner(),
      nameOwner: nameOwner(),
    } as const;
  }

  const handOver = () =>
    handOverRegistryAdmin({
      ...context(),
      deployer: deployer(),
      impersonateAccount: deployer(),
    });

  const asOwner = () => ({ account: env.namedAccounts.owner });
  const asNameOwner = () => ({ account: env.namedAccounts.nameOwner });

  // The Safe is `nameOwner`, as in the #486 test. The intermediary stand-in and
  // the operators are the remaining devnet signers, because a role holder that
  // has to send a transaction must be one.
  const asIntermediary = () => ({ account: env.namedAccounts.user });
  const intermediary = () => getAddress(env.namedAccounts.user.address);
  const asOperator = () => ({ account: env.namedAccounts.user2 });
  const operator = () => getAddress(env.namedAccounts.user2.address);

  /** Register a TLD the way `TemporaryDNSRegistrar.syncTLD` does: to the Safe,
   *  with ROOT_NAME_TOKEN, at MAX_EXPIRY. */
  const sweep = (label: string, holder = nameOwner()) =>
    env.v2.RootRegistry.write.register(
      [
        label,
        holder,
        zeroAddress,
        zeroAddress,
        DEPLOYMENT_ROLES.ROOT_NAME_TOKEN,
        MAX_EXPIRY,
      ],
      asOwner(),
    );

  const resourceOf = (label: string) =>
    env.v2.RootRegistry.read.getResource([idFromLabel(label)]);

  it(
    "unregister then renew: the resource regenerates and nothing of the prior operator survives",
    async () => {
      await handOver();
      const TLD = "revived";
      await sweep(TLD);

      const id = idFromLabel(TLD);
      const resource0 = await resourceOf(TLD);
      const tokenId0 = await env.v2.RootRegistry.read.getTokenId([id]);

      // The holder delegates repointing, and the name carries real settings.
      const RESOLVER = getAddress("0x965e1ec7510e9FeDE8f754a6e8662E068C770388");
      const SUBREGISTRY = getAddress(env.v2.ETHRegistry.address);
      await env.v2.RootRegistry.write.grantRoles(
        [resource0, ROLES.REGISTRY.SET_RESOLVER, intermediary()],
        asNameOwner(),
      );
      await env.v2.RootRegistry.write.setResolver([id, RESOLVER], asNameOwner());
      await env.v2.RootRegistry.write.setSubregistry(
        [id, SUBREGISTRY],
        asNameOwner(),
      );

      // Positive controls: the state exists before it is removed.
      expect(
        await env.v2.RootRegistry.read.roles([resource0, intermediary()]),
      ).toBe(ROLES.REGISTRY.SET_RESOLVER);
      expect(await env.v2.RootRegistry.read.getResolver([TLD])).toEqualAddress(
        RESOLVER,
      );
      expect(
        await env.v2.RootRegistry.read.getSubregistry([TLD]),
      ).toEqualAddress(SUBREGISTRY);

      // The lapse, then the revive.
      await env.v2.RootRegistry.write.unregister([id], asNameOwner());
      expect(await env.v2.RootRegistry.read.getStatus([id])).toBe(
        STATUS.AVAILABLE,
      );
      await env.v2.RootRegistry.write.renew([id, MAX_EXPIRY], asOwner());

      const resource1 = await resourceOf(TLD);
      const tokenId1 = await env.v2.RootRegistry.read.getTokenId([id]);
      const observed = {
        status: await env.v2.RootRegistry.read.getStatus([id]),
        resourceChanged: resource1 !== resource0,
        tokenIdChanged: tokenId1 !== tokenId0,
        rolesOnNewResource: (
          await env.v2.RootRegistry.read.roles([resource1, intermediary()])
        ).toString(),
        rolesStillOnOldResource: (
          await env.v2.RootRegistry.read.roles([resource0, intermediary()])
        ).toString(),
        resolver: await env.v2.RootRegistry.read.getResolver([TLD]),
        subregistry: await env.v2.RootRegistry.read.getSubregistry([TLD]),
        owner: await env.v2.RootRegistry.read.findOwner([TLD]),
      };
      console.log("OBSERVED " + JSON.stringify(observed));


      // Step 5 of the lifecycle: can the Safe get a revived (RESERVED) TLD back?
      // A reservation cannot be unregistered, so the only way out is to register
      // over it, which needs root REGISTER_RESERVED.
      const recover = await (async () => {
        try {
          await env.v2.RootRegistry.write.register(
            [TLD, nameOwner(), zeroAddress, zeroAddress,
             DEPLOYMENT_ROLES.ROOT_NAME_TOKEN, MAX_EXPIRY],
            asOwner(),
          );
          return "ok";
        } catch (e) {
          const m = String((e as Error).message ?? e);
          const n = m.match(/[A-Z][A-Za-z]+\(/);
          return n ? n[0].slice(0, -1) : m.slice(0, 90);
        }
      })();
      console.log(
        "RECOVER " +
          JSON.stringify({
            register: recover,
            status: await env.v2.RootRegistry.read.getStatus([id]),
            owner: await env.v2.RootRegistry.read.findOwner([TLD]),
          }),
      );

      // The revive leaves a reservation: alive, ownerless.
      expect(observed.status).toBe(STATUS.RESERVED);
      expect(observed.owner).toEqualAddress(zeroAddress);

      // Nothing of the prior operator reaches the revived entry.
      expect(observed.resourceChanged).toBe(true);
      expect(observed.rolesOnNewResource).toBe("0");
      expect(observed.resolver).toEqualAddress(zeroAddress);
      expect(observed.subregistry).toEqualAddress(zeroAddress);
    },
    TEST_TIMEOUT_MS,
  );
});
