/**
 * What can a RESERVED entry hold, and what survives a revive of one?
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

describe("reserved entries", () => {
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

  /** Run `fn`, return the revert name or "ok". Records instead of asserting, so
   *  one surprise does not hide the rest of the picture. */
  const outcome = async (fn: () => Promise<unknown>) => {
    try {
      await fn();
      return "ok";
    } catch (e) {
      const m = String((e as Error).message ?? e);
      const named = m.match(/[A-Z][A-Za-z]+\(/);
      return named ? named[0].slice(0, -1) : m.slice(0, 90);
    }
  };

  it(
    "a reservation cannot hold roles, and what a revive of one leaves behind",
    async () => {
      await handOver();
      const RESOLVER = getAddress("0x965e1ec7510e9FeDE8f754a6e8662E068C770388");
      const SUBREGISTRY = getAddress(env.v2.ETHRegistry.address);
      const future = BigInt(Math.floor(Date.now() / 1000) + 365 * 24 * 3600);

      // 1. Reserve with roles.
      const withRoles = await outcome(() =>
        env.v2.RootRegistry.write.register(
          ["reservedroles", zeroAddress, zeroAddress, zeroAddress,
           ROLES.REGISTRY.SET_RESOLVER, future],
          asOwner(),
        ),
      );

      // 2. Reserve without roles, but with settings.
      const TLD = "reserved";
      const plain = await outcome(() =>
        env.v2.RootRegistry.write.register(
          [TLD, zeroAddress, SUBREGISTRY, RESOLVER, 0n, future],
          asOwner(),
        ),
      );
      const id = idFromLabel(TLD);
      const resource0 = await resourceOf(TLD);

      // 3. Grant a role on the reservation, from the root holder and the Safe.
      const grantAsOwner = await outcome(() =>
        env.v2.RootRegistry.write.grantRoles(
          [resource0, ROLES.REGISTRY.SET_RESOLVER, intermediary()],
          asOwner(),
        ),
      );
      const grantAsSafe = await outcome(() =>
        env.v2.RootRegistry.write.grantRoles(
          [resource0, ROLES.REGISTRY.SET_RESOLVER, intermediary()],
          asNameOwner(),
        ),
      );

      // 4. Can anyone remove a reservation after the handover?
      const unregAsOwner = await outcome(() =>
        env.v2.RootRegistry.write.unregister([id], asOwner()),
      );
      const unregAsSafe = await outcome(() =>
        env.v2.RootRegistry.write.unregister([id], asNameOwner()),
      );

      const before = {
        reserveWithRoles: withRoles,
        reservePlain: plain,
        statusAfterReserve: await env.v2.RootRegistry.read.getStatus([id]),
        resolverOnReservation: await env.v2.RootRegistry.read.getResolver([TLD]),
        subregistryOnReservation:
          await env.v2.RootRegistry.read.getSubregistry([TLD]),
        rolesOnReservation: (
          await env.v2.RootRegistry.read.roles([resource0, intermediary()])
        ).toString(),
        grantAsRootHolder: grantAsOwner,
        grantAsSafe: grantAsSafe,
        unregisterAsRootHolder: unregAsOwner,
        unregisterAsSafe: unregAsSafe,
      };
      console.log("RESERVED " + JSON.stringify(before));

      // 5. If it was removable, revive it and read everything again.
      const removed =
        unregAsOwner === "ok" || unregAsSafe === "ok";
      if (removed) {
        const revive = await outcome(() =>
          env.v2.RootRegistry.write.renew([id, MAX_EXPIRY], asOwner()),
        );
        const resource1 = await resourceOf(TLD);
        console.log(
          "REVIVED " +
            JSON.stringify({
              revive,
              resourceChanged: resource1 !== resource0,
              status: await env.v2.RootRegistry.read.getStatus([id]),
              resolver: await env.v2.RootRegistry.read.getResolver([TLD]),
              subregistry: await env.v2.RootRegistry.read.getSubregistry([TLD]),
              rolesOnNewResource: (
                await env.v2.RootRegistry.read.roles([
                  resource1,
                  intermediary(),
                ])
              ).toString(),
            }),
        );
      } else {
        console.log("REVIVED {\"skipped\":\"reservation not removable\"}");
      }

      // The one claim strong enough to assert: a reservation holds no roles.
      expect(before.rolesOnReservation).toBe("0");
    },
    TEST_TIMEOUT_MS,
  );
});
