/**
 * Root authority after the registry handover.
 *
 * Rebuilds the assertions first run on 18 October 2026, whose only copy lived in
 * /private/tmp and was removed by the OS tmp reaper on 23 October. The findings
 * survived as prose in THOUGHT-PROVENANCE.md (18 Oct) and ROOT-ROLE-TAXONOMY.md §4.
 * This file is the durable version.
 *
 * It extends the upstream `registryHandover` fixture rather than replacing it.
 * Upstream proves the handover moves the right bitmaps. This proves what the
 * holder of the safe set can and cannot then do to a registered entry, which is
 * the question the TLD Oracle's authority model turns on.
 *
 * Each test states the claim it is evidence for.
 */
import { describe, expect, it } from "bun:test";
import { getAddress, type Address } from "viem";

import {
  DANGEROUS_ROOT_ROLES,
  DEPLOYMENT_ROLES,
  ROLES,
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
const ROOT_RESOURCE = 0n;
const STRANGER = getAddress("0x000000000000000000000000000000000000beef");

describe("root authority after handover", () => {
  const { env, setupEnv } = process.TEST_GLOBALS!;
  const workDir = mkdtempSync(join(tmpdir(), "root-authority-"));
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

  const ethId = () => idFromLabel("eth");
  const ethResource = () => env.v2.RootRegistry.read.getResource([ethId()]);
  const asOwner = () => ({ account: env.namedAccounts.owner });
  const asNameOwner = () => ({ account: env.namedAccounts.nameOwner });

  // Every role in the safe set, split into its regular and admin halves, so the
  // self-grant test covers the whole surface rather than a sample.
  const DANGEROUS: ReadonlyArray<readonly [string, bigint]> = [
    ["SET_SUBREGISTRY", ROLES.REGISTRY.SET_SUBREGISTRY],
    ["SET_SUBREGISTRY_ADMIN", ROLES.ADMIN.REGISTRY.SET_SUBREGISTRY],
    ["SET_RESOLVER", ROLES.REGISTRY.SET_RESOLVER],
    ["SET_RESOLVER_ADMIN", ROLES.ADMIN.REGISTRY.SET_RESOLVER],
    ["UNREGISTER", ROLES.REGISTRY.UNREGISTER],
    ["UNREGISTER_ADMIN", ROLES.ADMIN.REGISTRY.UNREGISTER],
    ["UPGRADE", ROLES.REGISTRY.UPGRADE],
    ["UPGRADE_ADMIN", ROLES.ADMIN.REGISTRY.UPGRADE],
    ["CAN_TRANSFER_ADMIN", ROLES.ADMIN.REGISTRY.CAN_TRANSFER],
  ];

  // 2(a), 2(b). The holder of the safe set cannot reach a registered entry.
  it(
    "the registry owner cannot repoint or unregister a registered entry",
    async () => {
      await handOver();
      expect(await env.v2.RootRegistry.read.roles([ROOT_RESOURCE, owner()]))
        .toBe(DEPLOYMENT_ROLES.REGISTRY_OWNER_ROOT);

      await expect(
        env.v2.RootRegistry.write.setResolver([ethId(), STRANGER], asOwner()),
      ).rejects.toThrow(/EACUnauthorizedAccountRoles/);
      await expect(
        env.v2.RootRegistry.write.setSubregistry(
          [ethId(), env.v2.ETHRegistry.address],
          asOwner(),
        ),
      ).rejects.toThrow(/EACUnauthorizedAccountRoles/);
      await expect(
        env.v2.RootRegistry.write.unregister([ethId()], asOwner()),
      ).rejects.toThrow(/EACUnauthorizedAccountRoles/);
    },
    TEST_TIMEOUT_MS,
  );

  // 2(c). No dangerous root role can be self-granted, in either half.
  it(
    "the registry owner cannot grant itself any dangerous root role",
    async () => {
      await handOver();
      for (const [name, role] of DANGEROUS) {
        expect(role & DANGEROUS_ROOT_ROLES).toBe(role); // the set is what we think it is
        await expect(
          env.v2.RootRegistry.write.grantRootRoles([role, owner()], asOwner()),
        ).rejects.toThrow(
          new RegExp("EACCannotGrantRoles", "i"),
        );
      }
    },
    TEST_TIMEOUT_MS,
  );

  // The limit found beyond prediction, and the strongest claim for Decision 2:
  // promotion fixes the envelope once.
  it(
    "entry admin roles cannot be added after registration",
    async () => {
      await handOver();
      const resource = await ethResource();
      for (const admin of [
        ROLES.ADMIN.REGISTRY.SET_RESOLVER,
        ROLES.ADMIN.REGISTRY.SET_SUBREGISTRY,
        ROLES.ADMIN.REGISTRY.RENEW,
        ROLES.ADMIN.REGISTRY.SET_URI,
      ]) {
        await expect(
          env.v2.RootRegistry.write.grantRoles(
            [resource, admin, STRANGER],
            asNameOwner(),
          ),
        ).rejects.toThrow(/EACCannotGrantRoles/);
      }
    },
    TEST_TIMEOUT_MS,
  );

  // CAN_TRANSFER reads the token owner's entry roles and does not fall back to
  // the root, so a root holder cannot transfer a registered entry in principle.
  it(
    "CAN_TRANSFER does not take the root fallback",
    async () => {
      await handOver();
      const tokenId = await env.v2.RootRegistry.read.getTokenId([ethId()]);
      await expect(
        env.v2.RootRegistry.write.safeTransferFrom(
          [nameOwner(), STRANGER, tokenId, 1n, "0x"],
          asOwner(),
        ),
      ).rejects.toThrow();
      expect(await env.v2.RootRegistry.read.getOwner([ethId()])).toBe(
        nameOwner(),
      );
    },
    TEST_TIMEOUT_MS,
  );

  // What the retained admin roles DO reach, so the claim is stated in both
  // directions rather than only as a denial.
  it(
    "a retained safe admin role grants and revokes its regular bit, and regenerates the token id",
    async () => {
      await handOver();
      const before = await env.v2.RootRegistry.read.getTokenId([ethId()]);
      const resource = await ethResource();

      await env.v2.RootRegistry.write.grantRoles(
        [resource, ROLES.REGISTRY.SET_RESOLVER, STRANGER],
        asNameOwner(),
      );
      expect(
        await env.v2.RootRegistry.read.roles([resource, STRANGER]),
      ).toBe(ROLES.REGISTRY.SET_RESOLVER);

      const after = await env.v2.RootRegistry.read.getTokenId([ethId()]);
      expect(after).not.toBe(before);

      await env.v2.RootRegistry.write.revokeRoles(
        [await ethResource(), ROLES.REGISTRY.SET_RESOLVER, STRANGER],
        asNameOwner(),
      );
      expect(
        await env.v2.RootRegistry.read.roles([await ethResource(), STRANGER]),
      ).toBe(0n);
    },
    TEST_TIMEOUT_MS,
  );

  // Assertion 3: delegation is real and withdrawable.
  it(
    "an entry admin delegates repointing to a third party and takes it back",
    async () => {
      await handOver();
      // A delegate that must send a transaction has to be a devnet signer, so
      // use a named account rather than the unfunded STRANGER sentinel.
      const delegate = getAddress(env.namedAccounts.user.address);
      const asDelegate = { account: env.namedAccounts.user };

      await env.v2.RootRegistry.write.grantRoles(
        [await ethResource(), ROLES.REGISTRY.SET_RESOLVER, delegate],
        asNameOwner(),
      );
      await env.v2.RootRegistry.write.setResolver(
        [ethId(), STRANGER],
        asDelegate,
      );
      expect(await env.v2.RootRegistry.read.getResolver(["eth"])).toEqualAddress(
        STRANGER,
      );

      await env.v2.RootRegistry.write.revokeRoles(
        [await ethResource(), ROLES.REGISTRY.SET_RESOLVER, delegate],
        asNameOwner(),
      );
      await expect(
        env.v2.RootRegistry.write.setResolver(
          [ethId(), env.v2.ETHRegistry.address],
          asDelegate,
        ),
      ).rejects.toThrow();
    },
    TEST_TIMEOUT_MS,
  );

  // Assertion 4, the one the Oracle recommendation rests on: the entry holder
  // repoints the subregistry with no act by anyone else, and nobody else can.
  it(
    "the entry holder repoints the subregistry between registries, and a third party cannot",
    async () => {
      await handOver();
      await env.v2.RootRegistry.write.setSubregistry(
        [ethId(), env.v2.RootRegistry.address],
        asNameOwner(),
      );
      expect(
        await env.v2.RootRegistry.read.getSubregistry(["eth"]),
      ).toEqualAddress(env.v2.RootRegistry.address);
      await env.v2.RootRegistry.write.setSubregistry(
        [ethId(), env.v2.ETHRegistry.address],
        asNameOwner(),
      );
      expect(
        await env.v2.RootRegistry.read.getSubregistry(["eth"]),
      ).toEqualAddress(env.v2.ETHRegistry.address);

      await expect(
        env.v2.RootRegistry.write.setSubregistry(
          [ethId(), env.v2.RootRegistry.address],
          { account: env.namedAccounts.user },
        ),
      ).rejects.toThrow();
    },
    TEST_TIMEOUT_MS,
  );
});
