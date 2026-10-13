import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { McpServer } from "@modelcontextprotocol/server";
import { expect, it } from "vitest";
import { z } from "zod";

import { AnalysisCapabilityUnavailableError } from "../../../src/domain/analysisErrorCore.js";
import { thinMach } from "../../../src/domain/binaryTarget.fixture.js";
import { err, ok } from "../../../src/domain/result.js";
import {
  createRizinTestManager,
  rizinTestInferiorTty,
} from "../providers/RizinTestInferiorTty.js";
import { silentLogger } from "../../../src/logger.js";
import { registerRizinDebugTools } from "../../../src/server/registerRizinDebugTools.js";
import type { RizinDebugToolManager } from "../../../src/server/registerRizinDebugTools.js";
import { createToolResultDelivery } from "../../../src/server/toolResult.js";
import {
  createBinarySessionTargets,
  createCacheProvider,
  createTestBinarySession,
} from "../../fixtures/binarySession.js";
import {
  validateDebuggerStatusResponse,
  waitForStartedFile,
} from "../../support/reverseDebuggerMcpTestHelpers.js";

it("admits Rizin startup across a bound analysis session", async () => {
  const [fixture] = await createBinarySessionTargets();
  const target = fixture.replace(/first\.hop$/u, "first.macho");
  await writeFile(target, thinMach(0xfeedfacf, 0x0100000c));
  const baseProvider = createCacheProvider([]);
  let clientsCreated = 0;
  const provider = {
    ...baseProvider,
    createClient: (
      ...arguments_: Parameters<typeof baseProvider.createClient>
    ) => {
      clientsCreated += 1;
      return baseProvider.createClient(...arguments_);
    },
  };
  const analysisSession = createTestBinarySession(provider);
  expect((await analysisSession.open(target)).ok).toBe(true);
  const initialRunId = z
    .object({ analysis_run: z.object({ run_id: z.string() }) })
    .parse(analysisSession.status()).analysis_run.run_id;
  const manager = {
    start: async () => ({
      ok: true,
      value: {
        session_id: "00000000-0000-4000-8000-000000000001",
        backend: null,
      },
    }),
    execute: async () =>
      err(new AnalysisCapabilityUnavailableError("rizin", "unused", "unused")),
    status: () => undefined,
    close: async () => ({ ok: true, value: { target_state: "unknown" } }),
    retryCleanupFailures: async () => ok(null),
  } satisfies RizinDebugToolManager;
  const server = new McpServer({ name: "rizin-start-admission", version: "1" });
  registerRizinDebugTools(
    server,
    manager,
    silentLogger,
    createToolResultDelivery(undefined),
    undefined,
    analysisSession,
  );
  const client = new Client({ name: "rizin-start-admission", version: "1" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  try {
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    const started = await client.callTool({
      name: "start_rizin_debug_session",
      arguments: { path: target, inferior_tty: "/dev/null" },
    });
    expect(started.isError ?? false).toBe(false);
    const currentRunId = z
      .object({ analysis_run: z.object({ run_id: z.string() }) })
      .parse(analysisSession.status()).analysis_run.run_id;
    expect(currentRunId).not.toBe(initialRunId);
    expect(analysisSession.activeTarget()?.path).toBe(target);
  } finally {
    await Promise.allSettled([client.close(), server.close()]);
    await analysisSession.close();
  }
});

it.skipIf(process.platform === "win32")(
  "propagates MCP cancellation into a running Rizin debugger command",
  async () => {
    const directory = await mkdtemp(join(tmpdir(), "rea-rizin-mcp-cancel-"));
    const provider = join(directory, "fake-rizin.mjs");
    const commandPath = join(directory, "command-started");
    await writeFile(
      provider,
      `#!/usr/bin/env node
process.stdout.write("\\0");
process.stdin.setEncoding("utf8");
process.stdin.on("data", async (chunk) => {
  for (const line of chunk.split("\\n")) {
    if (line.startsWith("!echo ")) continue;
    await import("node:fs/promises").then((fs) => fs.writeFile(${JSON.stringify(commandPath)}, "started"));
  }
});
`,
    );
    await chmod(provider, 0o700);
    const manager = createRizinTestManager({
      REA_RIZIN_COMMAND: provider,
    });
    const server = new McpServer({ name: "rizin-cancellation", version: "1" });
    registerRizinDebugTools(
      server,
      manager,
      silentLogger,
      createToolResultDelivery(undefined),
    );
    const client = new Client({ name: "rizin-cancellation", version: "1" });
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    try {
      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const started = await client.callTool({
        name: "start_rizin_debug_session",
        arguments: {
          path: "/tmp/fixture.bin",
          inferior_tty: await rizinTestInferiorTty(),
        },
      });
      const sessionId = z
        .object({ session_id: z.string().uuid() })
        .parse(started.structuredContent).session_id;
      const controller = new AbortController();
      const command = client.callTool(
        {
          name: "rizin_debug_command",
          arguments: { session_id: sessionId, command: "dr" },
        },
        { signal: controller.signal },
      );
      await waitForStartedFile(commandPath);
      controller.abort();
      await expect(command).rejects.toThrow(/abort/iu);
      const status = await validateDebuggerStatusResponse(
        client,
        "rizin_debug_session_status",
        sessionId,
      );
      expect(status.state).toBe("closed");
      expect(status).toHaveProperty("diagnostics_truncated");
    } finally {
      await Promise.allSettled([client.close(), server.close()]);
      await manager.closeAll().catch(() => undefined);
      await rm(directory, { recursive: true, force: true });
    }
  },
);
