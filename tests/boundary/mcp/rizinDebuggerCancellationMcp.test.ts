import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { McpServer } from "@modelcontextprotocol/server";
import { expect, it } from "vitest";
import { z } from "zod";

import { RizinDebugSessionManager } from "../../../src/rizin/RizinDebugSessionManager.js";
import {
  createRizinTestManager,
  rizinTestInferiorTty,
} from "../providers/RizinTestInferiorTty.js";
import { silentLogger } from "../../../src/logger.js";
import { registerRizinDebugTools } from "../../../src/server/registerRizinDebugTools.js";
import { createToolResultDelivery } from "../../../src/server/toolResult.js";
import {
  validateDebuggerStatusResponse,
  waitForStartedFile,
} from "../../support/reverseDebuggerMcpTestHelpers.js";

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
