import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { expect, it } from "vitest";

import { TestReverseEngineeringService as ReverseEngineeringService } from "../support/reverseEngineeringService.js";

it("uses stoppable process mode for caller-selected provider commands", async () => {
  const directory = await mkdtemp(join(tmpdir(), "rea-rizin-stoppable-"));
  const path = join(directory, "fixture.bin");
  await writeFile(path, "fixture");
  let received: Record<string, unknown> | undefined;
  const service = new ReverseEngineeringService({
    run: async (_command, _args, options) => {
      received = options as Record<string, unknown>;
      return { stdout: "", stderr: "" };
    },
  });

  try {
    await service.executeRizinCommand({ path, command: "iI" });
    expect(received?.stopSignal).toBe("SIGTERM");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it.skipIf(process.platform === "win32")(
  "waits for a cancelled Rizin process to exit before returning",
  async () => {
    const directory = await mkdtemp(join(tmpdir(), "rea-rizin-cancel-settle-"));
    const path = join(directory, "fixture.bin");
    const descendantStartedMarker = join(directory, "descendant-started");
    const descendantMarker = join(directory, "descendant-finished");
    const provider = join(directory, "slow-rizin.mjs");
    const descendantScript = [
      "const fs = require('node:fs');",
      "process.on('SIGTERM', () => {});",
      "fs.writeFileSync(process.env.REA_TEST_DESCENDANT_STARTED, 'started');",
      "setTimeout(() => fs.writeFileSync(process.env.REA_TEST_DESCENDANT, 'finished'), 500);",
      "setInterval(() => {}, 1000);",
    ].join("\n");
    await writeFile(path, "before");
    await writeFile(
      provider,
      `#!${process.execPath}
import { spawn } from "node:child_process";
process.stdout.write("provider output before cancellation");
const child = spawn(process.execPath, ["-e", ${JSON.stringify(descendantScript)}], { env: process.env, stdio: "ignore" });
setInterval(() => {}, 1000);
`,
    );
    await chmod(provider, 0o755);
    const controller = new AbortController();
    const service = new ReverseEngineeringService({
      environment: {
        REA_RIZIN_COMMAND: provider,
        REA_TEST_ARTIFACT: path,
        REA_TEST_DESCENDANT_STARTED: descendantStartedMarker,
        REA_TEST_DESCENDANT: descendantMarker,
      },
    });

    let pending: ReturnType<typeof service.executeRizinCommand> | undefined;
    try {
      pending = service.executeRizinCommand(
        { path, command: "sleep" },
        { signal: controller.signal },
      );
      let descendantStarted = false;
      for (let attempt = 0; attempt < 500; attempt += 1) {
        try {
          await readFile(descendantStartedMarker);
          descendantStarted = true;
          break;
        } catch {
          await new Promise((resolveDelay) => setTimeout(resolveDelay, 10));
        }
      }
      expect(descendantStarted).toBe(true);
      controller.abort();

      const result = await pending;
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error._tag).toBe("AnalysisCancelledError");
        expect(result.error.cleanup).toBeUndefined();
        expect(result.error.capturedOutput).toMatchObject({
          stdout: "provider output before cancellation",
          stderr: "",
          truncated: false,
          exit_code: null,
          signal: "SIGKILL",
        });
        expect(result.error.cause).toBeInstanceOf(Error);
        expect(result.error.partialObservation).toMatchObject({
          raw_result: {
            stdout: "provider output before cancellation",
            completion_status: "unknown",
          },
        });
      }
      expect(await readFile(path, "utf8")).toBe("before");
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 600));
      await expect(readFile(descendantMarker)).rejects.toMatchObject({
        code: "ENOENT",
      });
    } finally {
      controller.abort();
      await pending?.catch(() => undefined);
      await service.close().catch(() => undefined);
      await rm(directory, { recursive: true, force: true });
    }
  },
);
