import { execFileSync } from "node:child_process";
import { chmod, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { expect, it } from "vitest";

import { CutterBridgeClient } from "../../../src/cutter/CutterBridgeClient.js";
import {
  createTestProcessRegistry,
  waitForExit,
} from "../../../tests/support/process/processFixture.js";

it("authenticates bridge peers before payloads and permits status recovery after a poisoned UI timeout", () => {
  execFileSync(
    "python3",
    [resolve("tests/fixtures/cutter_bridge_protocol_test.py")],
    {
      encoding: "utf8",
      timeout: 10_000,
    },
  );
});

it("round-trips authenticated status and command bytes across the Python producer boundary", async () => {
  const directory = await mkdtemp(join(tmpdir(), "rea-cutter-interop-"));
  await chmod(directory, 0o700);
  const processes = createTestProcessRegistry();
  const child = processes.spawn(
    "python3",
    [resolve("tests/fixtures/cutter_bridge_protocol_test.py"), "--serve"],
    {
      env: { ...process.env, REA_CUTTER_BRIDGE_DIR: directory },
    },
  );
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => {
    stdout += chunk;
  });
  child.stderr.on("data", (chunk: string) => {
    stderr += chunk;
  });
  let exitedCleanly = false;
  try {
    await new Promise<void>((resolveReady, rejectReady) => {
      const timeout = setTimeout(
        () =>
          rejectReady(
            new Error(`Python bridge did not become ready: ${stderr}`),
          ),
        5_000,
      );
      const onData = (_chunk: string): void => {
        if (!stdout.includes("ready\n")) return;
        clearTimeout(timeout);
        child.stdout.off("data", onData);
        resolveReady();
      };
      child.stdout.on("data", onData);
      child.once("error", (error) => {
        clearTimeout(timeout);
        rejectReady(error);
      });
      child.once("exit", (code, signal) => {
        if (stdout.includes("ready\n")) return;
        clearTimeout(timeout);
        rejectReady(
          new Error(
            `Python bridge exited before ready (${code ?? signal}): ${stderr}`,
          ),
        );
      });
      if (stdout.includes("ready\n")) onData("");
    });

    const client = new CutterBridgeClient({
      ...process.env,
      REA_CUTTER_BRIDGE_DIR: directory,
    });
    const discovery = await client.listSessions();
    expect(discovery.discovery_status).toBe("sessions_found");
    expect(discovery.sessions).toHaveLength(1);
    const session = discovery.sessions[0];
    expect(session).toBeDefined();
    if (session === undefined) throw new Error("Python bridge session missing");
    expect(session.document_generation).toBe(4);
    expect(session.current_file).toBe("/tmp/cutter-interop-雪.bin");

    for (let index = 0; index <= 64; index += 1) {
      await expect(
        client.execute({
          sessionId: session.session_id,
          expectedGeneration: 3,
          command: "iI",
          json: false,
        }),
      ).rejects.toThrow("List sessions again");
    }

    const result = await client.execute({
      sessionId: session.session_id,
      expectedGeneration: session.document_generation,
      command: 'print("雪 ☃️ \\\"quoted\\\" \\\\ slash\\nline\\ttab")',
      json: false,
    });
    expect(result.output).toBe(
      'round-trip: 雪 ☃️ quote=" slash=\\\\ line=\\n tab=\\t',
    );
    expect(result.executionState).toBe("complete");
    expect(result.documentGeneration).toBe(4);
    expect(result.currentFile).toBe("/tmp/cutter-interop-雪.bin");
    expect(result.outputTruncated).toBe(false);
  } finally {
    child.stdin.end("shutdown\n");
    exitedCleanly = await waitForExit(child, 3_000);
    try {
      await processes.shutdown();
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }
  expect(exitedCleanly, stderr).toBe(true);
});
