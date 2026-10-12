import { rm } from "node:fs/promises";
import {
  createArtifact,
  providerSnapshot,
} from "../support/reverseEngineeringCompositionFixtures.js";
import { registerSharedReverseEngineeringEdgeCaseTests } from "../support/reverseEngineeringCompositionEdgeCases.js";

import { expect, it, vi } from "vitest";

import { TestReverseEngineeringService as ReverseEngineeringService } from "../support/reverseEngineeringService.js";

registerSharedReverseEngineeringEdgeCaseTests();

it("rejects NUL in a Rizin command before touching the provider", async () => {
  const { directory, path } = await createArtifact();
  let invoked = false;
  const service = new ReverseEngineeringService({
    run: async () => {
      invoked = true;
      return { stdout: "", stderr: "" };
    },
  });

  try {
    const result = await service.executeRizinCommand({
      path,
      command: "wx\u0000 00",
    });
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError", operation: "execute_rizin_command" },
    });
    expect(invoked).toBe(false);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it("rejects a digest when cancellation arrives before stream listeners attach", async () => {
  const { directory, path } = await createArtifact();
  let reads = 0;
  const signal = {
    get aborted() {
      reads += 1;
      return reads > 1;
    },
    addEventListener() {},
    removeEventListener() {},
    throwIfAborted() {},
    onabort: null,
    reason: undefined,
    dispatchEvent: () => true,
  } as AbortSignal;
  let digestStarted = false;
  const service = new ReverseEngineeringService({
    digest: async () => {
      digestStarted = true;
      return "a".repeat(64);
    },
  });

  try {
    const result = await service.inspectWithObjdump(
      { path, operation: "file_headers" },
      { signal },
    );
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisCancelledError" },
    });
    expect(reads).toBe(2);
    expect(digestStarted).toBe(false);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it.each([
  ["normal exit", providerSnapshot(), "complete", 0, false],
  [
    "non-zero exit",
    providerSnapshot({ exitCode: 7, diagnosticTruncated: true }),
    "complete",
    7,
    true,
  ],
  [
    "signal termination",
    providerSnapshot({
      exitCode: null,
      signal: "SIGSEGV",
      diagnosticTruncated: true,
    }),
    "unknown",
    null,
    true,
  ],
  [
    "signal termination with a numeric exit snapshot",
    providerSnapshot({ exitCode: 7, signal: "SIGSEGV" }),
    "unknown",
    null,
    false,
  ],
  [
    "signal termination without truncation",
    providerSnapshot({ exitCode: null, signal: "SIGTERM" }),
    "unknown",
    null,
    false,
  ],
  [
    "unknown exit status",
    providerSnapshot({ exitCode: null }),
    "unknown",
    null,
    false,
  ],
] as const)(
  "maps an owned command %s into provider Evidence",
  async (_name, snapshot, completion, exitCode, outputTruncated) => {
    const { directory, path } = await createArtifact();
    const runOwned = vi.fn(async () => snapshot);
    const service = new ReverseEngineeringService({
      runOwned,
      environment: { REA_RIZIN_COMMAND: "rizin-test" },
    });

    try {
      const result = await service.executeRizinCommand({ path, command: "iI" });
      expect(runOwned).toHaveBeenCalledOnce();
      expect(runOwned).toHaveBeenCalledWith(
        expect.objectContaining({
          command: "rizin-test",
          arguments: expect.arrayContaining(["-q", "-c", "iI"]),
          expectedCommand: null,
          env: expect.objectContaining({ REA_RIZIN_COMMAND: "rizin-test" }),
          hostEnvironment: {},
          sweepTokenOwnedProcesses: true,
        }),
        {
          timeoutMs: 120_000,
          diagnosticBytes: 16 * 1024 * 1024,
          acceptNonZeroExit: true,
        },
        { signal: expect.any(AbortSignal) },
      );
      expect(result).toMatchObject({
        ok: true,
        value: {
          raw_result: {
            stdout: "captured owned output",
            completion_status: completion,
            exit_code: exitCode,
            output_truncated: outputTruncated,
          },
        },
      });
      if (!result.ok) throw new Error("Expected provider Evidence");
      expect(result.value.parameters).toMatchObject({
        command: "iI",
        provider_executable: "rizin-test",
        command_arguments: expect.arrayContaining(["-q", "-c", "iI"]),
      });
      expect(result.value.locations).toContainEqual({
        kind: "artifact-path",
        path,
      });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);

it("preserves a provider timeout when cancellation arrives during the final digest", async () => {
  const { directory, path } = await createArtifact();
  const controller = new AbortController();
  let digests = 0;
  const service = new ReverseEngineeringService({
    digest: async () => {
      digests += 1;
      if (digests === 2) controller.abort();
      return "a".repeat(64);
    },
    run: async () => {
      throw Object.assign(new Error("provider timed out"), {
        stdout: "partial timeout output",
        stderr: "timeout diagnostic",
        code: "ETIMEDOUT",
        signal: null,
        killed: true,
      });
    },
  });

  try {
    const result = await service.executeRizinCommand(
      { path, command: "iI" },
      { signal: controller.signal },
    );
    expect(result).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisTimeoutError",
        capturedOutput: {
          stdout: "partial timeout output",
          stderr: "timeout diagnostic",
        },
        partialObservation: {
          raw_result: {
            stdout: "partial timeout output",
            completion_status: "unknown",
          },
        },
      },
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
