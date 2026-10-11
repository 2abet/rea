import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { ReverseEngineeringService } from "../../src/application/reverse/ReverseEngineeringService.js";
import { projectAnalysisError } from "../../src/domain/analysisErrorProjection.js";

describe("reverse engineering command services", () => {
  it("uses compatible local DWARF link flags and disables debuginfod through the environment", async () => {
    const directory = await mkdtemp(join(tmpdir(), "rea-reverse-tools-"));
    const path = join(directory, "fixture.bin");
    await writeFile(path, Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
    const calls: {
      command: string;
      args: readonly string[];
      env: NodeJS.ProcessEnv | undefined;
    }[] = [];
    const service = new ReverseEngineeringService({
      environment: {
        REA_OBJDUMP_COMMAND: "/tools/objdump",
        DEBUGINFOD_URLS: "https://debug.example.invalid",
      },
      run: async (command, args, options) => {
        calls.push({ command, args, env: options?.env });
        return { stdout: "DWARF output\n", stderr: "diagnostic\n" };
      },
    });

    try {
      const result = await service.inspectWithObjdump({
        path,
        operation: "dwarf",
        follow_debug_links: true,
      });
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(calls).toEqual([
        {
          command: "/tools/objdump",
          args: ["-W", "-WK", path],
          env: expect.objectContaining({ DEBUGINFOD_URLS: "" }),
        },
      ]);
      expect(result.value.raw_result).toMatchObject({
        stdout: "DWARF output\n",
        stderr: "diagnostic\n",
        exit_code: 0,
        output_truncated: false,
      });
      expect(result.value.provider.id).toBe("gnu.objdump");
      expect(result.value.subject?.local_path).toBe(path);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("rejects non-regular artifacts without launching the provider", async () => {
    const directory = await mkdtemp(
      join(tmpdir(), "rea-reverse-special-file-"),
    );
    let invoked = false;
    const service = new ReverseEngineeringService({
      run: async () => {
        invoked = true;
        return { stdout: "", stderr: "" };
      },
    });

    try {
      const result = await service.inspectWithObjdump({
        path: directory,
        operation: "file_headers",
      });
      expect(result.ok).toBe(false);
      expect(invoked).toBe(false);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("classifies captured spawn failures instead of reporting provider evidence", async () => {
    const directory = await mkdtemp(
      join(tmpdir(), "rea-objdump-spawn-failure-"),
    );
    const path = join(directory, "fixture.bin");
    await writeFile(path, "fixture");
    const service = new ReverseEngineeringService({
      run: async () => {
        const failure = Object.assign(new Error("not found"), {
          stdout: "",
          stderr: "",
          code: "ENOENT",
          signal: null,
          killed: false,
        });
        throw failure;
      },
    });

    try {
      const result = await service.inspectWithObjdump({
        path,
        operation: "file_headers",
      });
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error._tag).toBe("AnalysisCapabilityUnavailableError");
        expect(result.error.message).toContain("ENOENT");
        expect(result.error.message).not.toContain("stdout");
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("marks max-buffer termination as unknown completion while retaining output", async () => {
    const directory = await mkdtemp(join(tmpdir(), "rea-objdump-max-buffer-"));
    const path = join(directory, "fixture.bin");
    await writeFile(path, "fixture");
    const service = new ReverseEngineeringService({
      run: async () => {
        throw Object.assign(new Error("max buffer exceeded"), {
          stdout: "captured partial output",
          stderr: "",
          code: "ERR_CHILD_PROCESS_STDIO_MAXBUFFER",
          signal: "SIGTERM",
          killed: true,
        });
      },
    });

    try {
      const result = await service.executeRizinCommand({
        path,
        command: "wx 00 @ 0",
      });
      expect(result.ok).toBe(true);
      if (result.ok)
        expect(result.value.raw_result).toMatchObject({
          stdout: "captured partial output",
          exit_code: null,
          output_truncated: true,
          completion_status: "unknown",
        });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});

describe("Rizin command service", () => {
  it("runs Rizin with user scripts suppressed while retaining plugins and preserves nonzero output", async () => {
    const directory = await mkdtemp(join(tmpdir(), "rea-rizin-"));
    const path = join(directory, "fixture.bin");
    await writeFile(path, "fixture");
    const calls: { command: string; args: readonly string[] }[] = [];
    const service = new ReverseEngineeringService({
      environment: { REA_RIZIN_COMMAND: "/tools/rizin" },
      run: async (command, args) => {
        calls.push({ command, args });
        const failure = new Error("command exited with status 2") as Error & {
          stdout: string;
          stderr: string;
          code: number;
          signal: null;
          killed: boolean;
        };
        Object.assign(failure, {
          stdout: "partial data",
          stderr: "command error",
          code: 2,
          signal: null,
          killed: false,
        });
        throw failure;
      },
    });

    try {
      const result = await service.executeRizinCommand({ path, command: "iI" });
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(calls).toEqual([
        {
          command: "/tools/rizin",
          args: ["-N", "-q", "-c", "iI", path],
        },
      ]);
      expect(result.value.raw_result).toMatchObject({
        stdout: "partial data",
        stderr: "command error",
        exit_code: 2,
      });
      expect(result.value.parameters).toMatchObject({
        command: "iI",
        provider_executable: "/tools/rizin",
      });
      expect(result.value.provider.id).toBe("rizin");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("rejects multiline Rizin command input before launching the provider", async () => {
    const directory = await mkdtemp(join(tmpdir(), "rea-rizin-input-"));
    const path = join(directory, "fixture.bin");
    await writeFile(path, "fixture");
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
        command: "iI\nq",
      });
      expect(result.ok).toBe(false);
      expect(invoked).toBe(false);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("preserves pre and post artifact digests when an unrestricted Rizin command changes the file", async () => {
    const directory = await mkdtemp(join(tmpdir(), "rea-rizin-mutation-"));
    const path = join(directory, "fixture.bin");
    await writeFile(path, "before");
    const service = new ReverseEngineeringService({
      run: async () => {
        await writeFile(path, "after");
        return { stdout: "changed", stderr: "" };
      },
    });

    try {
      const result = await service.executeRizinCommand({
        path,
        command: "wx 00 @ 0",
      });
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.value.subject?.digest.sha256).toBe(
        createHash("sha256").update("before").digest("hex"),
      );
      expect(result.value.raw_result).toMatchObject({
        artifact_sha256_after: createHash("sha256")
          .update("after")
          .digest("hex"),
        artifact_changed: true,
      });
      expect(result.value.limitations).toContain(
        "The provider command may have changed the artifact while analysis was running; pre-run and post-run digests are both reported.",
      );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});

it("retains partial Evidence when a provider command times out", async () => {
  const directory = await mkdtemp(join(tmpdir(), "rea-rizin-timeout-partial-"));
  const path = join(directory, "fixture.bin");
  await writeFile(path, "before");
  const service = new ReverseEngineeringService({
    run: async () => {
      const failure = Object.assign(new Error("timeout"), {
        stdout: "captured before timeout",
        stderr: "still running",
        code: "ETIMEDOUT",
        signal: "SIGTERM",
        killed: true,
      });
      throw failure;
    },
  });

  try {
    const result = await service.executeRizinCommand({ path, command: "wx 00 @ 0" });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error._tag).toBe("AnalysisTimeoutError");
      expect(result.error.partialObservation).toMatchObject({
        operation: "execute_rizin_command",
        raw_result: {
          stdout: "captured before timeout",
          stderr: "still running",
          completion_status: "unknown",
          signal: "SIGTERM",
          artifact_sha256_after: expect.any(String),
        },
      });
      expect(JSON.stringify(projectAnalysisError(result.error))).toContain(
        "captured before timeout",
      );
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it("preserves provider facts when cancellation interrupts the post-run digest", async () => {
  const directory = await mkdtemp(join(tmpdir(), "rea-rizin-digest-cancel-"));
  const path = join(directory, "fixture.bin");
  await writeFile(path, "fixture");
  const controller = new AbortController();
  const service = new ReverseEngineeringService({
    run: async () => {
      controller.abort();
      return { stdout: "provider completed", stderr: "" };
    },
  });

  try {
    const result = await service.executeRizinCommand(
      { path, command: "iI" },
      { signal: controller.signal },
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error._tag).toBe("AnalysisCancelledError");
      expect(result.error.partialObservation).toMatchObject({
        raw_result: {
          stdout: "provider completed",
          exit_code: null,
          completion_status: "unknown",
          artifact_sha256_after: null,
        },
        limitations: expect.arrayContaining([
          expect.stringContaining("cancellation interrupted the digest"),
        ]),
      });
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it("marks signal-terminated provider output incomplete", async () => {
  const directory = await mkdtemp(join(tmpdir(), "rea-rizin-signal-"));
  const path = join(directory, "fixture.bin");
  await writeFile(path, "fixture");
  const service = new ReverseEngineeringService({
    run: async () => {
      throw Object.assign(new Error("terminated"), {
        stdout: "partial",
        stderr: "",
        code: null,
        signal: "SIGSEGV",
        killed: false,
      });
    },
  });

  try {
    const result = await service.executeRizinCommand({ path, command: "iI" });
    expect(result.ok).toBe(true);
    if (result.ok)
      expect(result.value.raw_result).toMatchObject({
        signal: "SIGSEGV",
        exit_code: null,
        completion_status: "unknown",
      });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
