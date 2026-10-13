import pino from "pino";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { expect, it, vi } from "vitest";

import { TestReverseEngineeringService as ReverseEngineeringService } from "../../support/reverseEngineeringService.js";
import { AnalysisInputError } from "../../../src/domain/analysisErrorCore.js";
import { HopperStartError } from "../../../src/domain/hopperErrors.js";
import {
  createBinarySessionTargets,
  createCacheProvider,
  createTestBinarySession,
} from "../../fixtures/binarySession.js";
import type { AnalysisOperationPort } from "../../../src/application/AnalysisProvider.js";
import { EvidenceIntegrityError } from "../../../src/domain/evidenceErrors.js";
import { err, ok } from "../../../src/domain/result.js";
import type { WithAdmittedAnalysis } from "../../../src/server/analysisAdmission.js";
import { createToolResultDelivery } from "../../../src/server/toolResult.js";
import { registerReverseEngineeringTools } from "../../../src/server/registerReverseEngineeringTools.js";
import {
  createReverseEngineeringMcpHarness,
  invokeWithLiveSignal,
} from "../../support/reverseEngineeringMcpHarness.js";

const createTimedOutRizinService = (): ReverseEngineeringService =>
  new ReverseEngineeringService({
    run: async () => {
      throw Object.assign(new Error("timed out"), {
        stdout: "partial provider output",
        stderr: "",
        code: "ETIMEDOUT",
        signal: null,
        killed: true,
      });
    },
  });

it("records partial Evidence and references it in the original MCP error", async () => {
  const { server, handler } = createReverseEngineeringMcpHarness();
  const service = createTimedOutRizinService();
  const recordEvidence = vi.fn(() => ok("added" as const));
  registerReverseEngineeringTools(
    server,
    service,
    pino({ enabled: false }),
    createToolResultDelivery(2 * 1024 * 1024),
    recordEvidence,
  );
  const invoke = handler("execute_rizin_command");

  const response = (await invokeWithLiveSignal(invoke, {
    path: "package.json",
    command: "iI",
  })) as {
    readonly isError?: boolean;
    readonly structuredContent?: {
      readonly error?: {
        readonly details?: Readonly<Record<string, unknown>>;
      };
    };
  };

  expect(response.isError).toBe(true);
  expect(recordEvidence).toHaveBeenCalledTimes(1);
  expect(response.structuredContent?.error?.details).toMatchObject({
    partial_observation: {
      kind: "retained-evidence",
      evidence_id: expect.any(String),
    },
  });
});

it("admits Rizin mutation and rebinds after dispatch while invalidating first", async () => {
  const { server, handler } = createReverseEngineeringMcpHarness();
  const events: string[] = [];
  const service = new ReverseEngineeringService({
    run: async () => {
      events.push("dispatch");
      return { stdout: "rizin output", stderr: "" };
    },
  });
  registerReverseEngineeringTools(
    server,
    service,
    pino({ enabled: false }),
    createToolResultDelivery(2 * 1024 * 1024),
    undefined,
    undefined,
    () => events.push("invalidate"),
    async (_path, _signal, operation) => {
      events.push("admit");
      const result = await operation();
      events.push("rebind");
      return ok(result);
    },
  );
  const invoke = handler("execute_rizin_command");

  await invoke(
    { path: "package.json", command: "iI" },
    { mcpReq: { signal: new AbortController().signal } },
  );

  expect(events).toEqual(["admit", "invalidate", "dispatch", "rebind"]);
});

it("invalidates the snapshot in the legacy Rizin admission path", async () => {
  const { server, handler } = createReverseEngineeringMcpHarness();
  const invalidateSnapshot = vi.fn();
  const service = new ReverseEngineeringService({
    run: async () => ({ stdout: "rizin output", stderr: "" }),
  });
  registerReverseEngineeringTools(
    server,
    service,
    pino({ enabled: false }),
    createToolResultDelivery(2 * 1024 * 1024),
    undefined,
    undefined,
    invalidateSnapshot,
  );
  const invoke = handler("execute_rizin_command");

  const response = (await invokeWithLiveSignal(invoke, {
    path: "package.json",
    command: "iI",
  })) as { readonly isError?: boolean };

  expect(response.isError).not.toBe(true);
  expect(invalidateSnapshot).toHaveBeenCalledOnce();
});

it("skips snapshot invalidation for malformed Rizin input", async () => {
  const { server, handler } = createReverseEngineeringMcpHarness();
  const invalidateSnapshot = vi.fn();
  const executeRizinCommand = vi.fn(async () =>
    err(new AnalysisInputError("execute_rizin_command")),
  );
  const service = {
    executeRizinCommand,
  } as unknown as ReverseEngineeringService;
  registerReverseEngineeringTools(
    server,
    service,
    pino({ enabled: false }),
    createToolResultDelivery(2 * 1024 * 1024),
    undefined,
    undefined,
    invalidateSnapshot,
  );
  const invoke = handler("execute_rizin_command");

  const response = (await invokeWithLiveSignal(invoke, {
    path: "package.json",
  })) as { readonly isError?: boolean };

  expect(response.isError).toBe(true);
  expect(executeRizinCommand).toHaveBeenCalledOnce();
  expect(invalidateSnapshot).not.toHaveBeenCalled();
});

it("delivers failed Rizin execution after external admission", async () => {
  const { server, handler } = createReverseEngineeringMcpHarness();
  const service = new ReverseEngineeringService({
    run: async () => {
      throw new Error("Rizin command failed");
    },
  });
  registerReverseEngineeringTools(
    server,
    service,
    pino({ enabled: false }),
    createToolResultDelivery(2 * 1024 * 1024),
    undefined,
    undefined,
    undefined,
    async (_path, _signal, operation) => ok(await operation()),
  );
  const invoke = handler("execute_rizin_command");

  const response = (await invokeWithLiveSignal(invoke, {
    path: "package.json",
    command: "iI",
  })) as { readonly isError?: boolean };

  expect(response.isError).toBe(true);
});

it("reports rebind failure when admitted Rizin execution has no partial observation", async () => {
  const { server, handler } = createReverseEngineeringMcpHarness();
  const service = {
    executeRizinCommand: async () =>
      err(new AnalysisInputError("execute_rizin_command")),
  } as unknown as ReverseEngineeringService;
  const observedOperationResult = vi.fn();
  registerReverseEngineeringTools(
    server,
    service,
    pino({ enabled: false }),
    createToolResultDelivery(2 * 1024 * 1024),
    undefined,
    undefined,
    undefined,
    async (_path, _signal, operation, rebindFailure) => {
      const result = await operation();
      observedOperationResult(result);
      return err(rebindFailure(result, new AnalysisInputError("rebind")));
    },
  );
  const invoke = handler("execute_rizin_command");

  const response = (await invoke(
    { path: "package.json", command: "iI" },
    { mcpReq: { signal: new AbortController().signal } },
  )) as {
    readonly isError?: boolean;
    readonly structuredContent?: {
      readonly error?: {
        readonly code?: string;
        readonly details?: { readonly reason?: string };
      };
    };
  };

  expect(response.isError).toBe(true);
  expect(observedOperationResult).toHaveBeenCalledWith(
    expect.objectContaining({ ok: false }),
  );
  expect(response.structuredContent?.error).toMatchObject({
    code: "unreadable_output",
    details: {
      reason: expect.stringContaining("could not be rebound"),
    },
  });
});

it.each(["success", "timeout"])(
  "retains %s output and leaves the session unbound when a symlink rebind fails",
  async (outcome) => {
    const [target] = await createBinarySessionTargets();
    const alias = join(dirname(target), "active-target-alias.hop");
    await symlink(target, alias);
    let profileResolutions = 0;
    const base = createCacheProvider([]);
    const session = createTestBinarySession({
      ...base,
      resolveAnalysisProfile: async (...arguments_) => {
        profileResolutions += 1;
        if (profileResolutions > 1) return err(new HopperStartError());
        return base.resolveAnalysisProfile!(...arguments_);
      },
    });
    expect((await session.open(target)).ok).toBe(true);
    expect(session.activeTarget()?.path).toBe(target);

    const { server, handler } = createReverseEngineeringMcpHarness();
    const service = new ReverseEngineeringService({
      run: async () => {
        await writeFile(alias, "changed by Rizin");
        if (outcome === "timeout")
          throw Object.assign(new Error("timed out"), {
            stdout: "partial analysis output",
            stderr: "timeout diagnostics",
            code: "ETIMEDOUT",
            signal: null,
            killed: true,
          });
        return { stdout: "partial analysis output", stderr: "" };
      },
    });
    const recordEvidence = vi.fn(() => ok("added" as const));
    registerReverseEngineeringTools(
      server,
      service,
      pino({ enabled: false }),
      createToolResultDelivery(2 * 1024 * 1024),
      recordEvidence,
      undefined,
      () => session.invalidateSnapshotForExternalMutation(),
      (path, signal, operation, rebindFailure) =>
        session.withAdmittedExternalMutation(
          path,
          signal,
          operation,
          rebindFailure,
        ),
    );
    const invoke = handler("execute_rizin_command");

    const response = (await invoke(
      { path: alias, command: "wx 00 @ 0" },
      { mcpReq: { signal: new AbortController().signal } },
    )) as {
      readonly isError?: boolean;
      readonly structuredContent?: {
        readonly error?: {
          readonly code?: string;
          readonly details?: Readonly<Record<string, unknown>>;
        };
      };
    };

    expect(profileResolutions).toBeGreaterThan(1);
    expect(response.isError).toBe(true);
    expect(response.structuredContent?.error?.code).toBe(
      outcome === "timeout" ? "provider_timeout" : "unreadable_output",
    );
    if (outcome === "timeout")
      expect(response.structuredContent?.error?.details).toMatchObject({
        captured_output: {
          stdout: "partial analysis output",
          stderr: "timeout diagnostics",
        },
        diagnostics: { rebind_error: { code: expect.any(String) } },
      });
    expect(response.structuredContent?.error?.details).toMatchObject({
      partial_observation: {
        kind: "retained-evidence",
        evidence_id: expect.any(String),
      },
    });
    expect(recordEvidence).toHaveBeenCalledTimes(1);
    expect(session.activeTarget()).toBeUndefined();
    await session.close();
    await rm(dirname(target), { recursive: true, force: true });
  },
);

it("preserves a partial MCP error without claiming failed Evidence retention", async () => {
  const { server, handler } = createReverseEngineeringMcpHarness();
  const service = createTimedOutRizinService();
  const recordEvidence = vi.fn((_evidence: unknown) =>
    err(new EvidenceIntegrityError("retention failed")),
  );
  registerReverseEngineeringTools(
    server,
    service,
    pino({ enabled: false }),
    createToolResultDelivery(2 * 1024 * 1024),
    recordEvidence,
  );
  const invoke = handler("execute_rizin_command");

  const response = (await invokeWithLiveSignal(invoke, {
    path: "package.json",
    command: "iI",
  })) as {
    readonly isError?: boolean;
    readonly structuredContent?: {
      readonly error?: {
        readonly details?: Readonly<Record<string, unknown>>;
      };
    };
  };

  expect(response.isError).toBe(true);
  expect(response.structuredContent?.error?.details).toMatchObject({
    partial_observation: expect.objectContaining({
      operation: "execute_rizin_command",
    }),
  });
  expect(
    JSON.stringify(response.structuredContent?.error?.details),
  ).not.toContain("retained-evidence");
});

it("delivers objdump Evidence and ordinary input errors through their named tools", async () => {
  const { server, handler } = createReverseEngineeringMcpHarness();
  const service = new ReverseEngineeringService({
    run: async () => ({ stdout: "objdump output", stderr: "" }),
  });
  const delivery = createToolResultDelivery(2 * 1024 * 1024);
  registerReverseEngineeringTools(
    server,
    service,
    pino({ enabled: false }),
    delivery,
  );
  const context = { mcpReq: { signal: new AbortController().signal } };
  const objdump = handler("inspect_with_objdump");
  const rizin = handler("execute_rizin_command");

  const success = (await objdump(
    { path: "package.json", operation: "file_headers" },
    context,
  )) as { readonly isError?: boolean };
  const objdumpFailure = (await objdump({}, context)) as {
    readonly isError?: boolean;
  };
  const failure = (await rizin({}, context)) as {
    readonly isError?: boolean;
    readonly structuredContent?: {
      readonly error?: { readonly code?: string };
    };
  };
  const cancelled = new AbortController();
  cancelled.abort();
  const cancelledContext = { mcpReq: { signal: cancelled.signal } };
  const cancelledObjdump = (await objdump(
    { path: "package.json", operation: "file_headers" },
    cancelledContext,
  )) as { readonly isError?: boolean };
  const cancelledRizin = (await rizin(
    { path: "package.json", command: "iI" },
    cancelledContext,
  )) as { readonly isError?: boolean };

  expect(success.isError).not.toBe(true);
  expect(objdumpFailure.isError).toBe(true);
  expect(failure.isError).toBe(true);
  expect(cancelledObjdump.isError).toBe(true);
  expect(cancelledRizin.isError).toBe(true);
});

it("does not treat a malformed partial observation as retained Evidence", async () => {
  const { server, handler } = createReverseEngineeringMcpHarness();
  const invalidError = Object.assign(
    new AnalysisInputError("execute_rizin_command"),
    { partialObservation: { evidence_id: 42 } },
  );
  const service = {
    inspectWithObjdump: async () => err(invalidError),
    executeRizinCommand: async () => err(invalidError),
  } as unknown as ReverseEngineeringService;
  const recordEvidence = vi.fn(() => ok("added" as const));
  registerReverseEngineeringTools(
    server,
    service,
    pino({ enabled: false }),
    createToolResultDelivery(2 * 1024 * 1024),
    recordEvidence,
  );
  const invoke = handler("execute_rizin_command");

  const response = (await invoke(
    { path: "package.json", command: "iI" },
    { mcpReq: { signal: new AbortController().signal } },
  )) as { readonly isError?: boolean };

  expect(response.isError).toBe(true);
  expect(recordEvidence).not.toHaveBeenCalled();
});

it("keeps provider execution and Evidence recording inside analysis admission", async () => {
  const { server, handler } = createReverseEngineeringMcpHarness();
  const events: string[] = [];
  const service = new ReverseEngineeringService({
    run: async () => {
      events.push("provider");
      return { stdout: "objdump output", stderr: "" };
    },
  });
  const recordEvidence = vi.fn(() => {
    events.push("record");
    return ok("added" as const);
  });
  const admission: WithAdmittedAnalysis = async (_name, _signal, operation) => {
    events.push("admission-start");
    const result = await operation({} as AnalysisOperationPort);
    events.push("admission-end");
    return ok(result);
  };
  registerReverseEngineeringTools(
    server,
    service,
    pino({ enabled: false }),
    createToolResultDelivery(2 * 1024 * 1024),
    recordEvidence,
    admission,
  );
  const invoke = handler("inspect_with_objdump");

  await invoke(
    { path: "package.json", operation: "file_headers" },
    { mcpReq: { signal: new AbortController().signal } },
  );

  expect(events).toEqual([
    "admission-start",
    "provider",
    "record",
    "admission-end",
  ]);
});

it("returns admission failures without invoking a reverse-engineering provider", async () => {
  const { server, handler } = createReverseEngineeringMcpHarness();
  const inspectWithObjdump = vi.fn();
  const service = {
    inspectWithObjdump,
    executeRizinCommand: vi.fn(),
  } as unknown as ReverseEngineeringService;
  const admission: WithAdmittedAnalysis = async () =>
    err(new AnalysisInputError("inspect_with_objdump"));
  registerReverseEngineeringTools(
    server,
    service,
    pino({ enabled: false }),
    createToolResultDelivery(2 * 1024 * 1024),
    undefined,
    admission,
  );
  const invoke = handler("inspect_with_objdump");

  const response = (await invoke(
    { path: "package.json", operation: "file_headers" },
    { mcpReq: { signal: new AbortController().signal } },
  )) as { readonly isError?: boolean };

  expect(response.isError).toBe(true);
  expect(inspectWithObjdump).not.toHaveBeenCalled();
});
