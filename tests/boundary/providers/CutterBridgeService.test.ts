import { expect, it } from "vitest";

import { CutterBridgeService } from "../../../src/cutter/CutterBridgeService.js";

it("retains uncertain command completion as Evidence without encouraging a retry", async () => {
  const service = new CutterBridgeService({
    listSessions: async () => ({
      sessions: [],
      bridge_directory: "/private/bridge",
      discovery_status: "no_live_bridge_found",
      bridge_directory_security: "private_verified",
    }),
    execute: async () => ({
      output: null,
      currentFile: "/fixtures/sample.bin",
      documentGeneration: 7,
      identityStatus: "partial",
      cutterVersion: "Cutter fixture version",
      executionState: "unknown",
      error: "transport-response-missing",
      message: "The command may have completed; do not retry automatically",
      outputTruncated: false,
    }),
  });

  const result = await service.execute({
    session_id: "27d3e3f1-f1e5-49ae-91ec-95af1f343a5a",
    expected_generation: 7,
    command: "Ps /tmp/project.rzdb",
  });

  expect(result.ok).toBe(false);
  if (result.ok) throw new Error("unknown command completion must fail");
  expect(result.error.partialObservation).toMatchObject({
    normalized_result: {
      command: "Ps /tmp/project.rzdb",
      output: null,
      execution_state: "unknown",
      error: "transport-response-missing",
      message: expect.stringContaining("do not retry automatically"),
      document_generation: 7,
      cutter_version: "Cutter fixture version",
    },
    limitations: expect.arrayContaining([
      "Command completion or its output could not be confirmed; do not retry automatically because the command may have produced partial or persistent effects.",
    ]),
    provider: { version: "Cutter fixture version" },
  });
});

const cutterInput = {
  session_id: "27d3e3f1-f1e5-49ae-91ec-95af1f343a5a",
  expected_generation: 7,
  command: "pd 4",
};

it("rejects malformed Cutter commands and pre-aborted calls", async () => {
  const service = new CutterBridgeService({
    listSessions: async () => ({
      sessions: [],
      bridge_directory: "/private/bridge",
      discovery_status: "no_live_bridge_found",
      bridge_directory_security: "private_verified",
    }),
    execute: async () => {
      throw new Error("must not dispatch");
    },
  });

  const malformed = await service.execute({ ...cutterInput, command: "" });
  expect(malformed).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisInputError" },
  });
  const controller = new AbortController();
  controller.abort();
  const cancelled = await service.execute(cutterInput, {
    signal: controller.signal,
  });
  expect(cancelled).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisCancelledError" },
  });
});

it.each([
  [new Error("session generation changed"), "AnalysisInputError"],
  [new Error("bridge disconnected"), "AnalysisCapabilityUnavailableError"],
  ["plain failure", "AnalysisCapabilityUnavailableError"],
])("maps a Cutter bridge failure to %s", async (failure, tag) => {
  const service = new CutterBridgeService({
    listSessions: async () => ({
      sessions: [],
      bridge_directory: "/private/bridge",
      discovery_status: "no_live_bridge_found",
      bridge_directory_security: "private_verified",
    }),
    execute: async () => {
      throw failure;
    },
  });

  const result = await service.execute(cutterInput);
  expect(result).toMatchObject({ ok: false, error: { _tag: tag } });
});

it("preserves cancellation unless the bridge reports an ambiguous completion", async () => {
  const createService = (message: string, controller: AbortController) =>
    new CutterBridgeService({
      listSessions: async () => ({
        sessions: [],
        bridge_directory: "/private/bridge",
        discovery_status: "no_live_bridge_found",
        bridge_directory_security: "private_verified",
      }),
      execute: async () => {
        controller.abort();
        throw new Error(message);
      },
    });
  const cancelledController = new AbortController();

  const cancelled = await createService(
    "transport cancelled",
    cancelledController,
  ).execute(cutterInput, { signal: cancelledController.signal });
  expect(cancelled).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisCancelledError" },
  });

  const uncertainController = new AbortController();
  const uncertain = await createService(
    "command may have completed",
    uncertainController,
  ).execute(cutterInput, { signal: uncertainController.signal });
  expect(uncertain).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisCapabilityUnavailableError" },
  });
});

it("retains the same cleanup failure until a live Cutter status probe succeeds", async () => {
  let live = false;
  const service = new CutterBridgeService({
    listSessions: async () => ({
      sessions: live
        ? [
            {
              session_id: cutterInput.session_id,
              pid: 42,
              document_generation: cutterInput.expected_generation,
              current_file: "/fixtures/sample.bin",
              cutter_version: null,
              identity_status: "partial" as const,
            },
          ]
        : [],
      bridge_directory: "/private/bridge",
      discovery_status: live ? "sessions_found" : "no_live_bridge_found",
      bridge_directory_security: "private_verified",
    }),
    execute: async () => ({
      output: null,
      currentFile: "/fixtures/sample.bin",
      documentGeneration: cutterInput.expected_generation,
      identityStatus: "partial",
      cutterVersion: null,
      executionState: "unknown",
      error: "transport-response-missing",
      message: "The command may have completed; do not retry automatically",
      outputTruncated: false,
    }),
  });

  const execution = await service.execute(cutterInput);
  expect(execution.ok).toBe(false);
  if (execution.ok) throw new Error("ambiguous completion must retain cleanup");
  const failure = execution.error;
  expect(failure.cleanupIncomplete).toBe(true);
  const disconnected = await service.retryCleanup();
  expect(disconnected).toMatchObject({ ok: false, error: failure });
  expect(failure.cleanupIncomplete).toBe(true);

  live = true;
  expect(await service.retryCleanup()).toMatchObject({ ok: true, value: null });
  expect(failure.cleanupIncomplete).toBe(false);
});
