import pino from "pino";
import { Cli, z } from "incur";
import { afterEach, expect, it, vi } from "vitest";

import { registerReverseEngineeringCommands } from "../../../src/cli/reverseEngineeringCommands.js";
import { CLI_COMMANDS } from "../../../src/cliCommandNames.js";
import {
  AnalysisCancelledError,
  AnalysisTimeoutError,
  AnalysisOutputError,
} from "../../../src/domain/analysisErrorCore.js";
import { projectAnalysisError } from "../../../src/domain/analysisErrorProjection.js";
import { createEvidence } from "../../../src/domain/evidence.js";
import { err, ok } from "../../../src/domain/result.js";
import { RizinDebugSessionManager } from "../../../src/rizin/RizinDebugSessionManager.js";
import type { CliInstance } from "../../../src/cli/types.js";
import type { ReverseEngineeringService } from "../../../src/application/reverse/ReverseEngineeringService.js";

const originalExitCode = process.exitCode;

afterEach(() => {
  process.exitCode = originalExitCode;
});

const observation = (completionStatus: "complete" | "unknown") =>
  createEvidence(
    undefined,
    { id: "gnu.objdump", name: "GNU objdump", version: null },
    {
      predicateType: "rea.reverse-engineering.command-observation",
      operation: "inspect_with_objdump",
      parameters: { operation: "file_headers" },
      result: { completion_status: completionStatus },
      rawResult: { completion_status: completionStatus },
    },
  );

const runObjdump = async (service: Partial<ReverseEngineeringService>) => {
  const commands = new Map<
    string,
    {
      run(input: {
        args: { path: string; operation: string };
        options: { followDebugLinks: boolean };
      }): Promise<unknown>;
    }
  >();
  const cli = {
    command: (
      name: string,
      definition: {
        run(input: {
          args: { path: string; operation: string };
          options: { followDebugLinks: boolean };
        }): Promise<unknown>;
      },
    ) => {
      commands.set(name, definition);
      return cli;
    },
  } as unknown as CliInstance;
  registerReverseEngineeringCommands(
    cli,
    pino({ enabled: false }),
    {},
    undefined,
    () => service as ReverseEngineeringService,
  );
  const command = commands.get(CLI_COMMANDS.inspectWithObjdump);
  if (command === undefined)
    throw new Error("objdump CLI command was not registered");
  return command.run({
    args: { path: "/tmp/sample", operation: "file_headers" },
    options: { followDebugLinks: false },
  });
};

it("returns complete Evidence after a successful retry of cleanup-only failure", async () => {
  const evidence = observation("complete");
  const error = Object.assign(
    new AnalysisOutputError(
      "inspect_with_objdump",
      "Provider process cleanup remains incomplete.",
      {
        cleanup: { reason: "first stop incomplete", resources: ["owned-run"] },
        partialObservation: evidence,
      },
    ),
    { cleanupOnly: true },
  );
  const service = {
    inspectWithObjdump: vi.fn(async () => err(error)),
    close: vi.fn(async () => undefined),
  };

  const result = await runObjdump(service);

  expect(result).toEqual(evidence);
  expect(service.close).toHaveBeenCalledOnce();
});

it("clears recovered cleanup state without promoting unknown Evidence", async () => {
  const evidence = observation("unknown");
  const error = Object.assign(
    new AnalysisOutputError(
      "inspect_with_objdump",
      "Provider process cleanup remains incomplete.",
      {
        cleanup: { reason: "first stop incomplete", resources: ["owned-run"] },
        partialObservation: evidence,
      },
    ),
    { cleanupOnly: true },
  );
  const service = {
    inspectWithObjdump: vi.fn(async () => err(error)),
    close: vi.fn(async () => undefined),
  };

  const result = await runObjdump(service);

  expect(result).toMatchObject({
    code: "unreadable_output",
    details: {
      partial_observation: {
        normalized_result: { completion_status: "unknown" },
      },
    },
  });
});

it("preserves an independent timeout after cleanup succeeds", async () => {
  const evidence = observation("unknown");
  const error = new AnalysisTimeoutError("inspect_with_objdump", 1_000, {
    cleanup: { reason: "first stop incomplete", resources: ["owned-run"] },
    partialObservation: evidence,
  });
  const service = {
    inspectWithObjdump: vi.fn(async () => err(error)),
    close: vi.fn(async () => undefined),
  };

  const result = await runObjdump(service);

  expect(result).toMatchObject({
    code: "provider_timeout",
    details: {
      partial_observation: {
        normalized_result: { completion_status: "unknown" },
      },
    },
  });
  expect(error.cleanupIncomplete).toBe(false);
  expect(projectAnalysisError(error).details).not.toHaveProperty("cleanup");
});

it("does not project cancellation cleanup as incomplete after a successful retry", async () => {
  const error = new AnalysisCancelledError("inspect_with_objdump", {
    cleanup: { reason: "first stop incomplete", resources: ["owned-run"] },
    partialObservation: observation("unknown"),
  });
  const service = {
    inspectWithObjdump: vi.fn(async () => err(error)),
    close: vi.fn(async () => undefined),
  };

  await runObjdump(service);

  expect(error.cleanupIncomplete).toBe(false);
  expect(projectAnalysisError(error).details).toMatchObject({
    cleanup: "complete",
  });
});

it("parses the Rizin inferior TTY as an option and passes it to the manager", async () => {
  const commands = new Map<
    string,
    {
      run(input: {
        args: Record<string, unknown>;
        options: Record<string, unknown>;
      }): Promise<unknown>;
    }
  >();
  const cli = {
    command: (
      name: string,
      definition: {
        run(input: {
          args: Record<string, unknown>;
          options: Record<string, unknown>;
        }): Promise<unknown>;
      },
    ) => {
      commands.set(name, definition);
      return cli;
    },
  } as unknown as CliInstance;
  const evidence = createEvidence(
    undefined,
    { id: "rizin.debugger", name: "Rizin debugger", version: null },
    {
      predicateType: "rea.debugger.command-observation",
      operation: "rizin_debug_command",
      parameters: {
        session_id: "session-1",
        command: "dr",
        inferior_tty: "/dev/pts/7",
      },
      result: { output: "registers" },
      rawResult: { output: "registers" },
    },
  );
  const start = vi
    .spyOn(RizinDebugSessionManager.prototype, "start")
    .mockResolvedValue(ok({ session_id: "session-1", backend: null }));
  const execute = vi
    .spyOn(RizinDebugSessionManager.prototype, "execute")
    .mockResolvedValue(
      ok({
        evidence,
        result: {
          command: "dr",
          output: "registers",
          output_scope: "command_and_interleaved_session_output",
          output_truncated: false,
          completion_status: "complete",
          backend: null,
        },
      }),
    );
  vi.spyOn(RizinDebugSessionManager.prototype, "close").mockResolvedValue(
    ok({ target_state: "unknown" }),
  );
  vi.spyOn(RizinDebugSessionManager.prototype, "closeAll").mockResolvedValue(
    undefined,
  );
  registerReverseEngineeringCommands(cli, pino({ enabled: false }), {});
  const command = commands.get(CLI_COMMANDS.debugWithRizin);
  if (command === undefined)
    throw new Error("Rizin CLI command was not registered");

  await command.run({
    args: { path: "./sample.bin", command: "dr" },
    options: { inferiorTty: "/dev/pts/7" },
  });

  expect(start).toHaveBeenCalledWith(
    { path: "./sample.bin", command: "dr", inferior_tty: "/dev/pts/7" },
    expect.any(AbortSignal),
  );
  expect(execute).toHaveBeenCalledWith(
    "session-1",
    "dr",
    expect.any(AbortSignal),
  );

  const parserCli = Cli.create("rea-test", { version: "1.0.0", sync: false });
  registerReverseEngineeringCommands(
    parserCli as unknown as CliInstance,
    pino({ enabled: false }),
    {},
  );
  const commandContract = Cli.toCommands
    .get(parserCli)
    ?.get(CLI_COMMANDS.debugWithRizin);
  expect(commandContract).toBeDefined();
  const argsSchema =
    commandContract === undefined
      ? undefined
      : Reflect.get(commandContract, "args");
  const optionsSchema =
    commandContract === undefined
      ? undefined
      : Reflect.get(commandContract, "options");
  if (
    !(argsSchema instanceof z.ZodObject) ||
    !(optionsSchema instanceof z.ZodObject)
  )
    throw new Error("Rizin CLI args/options schemas were not registered");
  expect(argsSchema.parse({ path: "./sample.bin", command: "dr" })).toEqual({
    path: "./sample.bin",
    command: "dr",
  });
  expect(optionsSchema.parse({ inferiorTty: "/dev/pts/7" })).toMatchObject({
    inferiorTty: "/dev/pts/7",
  });
});
