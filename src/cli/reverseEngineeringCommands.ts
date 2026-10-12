import { z } from "incur";
import type { Logger } from "pino";

import { createReverseEngineeringService } from "../composition/reverseEngineering.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import { AnalysisOutputError } from "../domain/analysisErrorCore.js";
import type { Result } from "../domain/result.js";
import { err } from "../domain/result.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { logCliCommand } from "../cliLogging.js";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import type { ReverseEngineeringService } from "../application/reverse/ReverseEngineeringService.js";
import { GdbSessionManager } from "../gdb/GdbSessionManager.js";

const executeWithCleanup = async <Value>(
  service: ReverseEngineeringService,
  execute: () => Promise<Result<Value, AnalysisError>>,
): Promise<Result<Value, AnalysisError>> => {
  let result: Result<Value, AnalysisError>;
  try {
    result = await execute();
  } catch (cause) {
    try {
      await service.close();
    } catch (cleanupCause) {
      throw new AggregateError(
        [cause, cleanupCause],
        "Reverse-engineering operation and cleanup both failed.",
      );
    }
    throw cause;
  }
  try {
    await service.close();
  } catch (cause) {
    if (result.ok) return err(asCleanupError(cause));
    const cleanup =
      cause instanceof AnalysisError
        ? cause.cleanup
        : undefined;
    const error = new AnalysisOutputError(
      "reverse_engineering_cleanup",
      "Provider cleanup remains incomplete after the command failed.",
      {
        cause: result.error,
        ...(cleanup === undefined ? {} : { cleanup }),
        ...(result.error.capturedOutput === undefined
          ? {}
          : { capturedOutput: result.error.capturedOutput }),
        ...(result.error.partialObservation === undefined
          ? {}
          : { partialObservation: result.error.partialObservation }),
      },
    );
    return err(error);
  }
  return result;
};

const asCleanupError = (cause: unknown): AnalysisError =>
  cause instanceof AnalysisError
    ? cause
    : new AnalysisOutputError(
        "reverse_engineering_cleanup",
        "Provider process cleanup failed.",
        { cause },
      );

/** Add one-shot reverse-engineering commands using the shared service layer. */
export const registerReverseEngineeringCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<NodeJS.ProcessEnv>,
  createGdbManager: (environment: Readonly<NodeJS.ProcessEnv>) => GdbSessionManager =
    (providerEnvironment) => new GdbSessionManager({ environment: providerEnvironment }),
): void => {
  const service = createReverseEngineeringService(environment);
  cli.command(CLI_COMMANDS.inspectWithObjdump, {
    description:
      "Inspect a local artifact with GNU objdump and retain its raw output as Evidence",
    args: z.object({
      path: z
        .string()
        .min(1)
        .describe("Path to the local artifact to inspect."),
      operation: z
        .enum([
          "file_headers",
          "section_headers",
          "symbols",
          "relocations",
          "dwarf",
          "disassemble",
          "disassemble_all",
          "architectures",
        ])
        .describe("GNU objdump inspection operation to run."),
    }),
    options: z.object({
      followDebugLinks: z
        .boolean()
        .default(true)
        .describe(
          "Follow local DWARF debug links. External debug-file identity is not bound to Evidence.",
        ),
    }),
    run: ({ args, options }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, CLI_COMMANDS.inspectWithObjdump, async () => {
          const result = await executeWithCleanup(service, () =>
            service.inspectWithObjdump(
              {
                ...args,
                follow_debug_links: options.followDebugLinks,
              },
              { signal },
            ),
          );
          return result.ok ? result.value : projectAnalysisError(result.error);
        }),
      ),
  });
  cli.command(CLI_COMMANDS.executeRizinCommand, {
    description: "Execute one Rizin command against a local artifact",
    args: z.object({
      path: z
        .string()
        .min(1)
        .describe("Path to the local artifact to analyze."),
      command: z.string().min(1).describe("One caller-selected Rizin command."),
    }),
    run: ({ args }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, CLI_COMMANDS.executeRizinCommand, async () => {
          const result = await executeWithCleanup(service, () =>
            service.executeRizinCommand(args, { signal }),
          );
          return result.ok ? result.value : projectAnalysisError(result.error);
        }),
      ),
  });
  cli.command(CLI_COMMANDS.debugWithGdb, {
    description:
      "Run one unrestricted GDB console command in an ephemeral MI session",
    args: z.object({
      command: z.string().min(1).describe("One unrestricted GDB console command."),
    }),
    run: ({ args }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, CLI_COMMANDS.debugWithGdb, async () => {
          const manager = createGdbManager(environment);
          let sessionId: string | undefined;
          try {
            const started = await manager.start(signal);
            if (!started.ok) return projectAnalysisError(started.error);
            sessionId = started.value.session_id;
            const executed = await manager.execute(sessionId, args.command, signal);
            return executed.ok
              ? executed.value.evidence
              : projectAnalysisError(executed.error);
          } finally {
            let cleanupFailed = false;
            if (sessionId !== undefined) {
              try {
                const closed = await manager.close(sessionId);
                cleanupFailed = !closed.ok;
                if (!closed.ok)
                  logger.error(
                    { command: CLI_COMMANDS.debugWithGdb, cleanup: projectAnalysisError(closed.error) },
                    "GDB cleanup failed after collecting command output",
                  );
              } catch (cause) {
                cleanupFailed = true;
                logger.error(
                  { command: CLI_COMMANDS.debugWithGdb, cleanup: cause instanceof Error ? cause.message : "Unknown cleanup failure" },
                  "GDB cleanup failed after collecting command output",
                );
              }
            }
            try {
              await manager.closeAll();
              cleanupFailed = false;
            } catch (cause) {
              cleanupFailed = true;
              logger.error(
                {
                  command: CLI_COMMANDS.debugWithGdb,
                  cleanup: cause instanceof Error ? cause.message : "Unknown cleanup failure",
                },
                "GDB fallback cleanup failed",
              );
            }
            if (cleanupFailed) process.exitCode = 1;
          }
        }),
      ),
  });
};
