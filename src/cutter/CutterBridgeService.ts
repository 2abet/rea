import { jsonValueSchema } from "../domain/jsonValue.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../domain/analysisErrorCore.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { createEvidence, type Evidence } from "../domain/evidence.js";
import { err, ok, type Result } from "../domain/result.js";
import { cutterCommandInputSchema } from "../contracts/cutterToolContracts.js";
import {
  CutterBridgeClient,
  type CutterBridgeDiscovery,
  type CutterBridgeExecution,
} from "./CutterBridgeClient.js";
import { CUTTER_PROVIDER_IDENTITY } from "./CutterBridgeClient.js";

interface CutterBridgePort {
  listSessions(): Promise<CutterBridgeDiscovery>;
  execute(input: {
    readonly sessionId: string;
    readonly expectedGeneration: number;
    readonly command: string;
    readonly json: boolean;
    readonly signal?: AbortSignal;
  }): Promise<CutterBridgeExecution>;
}

/** Shared Cutter bridge workflows used by the MCP adapter and CLI. */
export class CutterBridgeService {
  readonly #pendingCleanup = new Map<string, AnalysisOutputError>();

  constructor(readonly client: CutterBridgePort = new CutterBridgeClient()) {}

  /** A responsive status round-trip confirms the timed-out UI command has ended. */
  async retryCleanup(): Promise<Result<null, AnalysisError>> {
    for (const [sessionId, failure] of this.#pendingCleanup) {
      const discovery = await this.client.listSessions();
      if (!discovery.sessions.some((session) => session.session_id === sessionId))
        return err(failure);
      failure.resolveCleanup();
      this.#pendingCleanup.delete(sessionId);
    }
    return ok(null);
  }

  listSessions(): Promise<CutterBridgeDiscovery> {
    return this.client.listSessions();
  }

  async execute(
    rawInput: unknown,
    options: { readonly signal?: AbortSignal } = {},
  ): Promise<Result<Evidence, AnalysisError>> {
    const parsed = cutterCommandInputSchema.safeParse(rawInput);
    if (!parsed.success) return err(new AnalysisInputError("cutter_command"));
    if (options.signal?.aborted)
      return err(new AnalysisCancelledError("cutter_command"));
    const input = parsed.data;
    try {
      const output = await this.client.execute({
        sessionId: input.session_id,
        expectedGeneration: input.expected_generation,
        command: input.command,
        json: input.json,
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      });
      const normalizedOutput = jsonValueSchema.parse(output.output);
      const evidence = createEvidence(
        undefined,
        {
          ...CUTTER_PROVIDER_IDENTITY,
          version: output.cutterVersion,
        },
        {
          predicateType: "rea.cutter.command-observation",
          operation: "cutter_command",
          parameters: {
            session_id: input.session_id,
            expected_generation: input.expected_generation,
            command: input.command,
            json: input.json,
          },
          result: {
            command: input.command,
            output: normalizedOutput,
            execution_state: output.executionState,
            error: output.error,
            message: output.message,
            output_truncated: output.outputTruncated,
            cutter_version: output.cutterVersion,
            current_file: output.currentFile,
            document_generation: output.documentGeneration,
            identity_status: output.identityStatus,
          },
          rawResult: normalizedOutput,
          subjectUnavailableReason:
            "Cutter exposes no verified stable identity for the active unsaved document or tab.",
          limitations: [
            "Document identity is partial: the bridge uses a plugin instance UUID and observed generation; a same-path tab switch or reload may not be distinguishable.",
            "Cutter command effects depend on the Rizin command and active plugins.",
            "The local IPC protocol is implemented by REA and is not an upstream Cutter API.",
            ...(output.executionState === "unknown"
              ? [
                  "Command completion or its output could not be confirmed; do not retry automatically because the command may have produced partial or persistent effects.",
                ]
              : []),
            ...(output.outputTruncated
              ? [
                  "The command completed or may have completed, but output exceeded the bridge transport limit and was omitted.",
                ]
              : []),
          ],
        },
      );
      if (output.executionState === "unknown") {
        const failure = new AnalysisOutputError(
          "cutter_command",
          "Cutter command completion is unknown; the bound binary remains unavailable until its bridge responds again.",
          {
            cleanup: {
              reason: "The Cutter UI thread may still be running the dispatched command.",
              resources: [`cutter-session:${input.session_id}`],
            },
            partialObservation: evidence,
          },
        );
        this.#pendingCleanup.set(input.session_id, failure);
        return err(failure);
      }
      return ok(evidence);
    } catch (cause) {
      const message =
        cause instanceof Error
          ? cause.message
          : "Unknown Cutter bridge failure";
      if (options.signal?.aborted && !message.includes("may have completed"))
        return err(new AnalysisCancelledError("cutter_command", { cause }));
      return err(
        message.includes("generation changed") ||
          message.includes("unavailable or stale")
          ? new AnalysisInputError("cutter_command", { cause })
          : new AnalysisCapabilityUnavailableError(
              "cutter",
              "cutter_command",
              message,
              { cause },
            ),
      );
    }
  }
}
