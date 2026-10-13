import type { BinarySessionPort } from "../application/binary/BinarySessionPort.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { AnalysisOutputError } from "../domain/analysisErrorCore.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import type { Evidence } from "../domain/evidence.js";
import { err, type Result } from "../domain/result.js";

export type ExternalMutationAdmission = Pick<
  BinarySessionPort,
  "withAdmittedExternalMutation"
>;

/** Shared MCP admission and failure preservation for unrestricted commands. */
export const runWithExternalMutationAdmission = async <Value>(
  session: ExternalMutationAdmission | undefined,
  operationName: string,
  signal: AbortSignal | undefined,
  operation: () => Promise<Result<Value, AnalysisError>>,
  evidenceOf: (value: Value) => Evidence,
): Promise<Result<Value, AnalysisError>> => {
  if (session === undefined) return operation();
  const admitted = await session.withAdmittedExternalMutation(
    undefined,
    signal,
    operation,
    (value, cause) =>
      value.ok
        ? new AnalysisOutputError(
            operationName,
            "The external command may have changed the bound artifact, but the active analysis session could not be rebound.",
            {
              cause,
              partialObservation: evidenceOf(value.value),
              ...(cause.cleanup === undefined
                ? {}
                : { cleanup: cause.cleanup }),
              ...(cause.capturedOutput === undefined
                ? {}
                : { capturedOutput: cause.capturedOutput }),
            },
          )
        : value.error.retainSecondaryFailure(cause, {
            rebind_error: projectAnalysisError(cause),
          }),
    operationName,
  );
  return admitted.ok ? admitted.value : err(admitted.error);
};
