import pino from "pino";
import type { McpServer } from "@modelcontextprotocol/server";
import { expect, it, vi } from "vitest";

import { ReverseEngineeringService } from "../../../src/application/reverse/ReverseEngineeringService.js";
import { EvidenceIntegrityError } from "../../../src/domain/evidenceErrors.js";
import { err, ok } from "../../../src/domain/result.js";
import { createToolResultDelivery } from "../../../src/server/toolResult.js";
import { registerReverseEngineeringTools } from "../../../src/server/registerReverseEngineeringTools.js";

it("records partial Evidence and references it in the original MCP error", async () => {
  const registrations = new Map<
    string,
    (input: unknown, context: unknown) => Promise<unknown>
  >();
  const server = {
    registerTool: (
      name: string,
      _options: unknown,
      handler: (input: unknown, context: unknown) => Promise<unknown>,
    ) => registrations.set(name, handler),
  } as unknown as McpServer;
  const service = new ReverseEngineeringService({
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
  const recordEvidence = vi.fn(() => ok("added" as const));
  registerReverseEngineeringTools(
    server,
    service,
    pino({ enabled: false }),
    createToolResultDelivery(2 * 1024 * 1024),
    recordEvidence,
  );
  const invoke = registrations.get("execute_rizin_command");
  if (invoke === undefined) throw new Error("Rizin MCP handler was not registered");

  const response = (await invoke(
    { path: "package.json", command: "iI" },
    { mcpReq: { signal: new AbortController().signal } },
  )) as {
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

it("preserves a partial MCP error without claiming failed Evidence retention", async () => {
  const registrations = new Map<
    string,
    (input: unknown, context: unknown) => Promise<unknown>
  >();
  const server = {
    registerTool: (
      name: string,
      _options: unknown,
      handler: (input: unknown, context: unknown) => Promise<unknown>,
    ) => registrations.set(name, handler),
  } as unknown as McpServer;
  const service = new ReverseEngineeringService({
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
  const invoke = registrations.get("execute_rizin_command");
  if (invoke === undefined) throw new Error("Rizin MCP handler was not registered");

  const response = (await invoke(
    { path: "package.json", command: "iI" },
    { mcpReq: { signal: new AbortController().signal } },
  )) as {
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
