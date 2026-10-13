import { mutationRange } from "./scripts/lib/reverse-tools-mutation-targets.mjs";

const config = {
  $schema: "./node_modules/@stryker-mutator/core/schema/stryker-schema.json",
  testRunner: "command",
  commandRunner: {
    command: "npx vitest run --config vitest.reverse-tools-semantics.config.ts",
  },
  plugins: ["@stryker-mutator/typescript-checker"],
  checkers: ["typescript"],
  tsconfigFile: "tsconfig.reverse-tools-mutation.json",
  typescriptChecker: {
    prioritizePerformanceOverAccuracy: true,
  },
  coverageAnalysis: "off",
  mutate: [],
  thresholds: {
    high: 100,
    low: 100,
    break: 100,
  },
  concurrency: 2,
  timeoutMS: 30000,
  reporters: ["clear-text", "progress", "html", "json"],
};

export default {
  ...config,
  mutate: [
    ...config.mutate,
    mutationRange("src/cutter/CutterBridgeClient.ts", {
      expression: "status.data.current_file === undefined",
    }),
    mutationRange("src/cutter/CutterBridgeClient.ts", {
      expression: "response.current_file === undefined",
    }),
    mutationRange("src/rizin/RizinDebugSessionManager.ts", {
      declaration: "isRizinCommandDeadlineExpired",
    }),
    mutationRange("src/rizin/RizinDebugSessionManager.ts", {
      declaration: "createRizinCommandTimeoutError",
    }),
    mutationRange("src/rizin/RizinDebugSessionManager.ts", {
      declaration: "createRizinCommandTimeoutEvidence",
    }),
  ],
};
