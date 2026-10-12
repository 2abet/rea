import type { ReverseEngineeringServiceRuntimeOptions } from "../application/reverse/ReverseEngineeringService.js";
import { ReverseEngineeringService } from "../application/reverse/ReverseEngineeringService.js";
import { objdumpCommand, OBJDUMP_PROVIDER_IDENTITY } from "../objdump/ObjdumpCommand.js";
import { rizinCommand, RIZIN_PROVIDER_IDENTITY } from "../rizin/RizinCommand.js";
import type { ReverseEngineeringCommandPort } from "../application/reverse/ReverseEngineeringCommandPort.js";

export const createReverseEngineeringCommandPort = (
  environment: Readonly<NodeJS.ProcessEnv>,
): ReverseEngineeringCommandPort => ({
  objdump: (input) => ({
    executable: environment.REA_OBJDUMP_COMMAND ?? "objdump",
    arguments: objdumpCommand(input),
    identity: OBJDUMP_PROVIDER_IDENTITY,
    environmentOverrides: { DEBUGINFOD_URLS: "" },
  }),
  rizin: (input) => ({
    executable: environment.REA_RIZIN_COMMAND ?? "rizin",
    arguments: rizinCommand(input),
    identity: RIZIN_PROVIDER_IDENTITY,
  }),
});

/** Compose BYO reverse-engineering commands without acquiring tools at import time. */
export const createReverseEngineeringService = (
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
  options: ReverseEngineeringServiceRuntimeOptions = {},
): ReverseEngineeringService =>
  new ReverseEngineeringService({
    ...options,
    environment,
    commands: createReverseEngineeringCommandPort(environment),
  });
