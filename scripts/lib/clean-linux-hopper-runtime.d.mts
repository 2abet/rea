export function assertCleanLinuxHopperRuntime(
  launcherPaths?: readonly string[],
  procRoot?: string,
  listProcesses?: () => Promise<{ stdout: string }>,
): Promise<void>;
