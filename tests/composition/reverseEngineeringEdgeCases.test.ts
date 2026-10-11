import { mkdtemp, rm, truncate, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { expect, it, vi } from "vitest";

import { ReverseEngineeringService } from "../../src/application/reverse/ReverseEngineeringService.js";
import { objdumpCommand } from "../../src/objdump/ObjdumpCommand.js";

const createArtifact = async (): Promise<{
  directory: string;
  path: string;
}> => {
  const directory = await mkdtemp(join(tmpdir(), "rea-reverse-edge-"));
  const path = join(directory, "sample.bin");
  await writeFile(path, "initial artifact");
  return { directory, path };
};

it("uses the local-only DWARF option when debug links are disabled", () => {
  expect(
    objdumpCommand({
      path: "./sample.bin",
      operation: "dwarf",
      follow_debug_links: false,
    }),
  ).toEqual(["-W", "-WN", expect.stringMatching(/sample\.bin$/u)]);
});

it("rejects malformed objdump requests before touching the provider", async () => {
  let invoked = false;
  const service = new ReverseEngineeringService({
    run: async () => {
      invoked = true;
      return { stdout: "", stderr: "" };
    },
  });

  const result = await service.inspectWithObjdump({ path: "/tmp/a" });

  expect(result).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisInputError", operation: "inspect_with_objdump" },
  });
  expect(invoked).toBe(false);
});

it("returns cancellation that arrived before the artifact digest starts", async () => {
  const controller = new AbortController();
  controller.abort();
  const service = new ReverseEngineeringService();

  const result = await service.inspectWithObjdump(
    { path: "/tmp/a", operation: "file_headers" },
    { signal: controller.signal },
  );

  expect(result).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisCancelledError" },
  });
});

it.each([
  ["EACCES", "AnalysisAccessDeniedError"],
  ["EPERM", "AnalysisAccessDeniedError"],
  ["ETIMEDOUT", "AnalysisTimeoutError"],
  ["EINVAL", "AnalysisInputError"],
])(
  "maps artifact digest failure %s to its tagged analysis error",
  async (code, tag) => {
    const { directory, path } = await createArtifact();
    const service = new ReverseEngineeringService({
      digest: async () => {
        throw Object.assign(new Error("digest failure"), { code });
      },
    });

    try {
      const result = await service.inspectWithObjdump({
        path,
        operation: "file_headers",
      });
      expect(result).toMatchObject({ ok: false, error: { _tag: tag } });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);

it("maps cancellation during the initial digest to a cancellation error", async () => {
  const { directory, path } = await createArtifact();
  const controller = new AbortController();
  const service = new ReverseEngineeringService({
    digest: async () => {
      controller.abort();
      throw new Error("digest cancelled");
    },
  });

  try {
    const result = await service.inspectWithObjdump(
      { path, operation: "file_headers" },
      { signal: controller.signal },
    );
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisCancelledError" },
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it("cancels an in-progress file digest through its abort listener", async () => {
  const { directory, path } = await createArtifact();
  const controller = new AbortController();
  Object.defineProperty(controller.signal, "addEventListener", {
    value: (
      type: string,
      listener: Parameters<EventTarget["addEventListener"]>[1],
      options?: boolean | AddEventListenerOptions,
    ): void => {
      EventTarget.prototype.addEventListener.call(
        controller.signal,
        type,
        listener,
        options,
      );
      if (type === "abort") {
        controller.abort();
      }
    },
  });
  const service = new ReverseEngineeringService();

  try {
    const resultPromise = service.inspectWithObjdump(
      { path, operation: "file_headers" },
      { signal: controller.signal },
    );
    const result = await resultPromise;
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisCancelledError" },
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it("rejects a digest when cancellation arrives before stream listeners attach", async () => {
  const { directory, path } = await createArtifact();
  let reads = 0;
  const signal = {
    get aborted() {
      reads += 1;
      return reads > 1;
    },
    addEventListener() {},
    removeEventListener() {},
    throwIfAborted() {},
    onabort: null,
    reason: undefined,
    dispatchEvent: () => true,
  } as AbortSignal;
  const service = new ReverseEngineeringService();

  try {
    const result = await service.inspectWithObjdump(
      { path, operation: "file_headers" },
      { signal },
    );
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisCancelledError" },
    });
    expect(reads).toBe(3);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it("maps the artifact digest deadline to a timeout error", async () => {
  const { directory, path } = await createArtifact();
  await truncate(path, 64 * 1024 * 1024);
  const service = new ReverseEngineeringService();
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });

  try {
    const resultPromise = service.inspectWithObjdump({
      path,
      operation: "file_headers",
    });
    await new Promise<void>((resolve) => setImmediate(resolve));
    await vi.advanceTimersByTimeAsync(120_000);
    const result = await resultPromise;
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisTimeoutError" },
    });
  } finally {
    vi.useRealTimers();
    await rm(directory, { recursive: true, force: true });
  }
});

it.each([
  ["ETIMEDOUT", "AnalysisTimeoutError"],
  ["EACCES", "AnalysisAccessDeniedError"],
  ["EPERM", "AnalysisAccessDeniedError"],
  ["unknown", "AnalysisCapabilityUnavailableError"],
])(
  "maps provider failure %s to its tagged analysis error",
  async (code, tag) => {
    const { directory, path } = await createArtifact();
    const service = new ReverseEngineeringService({
      run: async () => {
        if (code === "unknown") throw new Error("provider failure");
        throw Object.assign(new Error("provider failure"), { code });
      },
    });

    try {
      const result = await service.inspectWithObjdump({
        path,
        operation: "file_headers",
      });
      expect(result).toMatchObject({ ok: false, error: { _tag: tag } });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);

it("records a changed artifact and unknown post-run digest separately", async () => {
  const { directory, path } = await createArtifact();
  const changed = new ReverseEngineeringService({
    run: async () => {
      await writeFile(path, "changed during provider execution");
      return { stdout: "observed", stderr: "" };
    },
  });
  const removed = new ReverseEngineeringService({
    run: async () => {
      await rm(path);
      return { stdout: "observed", stderr: "" };
    },
  });

  try {
    const changedResult = await changed.inspectWithObjdump({
      path,
      operation: "file_headers",
    });
    expect(changedResult).toMatchObject({
      ok: true,
      value: {
        raw_result: { artifact_changed: true },
        limitations: expect.arrayContaining([
          expect.stringContaining("may have changed"),
        ]),
      },
    });

    await writeFile(path, "restore for second digest");
    const removedResult = await removed.inspectWithObjdump({
      path,
      operation: "file_headers",
    });
    expect(removedResult).toMatchObject({
      ok: true,
      value: {
        raw_result: { artifact_sha256_after: null, artifact_changed: null },
        limitations: expect.arrayContaining([
          expect.stringContaining("post-run artifact digest"),
        ]),
      },
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it("maps an unavailable Rizin command to the Rizin capability error", async () => {
  const { directory, path } = await createArtifact();
  const service = new ReverseEngineeringService({
    run: async () => {
      throw Object.assign(new Error("not found"), { code: "ENOENT" });
    },
  });

  try {
    const result = await service.executeRizinCommand({ path, command: "iI" });
    expect(result).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisCapabilityUnavailableError",
        providerId: "rizin",
      },
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
