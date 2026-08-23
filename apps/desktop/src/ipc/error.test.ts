import { describe, expect, it } from "vitest";

import { describeIpcFailure, isIpcError } from "./error";

describe("IPC error presentation", () => {
  it("recognizes typed supervisor failures", () => {
    const error = { code: "notFound", message: "traffic flow was not found" };
    expect(isIpcError(error)).toBe(true);
    expect(describeIpcFailure(error)).toBe("traffic flow was not found");
  });

  it("does not expose framework errors, paths, or unknown typed codes", () => {
    expect(describeIpcFailure(new Error("IPC failed at /Users/private/metadata.sqlite3"))).toBe(
      "The local supervisor did not return a readable error.",
    );
    expect(describeIpcFailure({ sql: "SELECT secret FROM payloads" })).toBe(
      "The local supervisor did not return a readable error.",
    );
    expect(describeIpcFailure({ code: "database", message: "/private/database.sqlite3" })).toBe(
      "The local supervisor did not return a readable error.",
    );
  });
});
