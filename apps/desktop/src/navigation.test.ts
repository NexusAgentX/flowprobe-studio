import { describe, expect, it } from "vitest";

import { PRODUCT_SURFACES, surfaceForShortcut } from "./navigation";

function shortcut(key: string, overrides: Partial<KeyboardEvent> = {}) {
  return {
    altKey: false,
    ctrlKey: true,
    key,
    metaKey: false,
    shiftKey: false,
    ...overrides,
  };
}

describe("product navigation", () => {
  it("keeps the four product boundaries explicit and ordered", () => {
    expect(PRODUCT_SURFACES.map(({ id, label }) => ({ id, label }))).toEqual([
      { id: "proxy", label: "Proxy" },
      { id: "capture", label: "Capture" },
      { id: "analyze", label: "Analyze" },
      { id: "settings", label: "Settings" },
    ]);
  });

  it("maps Control or Command number shortcuts without stealing modified combinations", () => {
    expect(surfaceForShortcut(shortcut("1"))).toBe("proxy");
    expect(surfaceForShortcut(shortcut("2", { ctrlKey: false, metaKey: true }))).toBe("capture");
    expect(surfaceForShortcut(shortcut("3"))).toBe("analyze");
    expect(surfaceForShortcut(shortcut("4"))).toBe("settings");
    expect(surfaceForShortcut(shortcut("2", { altKey: true }))).toBeNull();
    expect(surfaceForShortcut(shortcut("2", { shiftKey: true }))).toBeNull();
    expect(surfaceForShortcut(shortcut("9"))).toBeNull();
    expect(surfaceForShortcut(shortcut("1", { ctrlKey: false }))).toBeNull();
  });
});
