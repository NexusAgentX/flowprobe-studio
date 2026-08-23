/// <reference types="node" />

import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const stylesheet = readFileSync(new URL("./styles.css", import.meta.url), "utf8");

function declarationsFor(selector: string): string {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = new RegExp(`${escaped}\\s*\\{([^}]*)\\}`, "m").exec(stylesheet);
  if (match?.[1] === undefined) {
    throw new Error(`missing CSS rule for ${selector}`);
  }
  return match[1];
}

function declaration(selector: string, property: string): string {
  const declarations = declarationsFor(selector);
  const match = new RegExp(`(?:^|;)\\s*${property}:\\s*([^;]+)`, "m").exec(declarations);
  if (match?.[1] === undefined) {
    throw new Error(`missing ${property} declaration for ${selector}`);
  }
  return match[1].trim();
}

function relativeLuminance(hex: string): number {
  const channels = /^#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(hex);
  if (channels === null) {
    throw new Error(`expected six-digit hex color, received ${hex}`);
  }

  const linear = channels.slice(1).map((channel) => {
    const value = Number.parseInt(channel, 16) / 255;
    return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * linear[0]! + 0.7152 * linear[1]! + 0.0722 * linear[2]!;
}

function contrastRatio(foreground: string, background: string): number {
  const foregroundLuminance = relativeLuminance(foreground);
  const backgroundLuminance = relativeLuminance(background);
  const light = Math.max(foregroundLuminance, backgroundLuminance);
  const dark = Math.min(foregroundLuminance, backgroundLuminance);
  return (light + 0.05) / (dark + 0.05);
}

describe("small-text contrast", () => {
  it("keeps every 10px text treatment at or above WCAG AA normal-text contrast", () => {
    const samples = [
      {
        label: "navigation shortcut",
        foreground: declaration(".nav-item kbd", "color"),
        background: declaration(".nav-item kbd", "background"),
      },
      {
        label: "Traffic table heading",
        foreground: declaration("th", "color"),
        background: declaration("th", "background"),
      },
      {
        label: "Traffic secondary text on a hovered row",
        foreground: declaration(".subtle", "color"),
        background: declaration("tbody tr:hover", "background"),
      },
      {
        label: "Traffic secondary text on the light panel",
        foreground: declaration(".subtle", "color"),
        background: "#ffffff",
      },
      {
        label: "semantic namespace",
        foreground: declaration(".semantic-card header p", "color"),
        background: declaration(".semantic-card", "background"),
      },
      {
        label: "semantic timestamp",
        foreground: declaration(".semantic-card time", "color"),
        background: declaration(".semantic-card", "background"),
      },
    ];

    expect(declaration(".nav-item kbd", "font-size")).toBe("10px");
    expect(declaration("th", "font-size")).toBe("10px");
    expect(declaration(".subtle", "font-size")).toBe("10px");
    expect(declaration(".semantic-card header p", "font-size")).toBe("10px");
    expect(declaration(".semantic-card time", "font-size")).toBe("10px");

    for (const sample of samples) {
      expect(contrastRatio(sample.foreground, sample.background), sample.label).toBeGreaterThanOrEqual(4.5);
    }
  });
});
