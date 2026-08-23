export type SurfaceId = "proxy" | "capture" | "analyze" | "settings";

export interface ProductSurface {
  id: SurfaceId;
  label: string;
  shortcut: string;
}

export const PRODUCT_SURFACES: readonly ProductSurface[] = [
  { id: "proxy", label: "Proxy", shortcut: "1" },
  { id: "capture", label: "Capture", shortcut: "2" },
  { id: "analyze", label: "Analyze", shortcut: "3" },
  { id: "settings", label: "Settings", shortcut: "4" },
] as const;

export function surfaceForShortcut(event: Pick<KeyboardEvent, "altKey" | "ctrlKey" | "key" | "metaKey" | "shiftKey">): SurfaceId | null {
  if ((!event.metaKey && !event.ctrlKey) || event.altKey || event.shiftKey) {
    return null;
  }

  return PRODUCT_SURFACES.find((surface) => surface.shortcut === event.key)?.id ?? null;
}
