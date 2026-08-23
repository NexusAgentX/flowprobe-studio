import type { SemanticOutputItem, TrafficListItem } from "./ipc";

export const TRAFFIC_PAGE_SIZE = 20;
export const SEMANTIC_PAGE_SIZE = 12;

export function appendTrafficItems(
  current: readonly TrafficListItem[],
  incoming: readonly TrafficListItem[],
): TrafficListItem[] {
  const byIdentity = new Map(current.map((item) => [item.flowId, item]));
  for (const item of incoming) {
    byIdentity.set(item.flowId, item);
  }
  return [...byIdentity.values()];
}

export function appendSemanticItems(
  current: readonly SemanticOutputItem[],
  incoming: readonly SemanticOutputItem[],
): SemanticOutputItem[] {
  const byIdentity = new Map(current.map((item) => [item.eventId, item]));
  for (const item of incoming) {
    byIdentity.set(item.eventId, item);
  }
  return [...byIdentity.values()];
}

export function destinationLabel(item: TrafficListItem): string {
  const address = item.destinationHost ?? item.destinationIp ?? "unknown destination";
  const socketAddress = address.includes(":") && !address.startsWith("[") ? `[${address}]` : address;
  return `${socketAddress}:${item.destinationPort}`;
}

export function timestampLabel(timestampNs: string): string {
  try {
    const milliseconds = BigInt(timestampNs) / 1_000_000n;
    const value = Number(milliseconds);
    if (!Number.isSafeInteger(value)) {
      return `${timestampNs} ns`;
    }
    return new Date(value).toISOString();
  } catch {
    return `${timestampNs} ns`;
  }
}
