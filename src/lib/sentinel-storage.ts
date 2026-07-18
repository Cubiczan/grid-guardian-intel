import type { ThreatBrief, OsintAsset } from "./sentinel.functions";

// ─── Persistence keys ──────────────────────────────────────────
const K_BRIEFS = "sentinel:briefs";
const K_WATCH = "sentinel:watch";
const K_SNAPSHOT = "sentinel:snapshot";
const K_AUDIT = "sentinel:audit";
const K_WEBHOOK = "sentinel:webhook";

function read<T>(key: string, fallback: T): T {
  if (typeof localStorage === "undefined") return fallback;
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}
function write(key: string, v: unknown) {
  if (typeof localStorage === "undefined") return;
  try {
    localStorage.setItem(key, JSON.stringify(v));
  } catch {
    /* ignore quota */
  }
}

// ─── Briefs cache (keyed by asset.id = ip:port) ────────────────
export function loadBriefs(): Record<string, ThreatBrief> {
  return read(K_BRIEFS, {});
}
export function saveBrief(brief: ThreatBrief) {
  const cur = loadBriefs();
  cur[brief.asset.id] = brief;
  write(K_BRIEFS, cur);
}

// ─── Watchlist (starred asset IDs → full asset snapshot) ───────
export type WatchEntry = { asset: OsintAsset; addedAt: string };
export function loadWatch(): Record<string, WatchEntry> {
  return read(K_WATCH, {});
}
export function toggleWatch(asset: OsintAsset): boolean {
  const cur = loadWatch();
  const has = Boolean(cur[asset.id]);
  if (has) delete cur[asset.id];
  else cur[asset.id] = { asset, addedAt: new Date().toISOString() };
  write(K_WATCH, cur);
  return !has;
}

// ─── Snapshot / diff (per query) ───────────────────────────────
export type Snapshot = { at: string; ids: string[] };
export type SnapshotMap = Record<string, Snapshot>;
export function loadSnapshot(query: string): Snapshot | null {
  const all = read<SnapshotMap>(K_SNAPSHOT, {});
  return all[query] ?? null;
}
export function saveSnapshot(query: string, ids: string[]) {
  const all = read<SnapshotMap>(K_SNAPSHOT, {});
  all[query] = { at: new Date().toISOString(), ids };
  write(K_SNAPSHOT, all);
}
export function diffSnapshot(prev: Snapshot | null, ids: string[]) {
  if (!prev) return { added: [] as string[], closed: [] as string[], first: true };
  const p = new Set(prev.ids);
  const c = new Set(ids);
  return {
    added: ids.filter((i) => !p.has(i)),
    closed: prev.ids.filter((i) => !c.has(i)),
    first: false,
  };
}

// ─── Audit log ─────────────────────────────────────────────────
export type AuditEvent = {
  at: string;
  assetId: string;
  kind: "analyze" | "watch" | "unwatch" | "delta";
  detail: string;
};
export function loadAudit(): AuditEvent[] {
  return read(K_AUDIT, [] as AuditEvent[]);
}
export function logAudit(ev: Omit<AuditEvent, "at">) {
  const cur = loadAudit();
  cur.unshift({ ...ev, at: new Date().toISOString() });
  write(K_AUDIT, cur.slice(0, 500));
}

// ─── Webhook config ────────────────────────────────────────────
export type WebhookConfig = { url: string; enabled: boolean };
export function loadWebhook(): WebhookConfig {
  return read(K_WEBHOOK, { url: "", enabled: false });
}
export function saveWebhook(cfg: WebhookConfig) {
  write(K_WEBHOOK, cfg);
}