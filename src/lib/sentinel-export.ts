import type { ThreatBrief, OsintAsset } from "./sentinel.functions";

function csvCell(v: unknown): string {
  const s = v == null ? "" : String(v);
  return `"${s.replace(/"/g, '""')}"`;
}

export function assetsToCsv(
  assets: OsintAsset[],
  briefs: Record<string, ThreatBrief>,
): string {
  const rows = [
    ["id", "ip", "port", "protocol", "sector", "org", "location", "priority", "summary", "generatedAt"],
  ];
  for (const a of assets) {
    const b = briefs[a.id];
    rows.push([
      a.id,
      a.ip,
      String(a.port),
      a.protocol,
      a.sector,
      a.org,
      a.location,
      b?.priority ?? "",
      b?.summary?.replace(/\s+/g, " ").trim() ?? "",
      b?.generatedAt ?? "",
    ]);
  }
  return rows.map((r) => r.map(csvCell).join(",")).join("\n");
}

// Minimal STIX 2.1 bundle: one Observed-Data + Indicator per asset,
// plus a Report per generated brief. Not exhaustive, but valid enough
// for a SOC to ingest into TAXII / OpenCTI / MISP importers.
export function assetsToStix(
  assets: OsintAsset[],
  briefs: Record<string, ThreatBrief>,
): string {
  const now = new Date().toISOString();
  const objects: unknown[] = [];
  const idFor = (kind: string, seed: string) =>
    `${kind}--${uuidFromSeed(seed)}`;

  for (const a of assets) {
    const ipv4 = idFor("ipv4-addr", `ip:${a.ip}`);
    objects.push({
      type: "ipv4-addr",
      spec_version: "2.1",
      id: ipv4,
      value: a.ip,
    });
    objects.push({
      type: "observed-data",
      spec_version: "2.1",
      id: idFor("observed-data", `obs:${a.id}`),
      created: now,
      modified: now,
      first_observed: now,
      last_observed: now,
      number_observed: 1,
      object_refs: [ipv4],
      labels: [a.protocol, a.sector, a.org].filter(Boolean),
    });
    objects.push({
      type: "indicator",
      spec_version: "2.1",
      id: idFor("indicator", `ind:${a.id}`),
      created: now,
      modified: now,
      name: `Exposed ${a.protocol} on ${a.ip}:${a.port}`,
      description: `${a.org} — ${a.location}`,
      indicator_types: ["anomalous-activity"],
      pattern_type: "stix",
      pattern: `[ipv4-addr:value = '${a.ip}' AND network-traffic:dst_port = ${a.port}]`,
      valid_from: now,
    });
    const b = briefs[a.id];
    if (b) {
      objects.push({
        type: "report",
        spec_version: "2.1",
        id: idFor("report", `rep:${a.id}:${b.generatedAt}`),
        created: b.generatedAt,
        modified: b.generatedAt,
        name: `Sentinel brief — ${a.ip}:${a.port} [${b.priority}]`,
        description: b.summary,
        published: b.generatedAt,
        report_types: ["threat-report"],
        object_refs: [ipv4],
        external_references: b.sources.map((s) => ({
          source_name: s.title || s.url,
          url: s.url,
        })),
      });
    }
  }
  return JSON.stringify(
    { type: "bundle", id: `bundle--${uuidFromSeed(`bundle:${now}`)}`, objects },
    null,
    2,
  );
}

export function downloadText(filename: string, mime: string, content: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// Deterministic UUID v4-ish from a seed string (djb2 + formatting).
function uuidFromSeed(seed: string): string {
  let h1 = 0x811c9dc5;
  let h2 = 0xdeadbeef;
  for (let i = 0; i < seed.length; i++) {
    const c = seed.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 2654435761);
    h2 = Math.imul(h2 ^ c, 1597334677);
  }
  const hex = (n: number) => (n >>> 0).toString(16).padStart(8, "0");
  const raw = (hex(h1) + hex(h2) + hex(h1 ^ h2) + hex(~h1)).slice(0, 32);
  return `${raw.slice(0, 8)}-${raw.slice(8, 12)}-4${raw.slice(13, 16)}-8${raw.slice(17, 20)}-${raw.slice(20, 32)}`;
}