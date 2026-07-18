import { createServerFn } from "@tanstack/react-start";

export type OsintAsset = {
  id: string;
  ip: string;
  port: number;
  protocol: string;
  location: string;
  org: string;
  sector: string;
  province?: string; // US state — used for the geo heatmap
};

const MOCK_ASSETS: OsintAsset[] = [
  { id: "a1", ip: "203.0.113.42", port: 502, protocol: "Modbus", location: "Eastern Europe", org: "National Power Grid Authority", sector: "Energy" },
  { id: "a2", ip: "198.51.100.17", port: 102, protocol: "Siemens S7", location: "Germany", org: "Rhein Water Works", sector: "Water Treatment" },
  { id: "a3", ip: "192.0.2.88", port: 44818, protocol: "EtherNet/IP", location: "Texas, USA", org: "Lone Star Refining", sector: "Oil & Gas" },
  { id: "a4", ip: "203.0.113.201", port: 20000, protocol: "DNP3", location: "Ukraine", org: "Kyiv Regional Substation", sector: "Energy" },
  { id: "a5", ip: "198.51.100.66", port: 2404, protocol: "IEC-104", location: "Taiwan", org: "Taipei Telecom Backbone", sector: "Telecommunications" },
  { id: "a6", ip: "192.0.2.144", port: 1911, protocol: "Niagara Fox", location: "Saudi Arabia", org: "Riyadh Municipal SCADA", sector: "Utilities" },
];

export type ThreatBrief = {
  asset: OsintAsset;
  summary: string;
  priority: "P1 - CRITICAL" | "P2 - HIGH" | "P3 - MONITOR";
  sources: { url: string; title: string }[];
  generatedAt: string;
  attack: AttackMapping[];
};

// ─────────────────────────────────────────────────────────────
// MITRE ATT&CK mapping (keyword-driven).
// Covers the ICS matrix + a handful of high-signal Enterprise
// techniques commonly cited in ICS/SCADA threat intel. Matches
// are made against the Tavily answer text — technique IDs and
// keyword lists trigger a hit, and the technique's tactic is
// derived from the ATT&CK matrix taxonomy.
// ─────────────────────────────────────────────────────────────

export type AttackMapping = {
  matrix: "ics" | "enterprise";
  techniqueId: string;
  techniqueName: string;
  tacticId: string;
  tacticName: string;
  url: string;
  matched: string[]; // keywords / phrases that fired
};

// ─── Confidence scoring for ATT&CK mappings ──────────────────
// Client-safe pure helper. Also handles legacy briefs whose
// mappings pre-date this scoring layer.
export type AttackConfidence = {
  score: number; // 0-99
  band: "high" | "medium" | "low";
  rationale: string;
  factors: string[];
};

export function scoreAttack(m: Pick<AttackMapping, "techniqueId" | "matched">): AttackConfidence {
  const matched = m.matched ?? [];
  const idHit = matched.some((k) => k.toLowerCase() === m.techniqueId.toLowerCase());
  const actorHits = matched.filter((k) => k.startsWith("actor:"));
  const keywordHits = matched.filter((k) => !k.startsWith("actor:") && k.toLowerCase() !== m.techniqueId.toLowerCase());
  const multiWord = keywordHits.filter((k) => k.includes(" "));

  const factors: string[] = [];
  let score = 20; // baseline for any hit
  if (idHit) {
    score += 55;
    factors.push(`Direct reference to ${m.techniqueId} in the brief text`);
  }
  if (keywordHits.length) {
    score += Math.min(40, keywordHits.length * 15);
    if (multiWord.length) score += Math.min(10, multiWord.length * 4);
    factors.push(
      `${keywordHits.length} keyword ${keywordHits.length === 1 ? "phrase" : "phrases"} matched: ${keywordHits.slice(0, 4).map((k) => `“${k}”`).join(", ")}${keywordHits.length > 4 ? "…" : ""}`,
    );
  }
  if (actorHits.length) {
    score += Math.min(35, actorHits.length * 25);
    const actors = actorHits.map((a) => a.replace(/^actor:/, "")).join(", ");
    factors.push(`Inferred from named threat actor(s): ${actors}`);
  }
  if (!factors.length) factors.push("Weak signal — no strong matches recorded");

  score = Math.max(15, Math.min(99, score));
  const band: AttackConfidence["band"] = score >= 75 ? "high" : score >= 45 ? "medium" : "low";
  return { score, band, rationale: factors.join(" · "), factors };
}

type AttackDef = {
  matrix: "ics" | "enterprise";
  id: string;
  name: string;
  tacticId: string;
  tacticName: string;
  keywords: string[];
};

const ATTACK_TECHNIQUES: AttackDef[] = [
  // --- ICS matrix ---
  { matrix: "ics", id: "T0819", name: "Exploit Public-Facing Application", tacticId: "TA0108", tacticName: "Initial Access", keywords: ["exploit public-facing", "internet-exposed", "publicly exposed", "shodan", "censys"] },
  { matrix: "ics", id: "T0883", name: "Internet Accessible Device", tacticId: "TA0108", tacticName: "Initial Access", keywords: ["internet accessible", "exposed to the internet", "reachable from the internet"] },
  { matrix: "ics", id: "T0817", name: "Drive-by Compromise", tacticId: "TA0108", tacticName: "Initial Access", keywords: ["drive-by compromise", "drive by download", "watering hole"] },
  { matrix: "ics", id: "T0865", name: "Spearphishing Attachment", tacticId: "TA0108", tacticName: "Initial Access", keywords: ["spearphish", "phishing", "malicious attachment"] },
  { matrix: "ics", id: "T0866", name: "Exploitation of Remote Services", tacticId: "TA0108", tacticName: "Initial Access", keywords: ["exploitation of remote services", "rdp exploit", "vpn exploit"] },
  { matrix: "ics", id: "T0886", name: "Remote Services", tacticId: "TA0109", tacticName: "Lateral Movement", keywords: ["remote services", "lateral movement", "smb", "rdp", "ssh"] },
  { matrix: "ics", id: "T0855", name: "Unauthorized Command Message", tacticId: "TA0104", tacticName: "Impair Process Control", keywords: ["unauthorized command", "malicious modbus write", "rogue command", "spoofed command"] },
  { matrix: "ics", id: "T0836", name: "Modify Parameter", tacticId: "TA0104", tacticName: "Impair Process Control", keywords: ["modify parameter", "setpoint change", "altered setpoint", "parameter tampering"] },
  { matrix: "ics", id: "T0831", name: "Manipulation of Control", tacticId: "TA0106", tacticName: "Impact", keywords: ["manipulation of control", "manipulated control", "hijack control"] },
  { matrix: "ics", id: "T0827", name: "Loss of Control", tacticId: "TA0106", tacticName: "Impact", keywords: ["loss of control", "operator locked out"] },
  { matrix: "ics", id: "T0828", name: "Loss of Productivity and Revenue", tacticId: "TA0106", tacticName: "Impact", keywords: ["outage", "downtime", "production halt", "shutdown"] },
  { matrix: "ics", id: "T0826", name: "Loss of Availability", tacticId: "TA0106", tacticName: "Impact", keywords: ["loss of availability", "denial of service", "ddos", "service disruption"] },
  { matrix: "ics", id: "T0879", name: "Damage to Property", tacticId: "TA0106", tacticName: "Impact", keywords: ["physical damage", "equipment damage", "damaged turbine", "burst pipe", "explosion"] },
  { matrix: "ics", id: "T0880", name: "Loss of Safety", tacticId: "TA0106", tacticName: "Impact", keywords: ["loss of safety", "safety system", "sis bypass", "triton", "trisis"] },
  { matrix: "ics", id: "T0809", name: "Data Destruction", tacticId: "TA0105", tacticName: "Inhibit Response Function", keywords: ["wiper", "data destruction", "erase firmware", "brick"] },
  { matrix: "ics", id: "T0814", name: "Denial of Service", tacticId: "TA0105", tacticName: "Inhibit Response Function", keywords: ["denial of service on plc", "flood the controller", "dos plc"] },
  { matrix: "ics", id: "T0846", name: "Remote System Discovery", tacticId: "TA0102", tacticName: "Discovery", keywords: ["network scan", "remote system discovery", "reconnaissance scan", "enumerate hosts"] },
  { matrix: "ics", id: "T0842", name: "Network Sniffing", tacticId: "TA0102", tacticName: "Discovery", keywords: ["network sniffing", "packet capture", "pcap", "eavesdrop"] },
  { matrix: "ics", id: "T0858", name: "Change Operating Mode", tacticId: "TA0110", tacticName: "Evasion", keywords: ["change operating mode", "run/program switch", "put plc in stop", "program mode"] },
  { matrix: "ics", id: "T0857", name: "System Firmware", tacticId: "TA0111", tacticName: "Persistence", keywords: ["malicious firmware", "firmware implant", "firmware backdoor"] },
  { matrix: "ics", id: "T0889", name: "Modify Program", tacticId: "TA0111", tacticName: "Persistence", keywords: ["modify plc program", "ladder logic modification", "rogue ladder logic"] },
  { matrix: "ics", id: "T0891", name: "Hardcoded Credentials", tacticId: "TA0107", tacticName: "Lateral Movement", keywords: ["hardcoded credential", "default password", "vendor backdoor"] },
  // --- Enterprise techniques cited often in ICS reporting ---
  { matrix: "enterprise", id: "T1190", name: "Exploit Public-Facing Application", tacticId: "TA0001", tacticName: "Initial Access", keywords: ["cve-", "0-day", "zero-day", "actively exploited", "rce vulnerability"] },
  { matrix: "enterprise", id: "T1133", name: "External Remote Services", tacticId: "TA0001", tacticName: "Initial Access", keywords: ["exposed vpn", "citrix", "fortinet vpn", "pulse secure", "ivanti"] },
  { matrix: "enterprise", id: "T1486", name: "Data Encrypted for Impact", tacticId: "TA0040", tacticName: "Impact", keywords: ["ransomware", "encrypted files", "ransom note", "lockbit", "blackcat", "alphv", "clop"] },
  { matrix: "enterprise", id: "T1078", name: "Valid Accounts", tacticId: "TA0001", tacticName: "Initial Access", keywords: ["stolen credential", "credential stuffing", "leaked password", "valid account"] },
  { matrix: "enterprise", id: "T1071", name: "Application Layer Protocol", tacticId: "TA0011", tacticName: "Command and Control", keywords: ["command and control", "c2 server", "c&c", "beaconing"] },
  { matrix: "enterprise", id: "T1490", name: "Inhibit System Recovery", tacticId: "TA0040", tacticName: "Impact", keywords: ["delete backups", "shadow copies", "inhibit recovery", "disabled backup"] },
];

// Named threat actors → additional technique hints.
const ACTOR_TECHNIQUES: Record<string, string[]> = {
  sandworm: ["T0836", "T0879", "T0826", "T0809"],
  volt_typhoon: ["T1133", "T1078", "T0883"],
  triton: ["T0880", "T0857"],
  trisis: ["T0880", "T0857"],
  industroyer: ["T0836", "T0855", "T0826"],
  crashoverride: ["T0836", "T0855", "T0826"],
  incontroller: ["T0855", "T0836", "T0889"],
  pipedream: ["T0855", "T0836", "T0889"],
  blackenergy: ["T0866", "T0826"],
  lockbit: ["T1486", "T1490"],
  alphv: ["T1486", "T1490"],
  blackcat: ["T1486", "T1490"],
};

export function extractAttack(text: string): AttackMapping[] {
  const hay = ` ${text.toLowerCase()} `;
  const byId = new Map<string, AttackMapping>();
  const push = (def: AttackDef, kw: string) => {
    const key = `${def.matrix}:${def.id}`;
    const existing = byId.get(key);
    if (existing) {
      if (!existing.matched.includes(kw)) existing.matched.push(kw);
      return;
    }
    byId.set(key, {
      matrix: def.matrix,
      techniqueId: def.id,
      techniqueName: def.name,
      tacticId: def.tacticId,
      tacticName: def.tacticName,
      url:
        def.matrix === "ics"
          ? `https://attack.mitre.org/techniques/${def.id}/`
          : `https://attack.mitre.org/techniques/${def.id}/`,
      matched: [kw],
    });
  };
  for (const def of ATTACK_TECHNIQUES) {
    // Direct technique ID reference wins.
    if (hay.includes(def.id.toLowerCase())) push(def, def.id);
    for (const kw of def.keywords) {
      if (hay.includes(kw.toLowerCase())) push(def, kw);
    }
  }
  // Actor-derived inferences.
  for (const [actor, techIds] of Object.entries(ACTOR_TECHNIQUES)) {
    const needle = actor.replace(/_/g, " ");
    if (!hay.includes(needle)) continue;
    for (const tid of techIds) {
      const def = ATTACK_TECHNIQUES.find((d) => d.id === tid);
      if (def) push(def, `actor:${needle}`);
    }
  }
  // Deterministic order: tactic then technique id.
  return Array.from(byId.values()).sort((a, b) =>
    a.tacticName === b.tacticName
      ? a.techniqueId.localeCompare(b.techniqueId)
      : a.tacticName.localeCompare(b.tacticName),
  );
}

// ICS/SCADA protocol fingerprints — used to label Censys hits.
const PROTOCOL_BY_PORT: Record<number, { protocol: string; sector: string }> = {
  502: { protocol: "Modbus", sector: "Industrial Control" },
  102: { protocol: "Siemens S7", sector: "Industrial Control" },
  44818: { protocol: "EtherNet/IP", sector: "Industrial Control" },
  20000: { protocol: "DNP3", sector: "Energy" },
  2404: { protocol: "IEC-104", sector: "Energy" },
  1911: { protocol: "Niagara Fox", sector: "Building Automation" },
  4911: { protocol: "Niagara Fox", sector: "Building Automation" },
  47808: { protocol: "BACnet", sector: "Building Automation" },
  789: { protocol: "Red Lion Crimson", sector: "Industrial Control" },
  9600: { protocol: "OMRON FINS", sector: "Industrial Control" },
  5006: { protocol: "MELSEC-Q", sector: "Industrial Control" },
  1962: { protocol: "PCWorx", sector: "Industrial Control" },
};

// Default Censys query: ICS/SCADA services exposed to the public internet.
const DEFAULT_CENSYS_QUERY =
  "services.service_name: {MODBUS, S7, DNP3, IEC_60870_5_104, FOX, BACNET, ETHERNET_IP}";

// Homeland scope — Sentinel-OSINT targets US critical infrastructure only.
const US_SCOPE = "location.country_code: US";

function scopeToUS(query: string): string {
  // Idempotent: don't double-append if the caller already scoped by country.
  if (/location\.country_code\s*:/i.test(query)) return query;
  return `(${query}) and ${US_SCOPE}`;
}

type CensysHit = {
  ip?: string;
  location?: { country?: string; province?: string; city?: string };
  autonomous_system?: { name?: string };
  services?: Array<{
    port?: number;
    service_name?: string;
    extended_service_name?: string;
  }>;
};

function normalizeCensys(hits: CensysHit[]): OsintAsset[] {
  const out: OsintAsset[] = [];
  for (const h of hits) {
    if (!h.ip || !h.services?.length) continue;
    // Prefer ICS services; fall back to first service.
    const svc =
      h.services.find((s) => s.port && PROTOCOL_BY_PORT[s.port]) ?? h.services[0];
    const port = svc?.port ?? 0;
    const fingerprint = PROTOCOL_BY_PORT[port];
    const protocol =
      fingerprint?.protocol ??
      svc?.extended_service_name ??
      svc?.service_name ??
      "Unknown";
    const sector = fingerprint?.sector ?? "Infrastructure";
    const loc = [h.location?.city, h.location?.province, h.location?.country]
      .filter(Boolean)
      .join(", ") || "Unknown";
    out.push({
      id: `${h.ip}:${port}`,
      ip: h.ip,
      port,
      protocol,
      location: loc,
      org: h.autonomous_system?.name ?? "Unknown operator",
      sector,
      province: h.location?.province,
    });
  }
  return out;
}

export type AssetFeed = {
  assets: OsintAsset[];
  source: "censys" | "mock";
  query: string;
  nextCursor?: string;
  pageSize: number;
  error?: string;
};

const PAGE_SIZE = 25;

export const listExposedAssets = createServerFn({ method: "GET" })
  .inputValidator((input?: { query?: string; cursor?: string }) => input ?? {})
  .handler(async ({ data }): Promise<AssetFeed> => {
    const query = data.query?.trim() || DEFAULT_CENSYS_QUERY;
    const scopedQuery = scopeToUS(query);
    const cursor = data.cursor?.trim() || undefined;
    const apiKey = process.env.CENSYS_API_KEY;
    if (!apiKey) {
      return {
        assets: MOCK_ASSETS.filter((a) => /USA|United States/i.test(a.location)),
        source: "mock",
        query: scopedQuery,
        pageSize: PAGE_SIZE,
        error: "Missing CENSYS_API_KEY",
      };
    }
    try {
      const res = await fetch("https://api.platform.censys.io/v3/global/search/query", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          query: scopedQuery,
          page_size: PAGE_SIZE,
          ...(cursor ? { cursor } : {}),
        }),
      });
      if (!res.ok) {
        const body = await res.text();
        console.error(`Censys error [${res.status}]: ${body}`);
        return {
          assets: MOCK_ASSETS.filter((a) => /USA|United States/i.test(a.location)),
          source: "mock",
          query: scopedQuery,
          pageSize: PAGE_SIZE,
          error: `Censys request failed [${res.status}] — showing mock feed`,
        };
      }
      const json = (await res.json()) as {
        result?: {
          hits?: CensysHit[];
          next_page_token?: string;
          nextCursor?: string;
          links?: { next?: string };
        };
        hits?: CensysHit[];
        next_page_token?: string;
        nextCursor?: string;
      };
      const hits = json.result?.hits ?? json.hits ?? [];
      const nextCursor =
        json.result?.nextCursor ||
        json.result?.next_page_token ||
        json.result?.links?.next ||
        json.nextCursor ||
        json.next_page_token ||
        undefined;
      const assets = normalizeCensys(hits);
      if (!assets.length && !cursor) {
        return {
          assets: MOCK_ASSETS.filter((a) => /USA|United States/i.test(a.location)),
          source: "mock",
          query: scopedQuery,
          pageSize: PAGE_SIZE,
          error: "Censys returned no hits — showing mock feed",
        };
      }
      return { assets, source: "censys", query: scopedQuery, nextCursor, pageSize: PAGE_SIZE };
    } catch (err) {
      console.error("Censys ingestion failed", err);
      return {
        assets: MOCK_ASSETS.filter((a) => /USA|United States/i.test(a.location)),
        source: "mock",
        query: scopedQuery,
        pageSize: PAGE_SIZE,
        error: (err as Error).message,
      };
    }
  });

export const analyzeAsset = createServerFn({ method: "POST" })
  .inputValidator((input: { asset: OsintAsset }) => input)
  .handler(async ({ data }): Promise<ThreatBrief> => {
    const asset = data.asset;

    const apiKey = process.env.TAVILY_API_KEY;
    if (!apiKey) throw new Error("Missing TAVILY_API_KEY");

    const query = `Active cyber threats, state-sponsored attacks, APT groups, or malware campaigns targeting ${asset.protocol} systems or ${asset.sector} infrastructure in ${asset.location} in the last 30 days. Include specific threat actor groups and recent CVEs.`;

    const res = await fetch("https://api.tavily.com/search", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        api_key: apiKey,
        query,
        search_depth: "advanced",
        include_answer: true,
        max_results: 5,
      }),
    });

    if (!res.ok) {
      const body = await res.text();
      console.error(`Tavily error [${res.status}]: ${body}`);
      throw new Error(`Tavily request failed [${res.status}]`);
    }

    const tavily = (await res.json()) as {
      answer?: string;
      results?: { url: string; title: string }[];
    };

    const answer = (tavily.answer ?? "No strategic intelligence found.").toString();
    const lower = answer.toLowerCase();
    let priority: ThreatBrief["priority"] = "P3 - MONITOR";
    if (/(apt|state-sponsored|sandworm|critical cve|zero-day|actively exploit)/.test(lower)) {
      priority = "P1 - CRITICAL";
    } else if (/(malware|vulnerability|cve-|ransomware|campaign)/.test(lower)) {
      priority = "P2 - HIGH";
    }

    return {
      asset,
      summary: answer,
      priority,
      sources: (tavily.results ?? []).map((r) => ({ url: r.url, title: r.title })),
      generatedAt: new Date().toISOString(),
      attack: extractAttack(answer),
    };
  });

// ─────────────────────────────────────────────────────────────
// CISA KEV enrichment — cross-reference protocols with the
// Known Exploited Vulnerabilities catalog.
// ─────────────────────────────────────────────────────────────

export type KevMatch = {
  cveId: string;
  vendor: string;
  product: string;
  shortDescription: string;
  dateAdded: string;
  dueDate?: string;
};

export type KevReport = Record<string, KevMatch[]>;

const KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

// Keyword sets per protocol — matched against KEV vendor/product/description.
const PROTOCOL_KEV_KEYWORDS: Record<string, string[]> = {
  Modbus: ["modbus"],
  "Siemens S7": ["siemens", "simatic", "s7-", "s7 "],
  "EtherNet/IP": ["rockwell", "allen-bradley", "allen bradley", "ethernet/ip"],
  DNP3: ["dnp3", "dnp 3"],
  "IEC-104": ["iec 60870", "iec-104", "iec104"],
  "Niagara Fox": ["niagara", "tridium"],
  BACnet: ["bacnet"],
  "OMRON FINS": ["omron"],
  "MELSEC-Q": ["mitsubishi electric", "melsec"],
  PCWorx: ["phoenix contact", "pcworx"],
  "Red Lion Crimson": ["red lion", "crimson"],
};

type KevRaw = {
  vulnerabilities?: Array<{
    cveID: string;
    vendorProject: string;
    product: string;
    shortDescription: string;
    dateAdded: string;
    dueDate?: string;
  }>;
};

let kevCache: { at: number; items: NonNullable<KevRaw["vulnerabilities"]> } | null = null;
const KEV_TTL_MS = 6 * 60 * 60 * 1000;

async function loadKev() {
  if (kevCache && Date.now() - kevCache.at < KEV_TTL_MS) return kevCache.items;
  const res = await fetch(KEV_URL);
  if (!res.ok) throw new Error(`KEV fetch failed [${res.status}]`);
  const json = (await res.json()) as KevRaw;
  const items = json.vulnerabilities ?? [];
  kevCache = { at: Date.now(), items };
  return items;
}

export const getKevForProtocols = createServerFn({ method: "POST" })
  .inputValidator((input: { protocols: string[] }) => input)
  .handler(async ({ data }): Promise<KevReport> => {
    const wanted = Array.from(new Set(data.protocols)).filter(Boolean);
    if (!wanted.length) return {};
    let items: NonNullable<KevRaw["vulnerabilities"]>;
    try {
      items = await loadKev();
    } catch (err) {
      console.error("KEV load failed", err);
      return {};
    }
    const report: KevReport = {};
    for (const proto of wanted) {
      const keys = PROTOCOL_KEV_KEYWORDS[proto];
      if (!keys) {
        report[proto] = [];
        continue;
      }
      const matches: KevMatch[] = [];
      for (const v of items) {
        const hay = `${v.vendorProject} ${v.product} ${v.shortDescription}`.toLowerCase();
        if (keys.some((k) => hay.includes(k))) {
          matches.push({
            cveId: v.cveID,
            vendor: v.vendorProject,
            product: v.product,
            shortDescription: v.shortDescription,
            dateAdded: v.dateAdded,
            dueDate: v.dueDate,
          });
        }
      }
      // Newest first, cap for UI sanity.
      matches.sort((a, b) => b.dateAdded.localeCompare(a.dateAdded));
      report[proto] = matches.slice(0, 25);
    }
    return report;
  });

// ─────────────────────────────────────────────────────────────
// Webhook notifier — server-side POST proxy so browser CORS
// restrictions on Slack / generic webhooks don't block delivery.
// ─────────────────────────────────────────────────────────────

export const sendWebhook = createServerFn({ method: "POST" })
  .inputValidator(
    (input: { url: string; payload: Record<string, unknown> }) => input,
  )
  .handler(async ({ data }): Promise<{ ok: boolean; status: number; body?: string }> => {
    try {
      const u = new URL(data.url);
      if (u.protocol !== "https:" && u.protocol !== "http:") {
        return { ok: false, status: 0, body: "Only http(s) URLs are allowed" };
      }
    } catch {
      return { ok: false, status: 0, body: "Invalid URL" };
    }
    try {
      const res = await fetch(data.url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data.payload),
      });
      const body = await res.text();
      return { ok: res.ok, status: res.status, body: body.slice(0, 500) };
    } catch (err) {
      return { ok: false, status: 0, body: (err as Error).message };
    }
  });

// ─────────────────────────────────────────────────────────────
// OSINT Framework recon toolkit
// Sources https://github.com/lockfale/osint-framework — a curated
// hierarchical registry of investigation tools. We fetch the JSON,
// flatten it, and surface entries relevant to infrastructure recon.
// ─────────────────────────────────────────────────────────────

export type ReconTool = {
  name: string;
  url: string;
  category: string;
  description?: string;
  pricing?: string;
  api?: boolean;
  registration?: boolean;
  deprecated?: boolean;
};

type ArfNode = {
  name: string;
  type: "folder" | "url";
  url?: string;
  description?: string;
  pricing?: string;
  api?: boolean;
  registration?: boolean;
  deprecated?: boolean;
  children?: ArfNode[];
};

const ARF_URL =
  "https://raw.githubusercontent.com/lockfale/OSINT-Framework/master/public/arf.json";

// Categories in OSINT Framework relevant to cyber-physical / infra recon.
// Matched against the top-level branch name.
const INFRA_BRANCHES = new Set([
  "IP & MAC Address",
  "Domain Name",
  "Malicious File Analysis",
  "Compliance & Risk Intelligence",
  "Dark Web",
  "Search Engines",
  "Tools",
  "Archives",
]);

let arfCache: { at: number; tools: ReconTool[] } | null = null;
const ARF_TTL_MS = 6 * 60 * 60 * 1000; // 6 hours

function flatten(node: ArfNode, trail: string[], out: ReconTool[]) {
  if (node.type === "folder") {
    for (const c of node.children ?? []) flatten(c, [...trail, node.name], out);
    return;
  }
  if (!node.url) return;
  // trail = [root, branch, ...subfolders]; keep "Branch > Subfolder".
  const branch = trail[1];
  if (!branch || !INFRA_BRANCHES.has(branch)) return;
  const category = trail.slice(1).join(" > ");
  out.push({
    name: node.name,
    url: node.url,
    category,
    description: node.description,
    pricing: node.pricing,
    api: node.api,
    registration: node.registration,
    deprecated: node.deprecated,
  });
}

async function loadArf(): Promise<ReconTool[]> {
  if (arfCache && Date.now() - arfCache.at < ARF_TTL_MS) return arfCache.tools;
  const res = await fetch(ARF_URL);
  if (!res.ok) throw new Error(`OSINT Framework fetch failed [${res.status}]`);
  const root = (await res.json()) as ArfNode;
  const tools: ReconTool[] = [];
  flatten(root, [], tools);
  arfCache = { at: Date.now(), tools };
  return tools;
}

export type ReconToolkit = {
  asset: OsintAsset;
  groups: { category: string; tools: ReconTool[] }[];
  total: number;
};

// Category priorities per asset context.
const SECTOR_CATEGORY_BOOST: Record<string, string[]> = {
  "Industrial Control": ["IP & MAC Address", "Tools", "Malicious File Analysis"],
  Energy: ["IP & MAC Address", "Compliance & Risk Intelligence", "Tools"],
  "Building Automation": ["IP & MAC Address", "Tools"],
  Infrastructure: ["IP & MAC Address", "Domain Name", "Tools"],
};

export const getReconToolkit = createServerFn({ method: "POST" })
  .inputValidator((input: { asset: OsintAsset }) => input)
  .handler(async ({ data }): Promise<ReconToolkit> => {
    const asset = data.asset;
    const all = await loadArf();
    const active = all.filter((t) => !t.deprecated);

    const boosted = new Set(
      SECTOR_CATEGORY_BOOST[asset.sector] ?? [
        "IP & MAC Address",
        "Domain Name",
        "Tools",
      ],
    );

    // Group by category, prioritized branches first.
    const byCat = new Map<string, ReconTool[]>();
    for (const t of active) {
      const arr = byCat.get(t.category) ?? [];
      arr.push(t);
      byCat.set(t.category, arr);
    }

    const groups = Array.from(byCat.entries())
      .map(([category, tools]) => ({
        category,
        tools: tools.sort((a, b) => a.name.localeCompare(b.name)),
      }))
      .sort((a, b) => {
        const ab = boosted.has(a.category.split(" > ")[0]) ? 0 : 1;
        const bb = boosted.has(b.category.split(" > ")[0]) ? 0 : 1;
        if (ab !== bb) return ab - bb;
        return a.category.localeCompare(b.category);
      });

    return { asset, groups, total: active.length };
  });