import { createServerFn } from "@tanstack/react-start";

export type OsintAsset = {
  id: string;
  ip: string;
  port: number;
  protocol: string;
  location: string;
  org: string;
  sector: string;
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
};

export const listExposedAssets = createServerFn({ method: "GET" }).handler(async () => {
  return MOCK_ASSETS;
});

export const analyzeAsset = createServerFn({ method: "POST" })
  .inputValidator((input: { assetId: string }) => input)
  .handler(async ({ data }): Promise<ThreatBrief> => {
    const asset = MOCK_ASSETS.find((a) => a.id === data.assetId);
    if (!asset) throw new Error("Asset not found");

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
    };
  });