// ─────────────────────────────────────────────────────────────
// SerpApi live-data layer — structured, real-time web intelligence
// for Sentinel-OSINT (DevNetwork API+Cloud+AI Hackathon 2026).
//
// SerpApi is the PRIMARY source for threat briefs and radius news:
// google_news gives locale/dated structured headlines, google gives
// organic depth for actor/CVE context. Tavily remains as fallback so
// the pipeline degrades gracefully instead of failing closed.
// ─────────────────────────────────────────────────────────────

export type SerpResult = {
  title: string;
  url: string;
  snippet?: string;
  source?: string;
  date?: string;
};

const SERPAPI_ENDPOINT = "https://serpapi.com/search.json";

function serpApiKey(): string | undefined {
  return process.env.SERPAPI_API_KEY;
}

async function serpApiFetch(
  params: Record<string, string>,
): Promise<Record<string, unknown> | null> {
  const key = serpApiKey();
  if (!key) return null;
  const url = new URL(SERPAPI_ENDPOINT);
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
  url.searchParams.set("api_key", key);
  try {
    const res = await fetch(url.toString());
    if (!res.ok) {
      console.error(`SerpApi error [${res.status}]: ${await res.text()}`);
      return null;
    }
    return (await res.json()) as Record<string, unknown>;
  } catch (err) {
    console.error("SerpApi request failed", err);
    return null;
  }
}

type RawNews = {
  title?: string;
  link?: string;
  snippet?: string;
  date?: string;
  source?: string | { name?: string };
};

type RawOrganic = {
  title?: string;
  link?: string;
  snippet?: string;
  date?: string;
};

/** Structured real-time headlines for a threat query (engine=google_news). */
export async function serpApiNews(
  query: string,
  num = 8,
): Promise<SerpResult[]> {
  const json = await serpApiFetch({
    engine: "google_news",
    q: query,
    num: String(num),
  });
  if (!json) return [];
  const results = (json.news_results ?? []) as RawNews[];
  return results
    .filter((r) => r.title && r.link)
    .map((r) => ({
      title: r.title as string,
      url: r.link as string,
      snippet: r.snippet,
      date: r.date,
      source:
        typeof r.source === "string"
          ? r.source
          : r.source?.name,
    }));
}

/** Organic SERP depth — actor/CVE/advisory context (engine=google). */
export async function serpApiOrganic(
  query: string,
  num = 8,
): Promise<SerpResult[]> {
  const json = await serpApiFetch({
    engine: "google",
    q: query,
    num: String(num),
  });
  if (!json) return [];
  const results = (json.organic_results ?? []) as RawOrganic[];
  return results
    .filter((r) => r.title && r.link)
    .map((r) => ({
      title: r.title as string,
      url: r.link as string,
      snippet: r.snippet,
      date: r.date,
    }));
}

/**
 * Compose the strategic-brief text from structured SerpApi results.
 * SerpApi returns structured data rather than a synthesized LLM
 * answer, so the brief is built from dated, attributed snippets —
 * every sentence in the summary traces to a citable source below it.
 */
export function composeBriefFromSerp(results: SerpResult[]): string {
  if (!results.length) return "";
  const lines = results.slice(0, 8).map((r) => {
    const who = r.source ? ` [${r.source}]` : "";
    const when = r.date ? ` (${r.date})` : "";
    const body = (r.snippet ?? r.title).replace(/\s+/g, " ").trim();
    return `• ${body}${when}${who}`.slice(0, 500);
  });
  return lines.join("\n");
}
