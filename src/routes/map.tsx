import { createFileRoute, Link } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import mapboxgl from "mapbox-gl";
import "mapbox-gl/dist/mapbox-gl.css";
import { listExposedAssets } from "@/lib/sentinel.functions";
import {
  getGlobalGeoEvents,
  type GeoEvent,
} from "@/lib/sentinel-geo.functions";

export const Route = createFileRoute("/map")({
  head: () => ({
    meta: [
      { title: "Sentinel-OSINT · Geo Map" },
      { name: "description", content: "Live map of exposed US critical-infrastructure assets fused with GDACS, USGS, and NOAA geo-event feeds." },
      { property: "og:title", content: "Sentinel-OSINT · Geo Map" },
      { property: "og:description", content: "Assets + wildfire, storm, quake, and NOAA alert overlays." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: MapPage,
});

const MAPBOX_TOKEN = import.meta.env.VITE_LOVABLE_CONNECTOR_MAPBOX_PUBLIC_TOKEN as
  | string
  | undefined;

const SEV_COLOR: Record<GeoEvent["severity"], string> = {
  extreme: "#ef4444",
  severe: "#f97316",
  moderate: "#eab308",
  minor: "#22c55e",
  info: "#94a3b8",
};

function MapPage() {
  const runAssets = useServerFn(listExposedAssets);
  const runEvents = useServerFn(getGlobalGeoEvents);
  const assetsQ = useQuery({
    queryKey: ["map-assets"],
    queryFn: () => runAssets({ data: {} }),
    staleTime: 5 * 60 * 1000,
  });
  const eventsQ = useQuery({
    queryKey: ["map-events"],
    queryFn: () => runEvents(),
    staleTime: 5 * 60 * 1000,
  });
  const assets = assetsQ.data?.assets ?? [];
  const events = eventsQ.data?.events ?? [];

  return (
    <div className="min-h-screen bg-background text-foreground">
      <header className="border-b border-border">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
          <div>
            <div className="text-xs font-mono uppercase tracking-widest text-muted-foreground">
              Sentinel-OSINT // Geo Situational Awareness
            </div>
            <h1 className="mt-1 text-xl font-bold tracking-tight">Threat Map</h1>
          </div>
          <nav className="flex items-center gap-3 text-xs font-mono uppercase tracking-widest">
            <Link to="/" className="text-muted-foreground hover:text-foreground">Matrix</Link>
            <span className="text-muted-foreground">·</span>
            <span className="text-primary">Geo Map</span>
          </nav>
        </div>
      </header>

      <main className="mx-auto max-w-7xl px-6 py-6">
        <div className="mb-3 flex flex-wrap items-center gap-3 text-[11px] font-mono uppercase tracking-widest text-muted-foreground">
          <span>Assets: {assets.length}</span>
          <span>·</span>
          <span>Events: {events.length}</span>
          <span>·</span>
          <span className="flex items-center gap-2">
            {(["extreme", "severe", "moderate", "minor", "info"] as const).map((s) => (
              <span key={s} className="flex items-center gap-1">
                <span
                  className="inline-block h-2 w-2 rounded-full"
                  style={{ background: SEV_COLOR[s] }}
                />
                {s}
              </span>
            ))}
          </span>
          <span className="ml-auto">
            {eventsQ.data?.errors?.length ? eventsQ.data.errors.join(" · ") : "GDACS · USGS · NOAA"}
          </span>
        </div>
        {MAPBOX_TOKEN ? (
          <MapCanvas assets={assets} events={events} />
        ) : (
          <ConnectHint />
        )}
      </main>
    </div>
  );
}

function ConnectHint() {
  return (
    <div className="rounded-lg border border-dashed border-border bg-card p-8 text-sm">
      <div className="mb-2 font-mono text-xs uppercase tracking-widest text-muted-foreground">
        Mapbox not connected
      </div>
      <p className="text-muted-foreground">
        The map view uses Mapbox GL for asset + geo-event visualization. Connect
        the Mapbox connector in Lovable to enable it — the public token is read
        from <span className="font-mono">VITE_LOVABLE_CONNECTOR_MAPBOX_PUBLIC_TOKEN</span> at build time.
      </p>
    </div>
  );
}

type AssetLike = { id: string; ip: string; port: number; org: string; location: string; sector: string; lat?: number; lon?: number };

function MapCanvas({ assets, events }: { assets: AssetLike[]; events: GeoEvent[] }) {
  const ref = useRef<HTMLDivElement | null>(null);
  const mapRef = useRef<mapboxgl.Map | null>(null);
  const [ready, setReady] = useState(false);
  const geoAssets = useMemo(
    () => assets.filter((a) => typeof a.lat === "number" && typeof a.lon === "number"),
    [assets],
  );

  useEffect(() => {
    if (!ref.current || mapRef.current) return;
    mapboxgl.accessToken = MAPBOX_TOKEN!;
    const map = new mapboxgl.Map({
      container: ref.current,
      style: "mapbox://styles/mapbox/dark-v11",
      center: [-98.5, 39.8], // continental US center
      zoom: 3.2,
      attributionControl: true,
    });
    map.addControl(new mapboxgl.NavigationControl(), "top-right");
    map.on("load", () => setReady(true));
    mapRef.current = map;
    return () => {
      map.remove();
      mapRef.current = null;
    };
  }, []);

  // Render/refresh markers whenever data changes.
  useEffect(() => {
    const map = mapRef.current;
    if (!map || !ready) return;
    const markers: mapboxgl.Marker[] = [];

    for (const a of geoAssets) {
      const el = document.createElement("div");
      el.style.cssText =
        "width:12px;height:12px;border-radius:2px;background:hsl(210,90%,60%);border:2px solid #fff;box-shadow:0 0 4px rgba(0,0,0,.6);cursor:pointer;";
      const popup = new mapboxgl.Popup({ offset: 12 }).setHTML(
        `<div style="font-family:ui-monospace,monospace;font-size:11px;line-height:1.4">
          <div style="font-weight:600">${escape(a.ip)}:${a.port}</div>
          <div>${escape(a.org)}</div>
          <div style="color:#666">${escape(a.location)} · ${escape(a.sector)}</div>
        </div>`,
      );
      const m = new mapboxgl.Marker({ element: el })
        .setLngLat([a.lon as number, a.lat as number])
        .setPopup(popup)
        .addTo(map);
      markers.push(m);
    }

    for (const e of events) {
      if (typeof e.lat !== "number" || typeof e.lon !== "number") continue;
      const el = document.createElement("div");
      const size =
        e.severity === "extreme" ? 18 : e.severity === "severe" ? 14 : e.severity === "moderate" ? 11 : 8;
      el.style.cssText = `width:${size}px;height:${size}px;border-radius:50%;background:${SEV_COLOR[e.severity]};opacity:.85;border:1px solid rgba(0,0,0,.4);cursor:pointer;`;
      const popup = new mapboxgl.Popup({ offset: size / 2 + 4 }).setHTML(
        `<div style="font-family:ui-monospace,monospace;font-size:11px;line-height:1.4;max-width:260px">
          <div style="font-weight:600;text-transform:uppercase">${escape(e.source)} · ${escape(e.type)} · ${escape(e.severity)}</div>
          <div>${escape(e.title)}</div>
          ${e.startedAt ? `<div style="color:#666">${new Date(e.startedAt).toLocaleString()}</div>` : ""}
          ${e.url ? `<a href="${escape(e.url)}" target="_blank" rel="noreferrer" style="color:#60a5fa">source →</a>` : ""}
        </div>`,
      );
      const m = new mapboxgl.Marker({ element: el })
        .setLngLat([e.lon, e.lat])
        .setPopup(popup)
        .addTo(map);
      markers.push(m);
    }

    return () => {
      for (const m of markers) m.remove();
    };
  }, [geoAssets, events, ready]);

  return (
    <div
      ref={ref}
      className="h-[calc(100vh-220px)] min-h-[520px] w-full overflow-hidden rounded-lg border border-border"
    />
  );
}

function escape(s: string): string {
  return String(s).replace(/[&<>"']/g, (c) =>
    c === "&" ? "&amp;"
    : c === "<" ? "&lt;"
    : c === ">" ? "&gt;"
    : c === '"' ? "&quot;"
    : "&#39;",
  );
}