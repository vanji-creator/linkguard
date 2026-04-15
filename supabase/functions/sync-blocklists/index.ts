/**
 * LinkGuard — sync-blocklists Edge Function
 *
 * Fetches URLhaus, OpenPhish, and ThreatFox threat feeds and upserts them
 * into the Supabase `urls` table. Run this on a daily cron or manually via:
 *
 *   supabase functions invoke sync-blocklists --no-verify-jwt
 *
 * Schedule it (in Supabase dashboard → Edge Functions → Schedules):
 *   Cron:  0 2 * * *   (2am UTC daily)
 */

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
);

// ── Fetchers ──────────────────────────────────────────────

async function fetchURLhaus(): Promise<UrlRow[]> {
  const resp = await fetch("https://urlhaus.abuse.ch/downloads/text_recent/");
  if (!resp.ok) throw new Error(`URLhaus HTTP ${resp.status}`);
  const text = await resp.text();
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#") && l.startsWith("http"))
    .map((url) => ({ url, verdict: "dangerous" as const, source: "urlhaus" }));
}

async function fetchOpenPhish(): Promise<UrlRow[]> {
  const resp = await fetch("https://openphish.com/feed.txt");
  if (!resp.ok) throw new Error(`OpenPhish HTTP ${resp.status}`);
  const text = await resp.text();
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.startsWith("http"))
    .map((url) => ({ url, verdict: "dangerous" as const, source: "openphish" }));
}

async function fetchThreatFox(): Promise<UrlRow[]> {
  const resp = await fetch("https://threatfox-api.abuse.ch/api/v1/", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query: "get_iocs", days: 7 }),
  });
  if (!resp.ok) throw new Error(`ThreatFox HTTP ${resp.status}`);
  const data = await resp.json();
  const rows: UrlRow[] = [];
  if (data.data) {
    for (const ioc of data.data) {
      if (ioc.ioc_type === "url" && ioc.ioc) {
        rows.push({ url: ioc.ioc, verdict: "dangerous", source: "threatfox" });
      }
    }
  }
  return rows;
}

// ── Upserter ─────────────────────────────────────────────

interface UrlRow {
  url: string;
  verdict: "dangerous" | "suspicious";
  source: string;
}

async function upsertBatch(rows: UrlRow[]): Promise<number> {
  const CHUNK = 500;
  let inserted = 0;
  for (let i = 0; i < rows.length; i += CHUNK) {
    const chunk = rows.slice(i, i + CHUNK);
    const { error, count } = await supabase
      .from("urls")
      .upsert(chunk, { onConflict: "url", ignoreDuplicates: true, count: "exact" });
    if (error) console.error("upsert error:", error.message);
    else inserted += count ?? 0;
  }
  return inserted;
}

// ── Handler ───────────────────────────────────────────────

Deno.serve(async () => {
  const results: Record<string, { fetched: number; error?: string }> = {};

  // Fetch all three feeds in parallel, tolerate individual failures
  const [urlhausResult, openphishResult, threatfoxResult] = await Promise.allSettled([
    fetchURLhaus(),
    fetchOpenPhish(),
    fetchThreatFox(),
  ]);

  const allRows: UrlRow[] = [];

  for (const [name, result] of [
    ["urlhaus", urlhausResult],
    ["openphish", openphishResult],
    ["threatfox", threatfoxResult],
  ] as const) {
    if (result.status === "fulfilled") {
      results[name] = { fetched: result.value.length };
      allRows.push(...result.value);
    } else {
      results[name] = { fetched: 0, error: (result.reason as Error).message };
      console.error(`${name} failed:`, (result.reason as Error).message);
    }
  }

  const newRows = await upsertBatch(allRows);

  const body = {
    ok: true,
    total_fetched: allRows.length,
    new_rows_inserted: newRows,
    feeds: results,
    synced_at: new Date().toISOString(),
  };

  console.log("sync-blocklists complete:", JSON.stringify(body));

  return new Response(JSON.stringify(body), {
    headers: { "Content-Type": "application/json" },
  });
});
