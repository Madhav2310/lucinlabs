// Web analytics collector for lucin.pages.dev, as a Cloudflare Pages Function.
//
// Mirrors the design of telemetry.js deliberately: a strict server-side
// allowlist, so the endpoint cannot persist a field it was never meant to,
// even if the client is changed to send more.
//
// What is NOT stored, by construction:
//   * the IP address (Cloudflare gives us CF-IPCountry; the IP is discarded)
//   * the user agent string (only a coarse desktop/tablet/mobile bucket)
//   * the full referrer URL (host only — the path can carry search terms)
//   * any form field value
//
// Vendor fan-out: if POSTHOG_KEY is set as an environment secret on the Pages
// project, events are ALSO forwarded to PostHog server-side. The page therefore
// loads no third-party script, the key never reaches a browser, and swapping
// vendors is a change here rather than on every page. Unset the secret and the
// forward is skipped — D1 remains the source of truth either way.

const ALLOWED_EVENTS = new Set([
  "page_view", "page_leave", "scroll_depth", "section_view",
  "outbound_click", "internal_click", "anchor_click", "button_click",
  "form_start", "form_submit", "form_error", "form_success",
  "copy_install", "tab_switch", "step_switch",
  "board_tool_toggle", "board_mincut", "board_reset",
  "figure_view", "pypi_downloads",
]);

const MAX_EVENTS_PER_REQUEST = 40;
const MAX_STR = 64;

const str = (v, n = MAX_STR) =>
  typeof v === "string" && v.length ? v.slice(0, n) : null;

const num = (v) =>
  typeof v === "number" && Number.isFinite(v) ? v : null;

export async function onRequestPost({ request, env }) {
  let body;
  try {
    body = await request.json();
  } catch {
    return new Response("bad json", { status: 400 });
  }
  if (!body || !Array.isArray(body.events)) {
    return new Response("missing events", { status: 400 });
  }

  const shared = {
    session_id: str(body.session_id, 32),
    path: str(body.path, 128),
    ref_host: str(body.ref_host, 128),
    device: ["desktop", "tablet", "mobile"].includes(body.device) ? body.device : null,
    viewport_w: num(body.viewport_w),
    country: request.headers.get("CF-IPCountry") || null,
  };

  const rows = [];
  for (const e of body.events.slice(0, MAX_EVENTS_PER_REQUEST)) {
    if (!e || !ALLOWED_EVENTS.has(e.name)) continue;   // unknown names are dropped
    rows.push({
      ...shared,
      name: e.name,
      prop_s: str(e.prop_s),
      prop_n: num(e.prop_n),
      ts: num(e.ts),
    });
  }
  if (!rows.length) return new Response(null, { status: 204 });

  const cols = ["session_id", "name", "path", "ref_host", "country",
                "device", "viewport_w", "prop_s", "prop_n", "ts"];
  const sql = `INSERT INTO web_events (${cols.join(", ")}) ` +
              `VALUES (${cols.map(() => "?").join(", ")})`;

  try {
    // One batch round-trip rather than N inserts — a page_leave flush can carry
    // twenty events and D1 charges per statement, not per row.
    await env.DB_TELEMETRY.batch(
      rows.map((r) => env.DB_TELEMETRY.prepare(sql).bind(...cols.map((c) => r[c] ?? null)))
    );
  } catch {
    return new Response("db error", { status: 500 });
  }

  forward(env, rows);
  return new Response(null, { status: 204 });
}

// Fire-and-forget. A vendor being down must never fail the write we already made.
function forward(env, rows) {
  if (!env.POSTHOG_KEY) return;
  const host = env.POSTHOG_HOST || "https://eu.i.posthog.com";
  const batch = rows.map((r) => ({
    event: r.name,
    distinct_id: r.session_id || "anon",
    properties: {
      $current_url: r.path, path: r.path, referrer_host: r.ref_host,
      country: r.country, device: r.device, viewport_w: r.viewport_w,
      value: r.prop_s, amount: r.prop_n, source: "web",
    },
    timestamp: r.ts ? new Date(r.ts).toISOString() : undefined,
  }));
  fetch(`${host}/batch/`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ api_key: env.POSTHOG_KEY, batch }),
  }).catch(() => {});
}
