// PyPI download ingest, as a Cloudflare Pages Function.
//
// Why this exists rather than the daily job writing D1 directly: `wrangler d1
// execute` from CI needs an API token carrying Account/D1/Edit, which is a
// broader grant than the job needs and turned out to be fiddly to attach to the
// existing deploy token. This Worker already holds the DB_TELEMETRY binding, so
// the job can POST rows and authenticate with a single shared secret that grants
// nothing except writing this one table.
//
// Auth: `Authorization: Bearer $PYPI_INGEST_TOKEN`, compared in constant time.
// Without PYPI_INGEST_TOKEN configured the endpoint refuses everything, so a
// misconfiguration fails closed rather than leaving an open writer.

const MAX_ROWS = 400;                 // ~13 months of daily rows in one call
const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;
const CATEGORY_RE = /^[A-Za-z0-9._-]{1,24}$/;

// Length-independent comparison, so a wrong token cannot be found byte by byte
// from response timing.
function safeEqual(a, b) {
  const enc = new TextEncoder();
  const x = enc.encode(a || ""), y = enc.encode(b || "");
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    diff |= (x[i] || 0) ^ (y[i] || 0);
  }
  return diff === 0;
}

export async function onRequestPost({ request, env }) {
  if (!env.PYPI_INGEST_TOKEN) {
    return new Response("ingest not configured", { status: 503 });
  }
  const auth = request.headers.get("Authorization") || "";
  if (!safeEqual(auth, `Bearer ${env.PYPI_INGEST_TOKEN}`)) {
    return new Response("unauthorized", { status: 401 });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return new Response("bad json", { status: 400 });
  }
  if (!body || !Array.isArray(body.rows)) {
    return new Response("missing rows", { status: 400 });
  }

  // Validate rather than trust: this writes to the same database the site's
  // analytics use, and the caller is a CI job whose input comes from a
  // third-party API.
  const rows = [];
  for (const r of body.rows.slice(0, MAX_ROWS)) {
    if (!r || typeof r.day !== "string" || !DAY_RE.test(r.day)) continue;
    if (typeof r.category !== "string" || !CATEGORY_RE.test(r.category)) continue;
    const n = Number(r.downloads);
    if (!Number.isFinite(n) || n < 0 || n > 1e9) continue;
    rows.push([r.day, r.category, Math.floor(n)]);
  }
  if (!rows.length) return new Response("no valid rows", { status: 400 });

  // UNIQUE(day, category) plus this upsert is what makes the daily job
  // idempotent: re-running a day already recorded corrects it in place.
  const sql = "INSERT INTO pypi_downloads (day, category, downloads) VALUES (?, ?, ?) " +
              "ON CONFLICT(day, category) DO UPDATE SET downloads = excluded.downloads";
  try {
    await env.DB_TELEMETRY.batch(
      rows.map((r) => env.DB_TELEMETRY.prepare(sql).bind(...r))
    );
  } catch {
    return new Response("db error", { status: 500 });
  }

  return new Response(JSON.stringify({ ok: true, written: rows.length }), {
    status: 200, headers: { "Content-Type": "application/json" },
  });
}
