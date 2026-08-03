// Lucin telemetry collector.
//
// Strict allowlist by design: this worker only accepts the fields listed in
// ALLOWED_STRING/ALLOWED_NUMBER below and silently drops everything else. That
// is the enforcement point for "never transmits file paths, source code,
// secret values, or tool/agent names" — even if the CLI is ever changed
// (by mistake or otherwise) to send more, this worker cannot persist it.
//
// No IP address, user agent, or any other request metadata is stored.

const ALLOWED_STRING = new Set([
  "anon_id", "event_type", "lucin_version", "python_version", "os",
  "frameworks", "output_format", "error_type",
]);
const ALLOWED_NUMBER = new Set([
  "agent_count", "tool_count", "file_count", "scan_duration_ms", "ci_mode",
]);
// finding_counts_json: an object of {rule_id: count} only. Rule IDs are a
// closed set (AG-XXX), never free text, so this cannot carry file paths or
// code even if malformed input is sent — validated below.
const RULE_ID_RE = /^AG-[A-Z0-9-]+$/;
const MAX_STRING_LEN = 64;

function sanitizeEvent(body) {
  const out = {};
  for (const key of ALLOWED_STRING) {
    const v = body[key];
    if (typeof v === "string" && v.length > 0 && v.length <= MAX_STRING_LEN) {
      out[key] = v;
    }
  }
  for (const key of ALLOWED_NUMBER) {
    const v = body[key];
    if (typeof v === "number" && Number.isFinite(v)) {
      out[key] = v;
    }
  }
  if (body.finding_counts_json && typeof body.finding_counts_json === "object") {
    const counts = {};
    for (const [ruleId, count] of Object.entries(body.finding_counts_json)) {
      if (RULE_ID_RE.test(ruleId) && typeof count === "number" && count >= 0 && count < 100000) {
        counts[ruleId] = Math.floor(count);
      }
    }
    out.finding_counts_json = JSON.stringify(counts);
  }
  return out;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname !== "/v1/event" || request.method !== "POST") {
      return new Response("not found", { status: 404 });
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return new Response("bad json", { status: 400 });
    }

    if (typeof body !== "object" || body === null || typeof body.anon_id !== "string" || typeof body.event_type !== "string") {
      return new Response("missing anon_id/event_type", { status: 400 });
    }

    const clean = sanitizeEvent(body);

    const columns = Object.keys(clean);
    const placeholders = columns.map(() => "?").join(", ");
    const sql = `INSERT INTO events (${columns.join(", ")}) VALUES (${placeholders})`;

    try {
      await env.DB.prepare(sql).bind(...columns.map((c) => clean[c])).run();
    } catch (e) {
      return new Response("db error", { status: 500 });
    }

    return new Response(null, { status: 204 });
  },
};
