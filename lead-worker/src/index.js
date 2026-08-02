// Lead capture for the design-partner form. Stores to D1; no third party.
const ALLOWED_ORIGINS = ["https://lucin.pages.dev"];

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const cors = {
      "Access-Control-Allow-Origin": ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0],
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Vary": "Origin",
    };
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    if (request.method !== "POST") return new Response("method not allowed", { status: 405, headers: cors });

    let body;
    try { body = await request.json(); } catch { return json({ ok: false, error: "bad json" }, 400, cors); }

    const name = String(body.name || "").trim().slice(0, 120);
    const email = String(body.email || "").trim().slice(0, 200).toLowerCase();
    const stack = String(body.stack || "").trim().slice(0, 40);
    const note = String(body.note || "").trim().slice(0, 1000);

    if (!name || !email || !/^[^@\s]+@[^@\s.]+\.[^@\s]+$/.test(email)) {
      return json({ ok: false, error: "name and a valid email are required" }, 400, cors);
    }

    try {
      await env.DB.prepare(
        "INSERT INTO leads (name, email, stack, note, ua, country, created_at) VALUES (?,?,?,?,?,?,?)"
      ).bind(
        name, email, stack, note,
        (request.headers.get("User-Agent") || "").slice(0, 300),
        request.headers.get("CF-IPCountry") || "",
        new Date().toISOString()
      ).run();
    } catch (e) {
      if (!/UNIQUE/i.test(String(e))) return json({ ok: false, error: "storage failed" }, 500, cors);
    }
    return json({ ok: true }, 200, cors);
  },
};

function json(obj, status, cors) {
  return new Response(JSON.stringify(obj), {
    status, headers: { ...cors, "Content-Type": "application/json" },
  });
}
