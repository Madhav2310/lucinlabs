// Lead capture for the design-partner form, as a Cloudflare Pages Function.
// Stores to D1; no third party. Lives at lucin.pages.dev/api/leads — same
// origin as the form, so no CORS handling is needed.

export async function onRequestPost({ request, env }) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "bad json" }, 400);
  }

  const name = String(body.name || "").trim().slice(0, 120);
  const email = String(body.email || "").trim().slice(0, 200).toLowerCase();
  const stack = String(body.stack || "").trim().slice(0, 40);
  const note = String(body.note || "").trim().slice(0, 1000);

  if (!name || !email || !/^[^@\s]+@[^@\s.]+\.[^@\s]+$/.test(email)) {
    return json({ ok: false, error: "name and a valid email are required" }, 400);
  }

  try {
    await env.DB_LEADS.prepare(
      "INSERT INTO leads (name, email, stack, note, ua, country, created_at) VALUES (?,?,?,?,?,?,?)"
    ).bind(
      name, email, stack, note,
      (request.headers.get("User-Agent") || "").slice(0, 300),
      request.headers.get("CF-IPCountry") || "",
      new Date().toISOString()
    ).run();
  } catch (e) {
    if (!/UNIQUE/i.test(String(e))) return json({ ok: false, error: "storage failed" }, 500);
  }
  return json({ ok: true }, 200);
}

function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status, headers: { "Content-Type": "application/json" },
  });
}
