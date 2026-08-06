// Auth gate for /dashboard/* — the page and its data endpoint.
//
// A Pages Functions _middleware here runs before the static asset is served, so
// site/dashboard/index.html is covered by the same check as /dashboard/data and
// there is no way to reach the page without the header.
//
// HTTP Basic over TLS, rather than a login form: no session store, no cookie to
// leak, no logout bug, and the browser remembers it. The threat model is "one
// person's private stats page", not multi-user auth.
//
// Fails closed: with DASHBOARD_PASSWORD unset the route 503s rather than falling
// open, so a missing secret can never publish the dashboard.

function safeEqual(a, b) {
  const enc = new TextEncoder();
  const x = enc.encode(a || ""), y = enc.encode(b || "");
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) diff |= (x[i] || 0) ^ (y[i] || 0);
  return diff === 0;
}

const CHALLENGE = {
  status: 401,
  headers: {
    "WWW-Authenticate": 'Basic realm="Lucin dashboard", charset="UTF-8"',
    // Belt and braces with robots.txt: a 401 is not indexable anyway, but if a
    // crawler ever sees a cached 200 this header still tells it to stay out.
    "X-Robots-Tag": "noindex, nofollow",
    "Cache-Control": "no-store",
  },
};

export async function onRequest({ request, env, next }) {
  if (!env.DASHBOARD_PASSWORD) {
    return new Response("dashboard not configured", { status: 503 });
  }

  const header = request.headers.get("Authorization") || "";
  if (!header.startsWith("Basic ")) return new Response("auth required", CHALLENGE);

  let decoded = "";
  try {
    decoded = atob(header.slice(6));
  } catch {
    return new Response("auth required", CHALLENGE);
  }
  const pass = decoded.slice(decoded.indexOf(":") + 1);   // username is ignored
  if (!safeEqual(pass, env.DASHBOARD_PASSWORD)) {
    return new Response("auth required", CHALLENGE);
  }

  const res = await next();
  const out = new Response(res.body, res);
  out.headers.set("X-Robots-Tag", "noindex, nofollow");
  out.headers.set("Cache-Control", "no-store");
  return out;
}
