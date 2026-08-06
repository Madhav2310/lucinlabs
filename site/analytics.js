/* analytics.js — first-party event capture for lucin.pages.dev.
 *
 * Why first-party and not a vendor script: the collector at /api/events fans out
 * to whatever backend is configured server-side, so the page itself loads no
 * third-party code. That keeps check_site.py's blocking-third-party rule green,
 * keeps the vendor key out of the browser, and means swapping analytics vendors
 * never touches a page.
 *
 * Why no consent banner is needed: no cookie, no localStorage, no fingerprint.
 * The session id lives in sessionStorage and dies with the tab, so it stitches a
 * single visit together and cannot follow anyone across sessions or sites. The
 * server records a coarse country from Cloudflare and discards the IP. Respects
 * Do Not Track and Global Privacy Control, in which case nothing is sent at all.
 *
 * Events are batched and flushed with sendBeacon on pagehide, so the last event
 * before someone leaves — which is usually the interesting one — is not lost.
 */
(function () {
  "use strict";

  var DNT = navigator.doNotTrack === "1" || window.doNotTrack === "1" ||
            navigator.msDoNotTrack === "1" || navigator.globalPrivacyControl === true;
  if (DNT) return;

  var ENDPOINT = "/api/events";
  var MAX_BATCH = 20;
  var FLUSH_MS = 4000;
  var queue = [];
  var timer = null;

  function sessionId() {
    try {
      var k = "lucin_s", v = sessionStorage.getItem(k);
      if (!v) {
        v = (crypto.randomUUID ? crypto.randomUUID() : String(Math.random()).slice(2) + Date.now())
              .replace(/-/g, "").slice(0, 24);
        sessionStorage.setItem(k, v);
      }
      return v;
    } catch (e) { return "nostore"; }
  }
  var SID = sessionId();

  function device() {
    var w = window.innerWidth;
    return w < 640 ? "mobile" : w < 1024 ? "tablet" : "desktop";
  }

  /* Referrer HOST only. The full URL can carry search terms and private paths;
     the host is all that is needed to know where traffic comes from. */
  function refHost() {
    try { return document.referrer ? new URL(document.referrer).host : ""; }
    catch (e) { return ""; }
  }

  function flush(sync) {
    if (!queue.length) return;
    var payload = JSON.stringify({
      session_id: SID,
      path: location.pathname,
      ref_host: refHost(),
      device: device(),
      viewport_w: window.innerWidth,
      events: queue.splice(0, queue.length),
    });
    clearTimeout(timer); timer = null;
    try {
      if (sync && navigator.sendBeacon) {
        navigator.sendBeacon(ENDPOINT, new Blob([payload], { type: "application/json" }));
      } else {
        fetch(ENDPOINT, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: payload, keepalive: true,
        }).catch(function () {});
      }
    } catch (e) { /* analytics must never break the page */ }
  }

  function track(name, s, n) {
    queue.push({ name: name, prop_s: s == null ? null : String(s).slice(0, 64),
                 prop_n: typeof n === "number" ? n : null, ts: Date.now() });
    if (queue.length >= MAX_BATCH) return flush(false);
    if (!timer) timer = setTimeout(function () { flush(false); }, FLUSH_MS);
  }
  window.lucinTrack = track;   // so page code can emit its own events

  track("page_view");

  /* ---------- scroll depth: one event per quartile, never repeated ---------- */
  var hit = {};
  var scrollPending = false;
  window.addEventListener("scroll", function () {
    if (scrollPending) return;
    scrollPending = true;
    requestAnimationFrame(function () {
      scrollPending = false;
      var d = document.documentElement;
      var max = (d.scrollHeight - d.clientHeight) || 1;
      var pct = Math.min(100, Math.round((d.scrollTop / max) * 100));
      [25, 50, 75, 100].forEach(function (q) {
        if (pct >= q && !hit[q]) { hit[q] = 1; track("scroll_depth", null, q); }
      });
    });
  }, { passive: true });

  /* ---------- which sections actually get seen, and for how long ----------
     A section counts as read only after 1s of >=50% visibility, so a fast
     scroll past does not register as engagement. */
  if ("IntersectionObserver" in window) {
    var seen = {}, timers = {};
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        var id = e.target.id || e.target.getAttribute("data-sec") || "unnamed";
        if (e.isIntersecting) {
          if (!seen[id]) timers[id] = setTimeout(function () {
            seen[id] = 1; track("section_view", id);
          }, 1000);
        } else { clearTimeout(timers[id]); }
      });
    }, { threshold: 0.5 });
    document.querySelectorAll("section[id], figure.fig[id]").forEach(function (el) { io.observe(el); });
  }

  /* ---------- delegated click capture ----------
     One listener for the whole page. Elements opt in with data-ev, and the
     common cases (links, buttons) are inferred so nothing needs hand-wiring. */
  /* Controls that already emit a specific named event. Without this they would
     also fire a generic button_click, double-counting every tab switch and
     board toggle and making both numbers wrong. */
  var INSTRUMENTED = '[role="tab"],[data-tool],#copyInstall,#boardCta,#boardReset,#leadSubmit';

  /* Button text can be a multi-line block ("03\n  Keep the debt visible\n ..."),
     which makes a useless label once truncated. Collapse it to one line. */
  function label(el) {
    return (el.getAttribute("aria-label") || el.textContent || "")
      .replace(/\s+/g, " ").trim().slice(0, 64);
  }

  document.addEventListener("click", function (ev) {
    var el = ev.target.closest("[data-ev],a[href],button");
    if (!el) return;

    var explicit = el.getAttribute("data-ev");
    if (explicit) return track(explicit, el.getAttribute("data-ev-prop") || label(el));
    if (el.matches(INSTRUMENTED)) return;

    if (el.tagName === "A") {
      var href = el.getAttribute("href") || "";
      if (/^https?:/i.test(href)) {
        var host = "";
        try { host = new URL(href).host; } catch (e) {}
        if (host && host !== location.host) return track("outbound_click", host);
      }
      if (href.charAt(0) === "#") return track("anchor_click", href.slice(1));
      return track("internal_click", href);
    }
    if (el.tagName === "BUTTON") return track("button_click", label(el));
  }, { passive: true, capture: true });

  /* ---------- forms: separate starting from finishing ----------
     The gap between form_start and form_submit is the drop-off, which is the
     number worth knowing. Field VALUES are never read. */
  document.querySelectorAll("form").forEach(function (form) {
    var started = false;
    form.addEventListener("input", function () {
      if (started) return;
      started = true;
      track("form_start", form.id || "form");
    }, { passive: true, once: false });
    form.addEventListener("submit", function () {
      track("form_submit", form.id || "form");
    }, { passive: true });
  });

  /* ---------- dwell time, sent once on the way out ---------- */
  var t0 = Date.now(), gone = false;
  function leave() {
    if (gone) return;
    gone = true;
    track("page_leave", null, Math.min(1000 * 60 * 30, Date.now() - t0));
    flush(true);
  }
  window.addEventListener("pagehide", leave);
  document.addEventListener("visibilitychange", function () {
    if (document.visibilityState === "hidden") { flush(true); }
  });
})();
