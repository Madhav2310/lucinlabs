// /dashboard/data — every number the dashboard shows, in one round trip.
//
// Guarded by ../dashboard/_middleware.js, so this inherits the same Basic Auth
// as the page. All SQL is static; the only caller-controlled value is the day
// window, which is clamped to an integer before it reaches a query.
//
// Reads three sources that used to live in three different tools:
//   events         — CLI scans     (site/functions/api/telemetry.js)
//   web_events     — site activity (site/functions/api/events.js)
//   pypi_downloads — installs      (.github/workflows/pypi-stats.yml)

const one = async (db, sql, ...b) =>
  (await db.prepare(sql).bind(...b).first()) || {};
const many = async (db, sql, ...b) =>
  ((await db.prepare(sql).bind(...b).all()).results) || [];

export async function onRequestGet({ request, env }) {
  const db = env.DB_TELEMETRY;
  const url = new URL(request.url);
  const days = Math.min(365, Math.max(1, parseInt(url.searchParams.get("days"), 10) || 30));
  const since = `-${days} days`;

  // Your own machine, so its activity can be shown separately instead of
  // swamping every total. Unset means nothing is excluded.
  const self = env.DASHBOARD_SELF_ANON || "";

  // Historical CI runs reported before LUCIN_TELEMETRY=0 was set in this repo's
  // workflows: ephemeral Linux runners, one or two events each. Rough by design
  // — it only has to separate a runner from a laptop, and new CI no longer
  // reports at all.
  const CI_SHAPED = `(os = 'linux' AND anon_id IN
      (SELECT anon_id FROM events GROUP BY anon_id HAVING COUNT(*) <= 3))`;

  try {
    const [
      totals, installsDaily, scansDaily, webDaily, topPages, funnel,
      frameworks, rules, countries, devices, versions, recentErrors, interactions,
      segments, rulesExternal, ciRuns,
    ] = await Promise.all([
      one(db, `SELECT
          (SELECT COUNT(*) FROM events WHERE event_type='scan')            AS scans_all,
          (SELECT COUNT(*) FROM events WHERE event_type='scan'
             AND anon_id != ?1 AND NOT ${CI_SHAPED})                       AS scans_external,
          (SELECT COUNT(DISTINCT anon_id) FROM events)                     AS machines_all,
          (SELECT COUNT(DISTINCT anon_id) FROM events
             WHERE anon_id != ?1 AND NOT ${CI_SHAPED})                     AS machines_external,
          -- Not all-time: pypistats' overall endpoint only returns a recent
          -- window, so this is the sum of every day we have recorded. It grows
          -- as the daily job runs. pypi_days says how many days that covers.
          (SELECT COALESCE(SUM(downloads),0) FROM pypi_downloads
             WHERE category='total')                                       AS pypi_recorded,
          (SELECT COUNT(DISTINCT day) FROM pypi_downloads
             WHERE category='total')                                       AS pypi_days,
          (SELECT MIN(day) FROM pypi_downloads WHERE category='total')     AS pypi_first,
          (SELECT MAX(day) FROM pypi_downloads WHERE category='total')     AS pypi_last,
          (SELECT COALESCE(SUM(downloads),0) FROM pypi_downloads
             WHERE category='ci_runs')                                     AS ci_runs_recorded,
          (SELECT COUNT(DISTINCT session_id) FROM web_events)              AS sessions_all,
          -- Median, not mean: one 47-second scan drags the average somewhere no
          -- actual scan lives. SQLite has no median(), hence the offset trick.
          (SELECT scan_duration_ms FROM events WHERE scan_duration_ms IS NOT NULL
             ORDER BY scan_duration_ms
             LIMIT 1 OFFSET (SELECT COUNT(*)/2 FROM events
                             WHERE scan_duration_ms IS NOT NULL))          AS median_scan_ms,
          (SELECT ROUND(AVG(scan_duration_ms)) FROM events
             WHERE scan_duration_ms IS NOT NULL)                           AS avg_scan_ms`, self),

      many(db, `SELECT day AS d, downloads AS n FROM pypi_downloads
                WHERE category='total' AND day >= date('now', ?) ORDER BY d`, since),

      many(db, `SELECT date(received_at) AS d, COUNT(*) AS n FROM events
                WHERE event_type='scan' AND received_at >= datetime('now', ?)
                GROUP BY d ORDER BY d`, since),

      many(db, `SELECT date(received_at) AS d, COUNT(DISTINCT session_id) AS n
                FROM web_events WHERE received_at >= datetime('now', ?)
                GROUP BY d ORDER BY d`, since),

      many(db, `SELECT path AS k, COUNT(DISTINCT session_id) AS n FROM web_events
                WHERE name='page_view' AND received_at >= datetime('now', ?)
                GROUP BY k ORDER BY n DESC LIMIT 12`, since),

      // Where attention is lost between landing and asking for Guard access.
      one(db, `SELECT
          COUNT(DISTINCT session_id) AS visited,
          COUNT(DISTINCT CASE WHEN name='scroll_depth' AND prop_n>=50
                              THEN session_id END)            AS scrolled_half,
          COUNT(DISTINCT CASE WHEN name IN ('board_tool_toggle','board_mincut','board_reset')
                              THEN session_id END)            AS used_board,
          COUNT(DISTINCT CASE WHEN name='copy_install' THEN session_id END) AS copied,
          COUNT(DISTINCT CASE WHEN name='form_start'   THEN session_id END) AS form_started,
          COUNT(DISTINCT CASE WHEN name='form_submit'  THEN session_id END) AS form_submitted
        FROM web_events WHERE received_at >= datetime('now', ?)`, since),

      many(db, `SELECT frameworks AS k, COUNT(*) AS n FROM events
                WHERE frameworks IS NOT NULL AND frameworks != ''
                GROUP BY k ORDER BY n DESC LIMIT 10`),

      // finding_counts_json is {"AG-XXX": n}; json_each expands it to rows.
      many(db, `SELECT key AS k, SUM(CAST(value AS INTEGER)) AS n
                FROM events, json_each(events.finding_counts_json)
                WHERE finding_counts_json IS NOT NULL AND finding_counts_json != '{}'
                GROUP BY k ORDER BY n DESC LIMIT 12`),

      many(db, `SELECT COALESCE(country,'??') AS k, COUNT(DISTINCT session_id) AS n
                FROM web_events WHERE received_at >= datetime('now', ?)
                GROUP BY k ORDER BY n DESC LIMIT 10`, since),

      many(db, `SELECT COALESCE(device,'?') AS k, COUNT(DISTINCT session_id) AS n
                FROM web_events WHERE received_at >= datetime('now', ?)
                GROUP BY k ORDER BY n DESC`, since),

      many(db, `SELECT COALESCE(lucin_version,'?') AS k, COUNT(*) AS n FROM events
                GROUP BY k ORDER BY n DESC LIMIT 8`),

      many(db, `SELECT COALESCE(error_type,'?') AS k, COUNT(*) AS n FROM events
                WHERE event_type='error' GROUP BY k ORDER BY n DESC LIMIT 8`),

      many(db, `SELECT name AS k, COUNT(*) AS n FROM web_events
                WHERE received_at >= datetime('now', ?)
                GROUP BY k ORDER BY n DESC LIMIT 16`, since),

      // Who the telemetry is actually from.
      many(db, `SELECT
          CASE WHEN anon_id = ?1 THEN 'you'
               WHEN ${CI_SHAPED}  THEN 'this repo CI'
               ELSE 'external' END AS k,
          COUNT(DISTINCT anon_id) AS machines,
          COUNT(*) AS n
        FROM events GROUP BY k ORDER BY n DESC`, self),

      // Rules, with your own machine taken out — the ranking differs.
      many(db, `SELECT key AS k, SUM(CAST(value AS INTEGER)) AS n
                FROM events, json_each(events.finding_counts_json)
                WHERE finding_counts_json NOT IN ('', '{}')
                  AND anon_id != ?1 AND NOT ${CI_SHAPED}
                GROUP BY k ORDER BY n DESC LIMIT 12`, self),

      // This repo's own CI runs per day, to read the install curve against.
      many(db, `SELECT day AS d, downloads AS n FROM pypi_downloads
                WHERE category='ci_runs' AND day >= date('now', ?) ORDER BY d`, since),
    ]);

    return Response.json({
      days, generated_at: new Date().toISOString(),
      totals, installsDaily, scansDaily, webDaily, topPages, funnel,
      frameworks, rules, countries, devices, versions, recentErrors, interactions,
      segments, rulesExternal, ciRuns, self_known: Boolean(self),
    }, { headers: { "Cache-Control": "no-store" } });
  } catch (e) {
    return Response.json({ error: String(e && e.message || e) }, { status: 500 });
  }
}
