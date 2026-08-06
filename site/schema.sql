-- schema.sql — the D1 schema for lucin.pages.dev, in version control.
--
-- Until now these tables existed only in the Cloudflare dashboard, which meant
-- the shape of the data was undocumented and unreviewable, and a column rename
-- could silently break a collector with nothing to catch it.
--
-- Apply with:
--   wrangler d1 execute lucin-telemetry --file=site/schema.sql --remote
--   wrangler d1 execute lucin-leads     --file=site/schema.sql --remote
-- Every statement is IF NOT EXISTS, so re-running it is safe.

-- ---------------------------------------------------------------- CLI events
-- Written by site/functions/api/telemetry.js. Field set is fixed by the
-- allowlist in that file: no file paths, source, secrets, tool or agent names.
CREATE TABLE IF NOT EXISTS events (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  anon_id             TEXT,
  event_type          TEXT,
  lucin_version       TEXT,
  python_version      TEXT,
  os                  TEXT,
  frameworks          TEXT,
  output_format       TEXT,
  error_type          TEXT,
  agent_count         INTEGER,
  tool_count          INTEGER,
  file_count          INTEGER,
  scan_duration_ms    INTEGER,
  ci_mode             INTEGER,
  finding_counts_json TEXT,
  created_at          TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_events_type_time ON events (event_type, created_at);
CREATE INDEX IF NOT EXISTS idx_events_anon      ON events (anon_id);

-- ------------------------------------------------------------- web analytics
-- Written by site/functions/api/events.js from site/analytics.js.
--
-- `session_id` is a random value held in sessionStorage and dropped when the
-- tab closes: it stitches one visit together and cannot follow anyone across
-- sessions or sites. No cookie, no IP, no user agent string is stored — only
-- the coarse buckets below, which is why this needs no consent banner.
CREATE TABLE IF NOT EXISTS web_events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id  TEXT,
  name        TEXT NOT NULL,
  path        TEXT,
  ref_host    TEXT,      -- referrer HOST only, never the full URL
  country     TEXT,      -- from CF-IPCountry; the IP itself is discarded
  device      TEXT,      -- desktop | tablet | mobile
  viewport_w  INTEGER,
  prop_s      TEXT,      -- one string payload, e.g. the tool id that was toggled
  prop_n      REAL,      -- one numeric payload, e.g. scroll depth or dwell ms
  ts          INTEGER,   -- client timestamp, ms since epoch
  created_at  TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_web_name_time ON web_events (name, created_at);
CREATE INDEX IF NOT EXISTS idx_web_session   ON web_events (session_id);
CREATE INDEX IF NOT EXISTS idx_web_path      ON web_events (path);

-- ---------------------------------------------------------- package installs
-- Written daily by .github/workflows/pypi-stats.yml from pypistats.org.
-- UNIQUE(day, category) makes the daily job idempotent: re-running it for a day
-- already recorded updates the row instead of double-counting.
CREATE TABLE IF NOT EXISTS pypi_downloads (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  day        TEXT NOT NULL,
  category   TEXT NOT NULL,   -- 'total', or a python version / installer label
  downloads  INTEGER NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  UNIQUE (day, category)
);
CREATE INDEX IF NOT EXISTS idx_pypi_day ON pypi_downloads (day);

-- -------------------------------------------------------------------- leads
-- Written by site/functions/api/leads.js.
CREATE TABLE IF NOT EXISTS leads (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  name       TEXT,
  email      TEXT UNIQUE,
  stack      TEXT,
  note       TEXT,
  ua         TEXT,
  country    TEXT,
  created_at TEXT
);
