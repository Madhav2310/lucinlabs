-- schema_telemetry.sql — D1 schema for the `lucin_telemetry` database.
--
-- Apply with:
--   wrangler d1 execute lucin_telemetry --file=site/schema_telemetry.sql --remote
--
-- Every statement is IF NOT EXISTS, so re-running is safe and never touches
-- existing rows. Kept in version control because the shape of this data
-- previously existed only in the Cloudflare dashboard, where it could not be
-- reviewed or diffed.
--
-- The `events` block below was transcribed from the LIVE table
-- (`SELECT sql FROM sqlite_master`), not written from memory — an earlier draft
-- guessed `created_at` where production actually uses `received_at`, and the
-- apply failed on the index. If you edit this file, read the live schema first.

-- ---------------------------------------------------------------- CLI events
-- Written by site/functions/api/telemetry.js. The field set is fixed by the
-- allowlist in that file: no file paths, source, secret values, tool or agent
-- names can be persisted here even if the CLI is changed to send them.
CREATE TABLE IF NOT EXISTS events (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  received_at         TEXT NOT NULL DEFAULT (datetime('now')),
  anon_id             TEXT NOT NULL,
  event_type          TEXT NOT NULL,
  lucin_version       TEXT,
  python_version      TEXT,
  os                  TEXT,
  frameworks          TEXT,
  agent_count         INTEGER,
  tool_count          INTEGER,
  file_count          INTEGER,
  scan_duration_ms    REAL,
  output_format       TEXT,
  ci_mode             INTEGER,
  finding_counts_json TEXT,
  error_type          TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_type ON events (event_type);
CREATE INDEX IF NOT EXISTS idx_events_time ON events (received_at);
CREATE INDEX IF NOT EXISTS idx_events_anon ON events (anon_id);

-- ------------------------------------------------------------- web analytics
-- Written by site/functions/api/events.js from site/analytics.js.
--
-- `session_id` is a random value held in sessionStorage and dropped when the
-- tab closes: it stitches one visit together and cannot follow anyone across
-- sessions or sites. No cookie, no IP, no user-agent string is stored — only
-- the coarse buckets below, which is why this needs no consent banner.
CREATE TABLE IF NOT EXISTS web_events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  received_at TEXT NOT NULL DEFAULT (datetime('now')),
  session_id  TEXT,
  name        TEXT NOT NULL,
  path        TEXT,
  ref_host    TEXT,      -- referrer HOST only, never the full URL
  country     TEXT,      -- from CF-IPCountry; the IP itself is discarded
  device      TEXT,      -- desktop | tablet | mobile
  viewport_w  INTEGER,
  prop_s      TEXT,      -- one string payload, e.g. the tool id that was toggled
  prop_n      REAL,      -- one numeric payload, e.g. scroll depth or dwell ms
  ts          INTEGER    -- client timestamp, ms since epoch
);
CREATE INDEX IF NOT EXISTS idx_web_name ON web_events (name);
CREATE INDEX IF NOT EXISTS idx_web_time ON web_events (received_at);
CREATE INDEX IF NOT EXISTS idx_web_sess ON web_events (session_id);
CREATE INDEX IF NOT EXISTS idx_web_path ON web_events (path);

-- ---------------------------------------------------------- package installs
-- Written daily by .github/workflows/pypi-stats.yml from pypistats.org.
-- UNIQUE(day, category) makes the job idempotent: re-running it for a day
-- already recorded updates the row instead of double-counting.
CREATE TABLE IF NOT EXISTS pypi_downloads (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  received_at TEXT NOT NULL DEFAULT (datetime('now')),
  day         TEXT NOT NULL,
  category    TEXT NOT NULL,   -- 'total', or a python-version label such as py3.11
  downloads   INTEGER NOT NULL,
  UNIQUE (day, category)
);
CREATE INDEX IF NOT EXISTS idx_pypi_day ON pypi_downloads (day);
