-- schema_leads.sql — D1 schema for the `lucin-leads` database.
--
-- Applied with:
--   wrangler d1 execute lucin-leads --file=site/schema_leads.sql --remote
-- Every statement is IF NOT EXISTS, so re-running is safe and never touches
-- existing rows. Kept in version control because until now the shape of this
-- data existed only in the Cloudflare dashboard, where it could not be reviewed.

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
