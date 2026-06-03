# Scam Guard AI · စကမ်းကာကွယ်
Myanmar Anti-Scam Chatbot — Netlify + Supabase

## File Structure
```
scamguard-myanmar/
├── netlify.toml                   ← routes, headers, security
├── package.json
├── public/
│   ├── index.html                 ← chat page
│   └── admin.html                 ← admin panel (password protected)
└── netlify/functions/
    ├── chat.js                    ← Claude AI proxy + Supabase logging
    └── admin.js                   ← admin API (stats, logs, config)
```

## Required Environment Variables (Netlify)
| Variable             | Where to get                              |
|----------------------|-------------------------------------------|
| ANTHROPIC_API_KEY    | console.anthropic.com → API Keys          |
| ADMIN_TOKEN          | Your chosen admin password                |
| SUPABASE_URL         | Supabase → Project Settings → API → URL   |
| SUPABASE_ANON_KEY    | Supabase → Project Settings → API → anon  |

## Supabase SQL Setup
Run this in Supabase → SQL Editor:

```sql
CREATE TABLE chat_logs (
  id          BIGSERIAL PRIMARY KEY,
  session_id  TEXT NOT NULL DEFAULT 'anon',
  role        TEXT NOT NULL,
  message     TEXT,
  ip_hash     TEXT,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE site_config (
  key         TEXT PRIMARY KEY,
  value       TEXT,
  updated_at  TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE chat_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE site_config ENABLE ROW LEVEL SECURITY;
CREATE POLICY "service_all" ON chat_logs FOR ALL USING (true);
CREATE POLICY "service_all" ON site_config FOR ALL USING (true);
CREATE INDEX idx_logs_session ON chat_logs(session_id);
CREATE INDEX idx_logs_created ON chat_logs(created_at DESC);
CREATE INDEX idx_logs_role    ON chat_logs(role);
```

## Admin Panel Features
- Real-time stats (messages, sessions, 24h activity, errors)
- Chat log viewer with search + filter + export CSV
- Session browser (view each user's conversation)
- Keyword frequency charts
- Config editor (stored in Supabase)
- Data retention / log deletion
- Complete setup guide built-in

## Admin Default Password
Local testing: `scamguard-admin-2025`
Production: set `ADMIN_TOKEN` in Netlify env vars
