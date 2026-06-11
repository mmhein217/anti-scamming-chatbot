// netlify/functions/admin.js
// Secure admin API — Supabase-backed stats, logs, config

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Token',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store'
  };
}

async function supabaseRequest(url, key, path, method = 'GET', body = null, params = '') {
  const opts = {
    method,
    headers: {
      'Content-Type': 'application/json',
      'apikey': key,
      'Authorization': `Bearer ${key}`,
      'Prefer': 'return=representation'
    }
  };
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(`${url}/rest/v1/${path}${params}`, opts);
  if (!r.ok) throw new Error(`Supabase ${r.status}: ${await r.text()}`);
  return r.status === 204 ? null : r.json();
}

exports.handler = async function(event) {
  const h = corsHeaders();
  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: h, body: '' };

  // Auth
  const adminToken = process.env.ADMIN_TOKEN;
  const provided = event.headers['x-admin-token'];
  if (!adminToken || provided !== adminToken) {
    return { statusCode: 401, headers: h, body: JSON.stringify({ error: 'Unauthorized' }) };
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_ANON_KEY;
  const hasSupabase = !!(supabaseUrl && supabaseKey);

  let body = {};
  try { body = JSON.parse(event.body || '{}'); } catch {}
  const action = body.action;

  try {

    // ── STATS ──
    if (action === 'stats') {
      let stats = {
        apiConfigured: !!process.env.GEMINI_API_KEY,
        supabaseConfigured: hasSupabase,
        model: process.env.GEMINI_MODEL || 'gemini-2.0-flash',
        timestamp: new Date().toISOString(),
        totalMessages: 0,
        totalSessions: 0,
        errorsToday: 0,
        messagesLast24h: 0
      };

      if (hasSupabase) {
        const since24h = new Date(Date.now() - 86400000).toISOString();

        // total messages
        const total = await supabaseRequest(supabaseUrl, supabaseKey,
          'chat_logs', 'GET', null,
          '?select=count&role=neq.error');
        stats.totalMessages = total?.[0]?.count || 0;

        // unique sessions
        const sessions = await supabaseRequest(supabaseUrl, supabaseKey,
          'chat_logs', 'GET', null,
          '?select=session_id&role=eq.user');
        const uniqueSessions = new Set((sessions || []).map(r => r.session_id));
        stats.totalSessions = uniqueSessions.size;

        // last 24h messages
        const recent = await supabaseRequest(supabaseUrl, supabaseKey,
          'chat_logs', 'GET', null,
          `?select=count&created_at=gte.${since24h}&role=eq.user`);
        stats.messagesLast24h = recent?.[0]?.count || 0;

        // errors today
        const errs = await supabaseRequest(supabaseUrl, supabaseKey,
          'chat_logs', 'GET', null,
          `?select=count&created_at=gte.${since24h}&role=eq.error`);
        stats.errorsToday = errs?.[0]?.count || 0;
      }

      return { statusCode: 200, headers: h, body: JSON.stringify(stats) };
    }

    // ── GET LOGS ──
    if (action === 'getLogs') {
      if (!hasSupabase) return { statusCode: 200, headers: h, body: JSON.stringify({ logs: [], supabaseConfigured: false }) };

      const limit = Math.min(body.limit || 100, 500);
      const offset = body.offset || 0;
      const role = body.role || null;
      const search = body.search || null;
      const session = body.session || null;

      let params = `?select=*&order=created_at.desc&limit=${limit}&offset=${offset}`;
      if (role) params += `&role=eq.${role}`;
      if (session) params += `&session_id=eq.${session}`;

      const logs = await supabaseRequest(supabaseUrl, supabaseKey, 'chat_logs', 'GET', null, params);

      // client-side search filter (Supabase free tier doesn't have full-text search)
      const filtered = search
        ? (logs || []).filter(l => l.message?.toLowerCase().includes(search.toLowerCase()))
        : (logs || []);

      return { statusCode: 200, headers: h, body: JSON.stringify({ logs: filtered, supabaseConfigured: true }) };
    }

    // ── GET SESSION LIST ──
    if (action === 'getSessions') {
      if (!hasSupabase) return { statusCode: 200, headers: h, body: JSON.stringify({ sessions: [] }) };

      const rows = await supabaseRequest(supabaseUrl, supabaseKey,
        'chat_logs', 'GET', null,
        '?select=session_id,created_at&role=eq.user&order=created_at.desc&limit=200');

      // group by session
      const map = {};
      for (const r of (rows || [])) {
        if (!map[r.session_id]) map[r.session_id] = { session_id: r.session_id, last_active: r.created_at, count: 0 };
        map[r.session_id].count++;
      }
      const sessions = Object.values(map).sort((a, b) => new Date(b.last_active) - new Date(a.last_active));

      return { statusCode: 200, headers: h, body: JSON.stringify({ sessions }) };
    }

    // ── SAVE CONFIG ──
    if (action === 'saveConfig') {
      if (!hasSupabase) return { statusCode: 200, headers: h, body: JSON.stringify({ ok: true, note: 'Config saved locally (no Supabase)' }) };

      const { key, value } = body;
      if (!key) return { statusCode: 400, headers: h, body: JSON.stringify({ error: 'key required' }) };

      // upsert into site_config table
      await supabaseRequest(supabaseUrl, supabaseKey, 'site_config', 'POST',
        { key, value: JSON.stringify(value), updated_at: new Date().toISOString() },
        '');

      return { statusCode: 200, headers: h, body: JSON.stringify({ ok: true }) };
    }

    // ── GET CONFIG ──
    if (action === 'getConfig') {
      if (!hasSupabase) return { statusCode: 200, headers: h, body: JSON.stringify({ config: {} }) };

      const rows = await supabaseRequest(supabaseUrl, supabaseKey, 'site_config', 'GET', null, '?select=key,value');
      const config = {};
      for (const r of (rows || [])) {
        try { config[r.key] = JSON.parse(r.value); } catch { config[r.key] = r.value; }
      }
      return { statusCode: 200, headers: h, body: JSON.stringify({ config }) };
    }

    // ── DELETE LOGS ──
    if (action === 'deleteLogs') {
      if (!hasSupabase) return { statusCode: 200, headers: h, body: JSON.stringify({ ok: true }) };

      const olderThan = body.olderThan; // ISO date string
      let params = '';
      if (olderThan) params = `?created_at=lt.${olderThan}`;
      else params = '?id=gte.0'; // delete all

      await supabaseRequest(supabaseUrl, supabaseKey, 'chat_logs', 'DELETE', null, params);
      return { statusCode: 200, headers: h, body: JSON.stringify({ ok: true }) };
    }

    // ── KEYWORD STATS ──
    if (action === 'keywordStats') {
      if (!hasSupabase) return { statusCode: 200, headers: h, body: JSON.stringify({ keywords: {} }) };

      const rows = await supabaseRequest(supabaseUrl, supabaseKey,
        'chat_logs', 'GET', null,
        '?select=message&role=eq.user&limit=1000&order=created_at.desc');

      const allText = (rows || []).map(r => r.message?.toLowerCase()).join(' ');
      const kw = {
        'job / အလုပ်': (allText.match(/job|data entry|အလုပ်/g)||[]).length,
        'ငွေ / transfer': (allText.match(/ငွေ|transfer|payment/g)||[]).length,
        'crypto / bitcoin': (allText.match(/crypto|bitcoin|invest|ရင်းနှီး/g)||[]).length,
        'love / ချစ်': (allText.match(/love|ချစ်|romance/g)||[]).length,
        'KK Park / မြဝတီ': (allText.match(/kk park|မြဝတီ|myawaddy|scam compound/g)||[]).length,
        'otp / ဘဏ်': (allText.match(/otp|pin|ဘဏ်|bank/g)||[]).length
      };
      return { statusCode: 200, headers: h, body: JSON.stringify({ keywords: kw }) };
    }

    // ── GET CACHED ANSWERS ──
    if (action === 'getCachedAnswers') {
      if (!hasSupabase) return { statusCode: 200, headers: h, body: JSON.stringify({ answers: [] }) };
      const rows = await supabaseRequest(supabaseUrl, supabaseKey, 'cached_answers', 'GET', null, '?select=*&order=id.asc');
      return { statusCode: 200, headers: h, body: JSON.stringify({ answers: rows || [] }) };
    }

    // ── ADD CACHED ANSWER ──
    if (action === 'addCachedAnswer') {
      if (!hasSupabase) return { statusCode: 400, headers: h, body: JSON.stringify({ error: 'Supabase not configured' }) };
      const { question, keywords, answer } = body;
      if (!question || !keywords || !answer) return { statusCode: 400, headers: h, body: JSON.stringify({ error: 'question, keywords, and answer required' }) };
      const row = await supabaseRequest(supabaseUrl, supabaseKey, 'cached_answers', 'POST',
        { question, keywords, answer, is_active: true, hit_count: 0, created_at: new Date().toISOString(), updated_at: new Date().toISOString() }, '');
      return { statusCode: 200, headers: h, body: JSON.stringify({ ok: true, id: row?.[0]?.id }) };
    }

    // ── UPDATE CACHED ANSWER ──
    if (action === 'updateCachedAnswer') {
      if (!hasSupabase) return { statusCode: 400, headers: h, body: JSON.stringify({ error: 'Supabase not configured' }) };
      const { id, question, keywords, answer, is_active } = body;
      if (!id) return { statusCode: 400, headers: h, body: JSON.stringify({ error: 'id required' }) };
      const patch = { updated_at: new Date().toISOString() };
      if (question !== undefined) patch.question = question;
      if (keywords !== undefined) patch.keywords = keywords;
      if (answer !== undefined) patch.answer = answer;
      if (is_active !== undefined) patch.is_active = is_active;
      await supabaseRequest(supabaseUrl, supabaseKey, 'cached_answers', 'PATCH', patch, `?id=eq.${id}`);
      return { statusCode: 200, headers: h, body: JSON.stringify({ ok: true }) };
    }

    // ── DELETE CACHED ANSWER ──
    if (action === 'deleteCachedAnswer') {
      if (!hasSupabase) return { statusCode: 400, headers: h, body: JSON.stringify({ error: 'Supabase not configured' }) };
      const { id } = body;
      if (!id) return { statusCode: 400, headers: h, body: JSON.stringify({ error: 'id required' }) };
      await supabaseRequest(supabaseUrl, supabaseKey, 'cached_answers', 'DELETE', null, `?id=eq.${id}`);
      return { statusCode: 200, headers: h, body: JSON.stringify({ ok: true }) };
    }

  } catch (err) {
    console.error('Admin function error:', err);
    return { statusCode: 500, headers: h, body: JSON.stringify({ error: err.message }) };
  }

  return { statusCode: 400, headers: h, body: JSON.stringify({ error: 'Unknown action' }) };
};
