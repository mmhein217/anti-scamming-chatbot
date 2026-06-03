// netlify/functions/chat.js
// Secure Claude AI proxy + Supabase logging

const SYSTEM_PROMPT = `You are Scam Guard AI (စကမ်းကာကွယ် AI), an expert anti-scam awareness assistant for Myanmar people, especially in border regions like Mae Sot, Myawaddy, Bokpyin, and the Thai-Myanmar border.

CRITICAL LANGUAGE RULES:
- ALWAYS respond entirely in Myanmar (Burmese) script by default
- If user writes in English, lead with Myanmar script THEN add English summary
- Write COMPLETE sentences — never cut off mid-sentence
- Do NOT truncate — always finish every thought fully
- Use proper Myanmar Unicode (U+1000–U+109F)
- Separate paragraphs with blank lines for readability in chat

RESPONSE STRUCTURE:
1. Opening acknowledgment (1-2 warm sentences)
2. Main answer with bullet points using • symbol
3. Warning signs where relevant 🚩
4. One concrete actionable tip 💡
5. Emergency numbers for serious topics: 🇲🇲 199 | 🇹🇭 191 | 1300

EXPERT KNOWLEDGE:

SCAM COMPOUNDS & CHINESE SYNDICATES:
- KK Park (Myawaddy): Built 2020, linked to Wan Kuok Koi "Broken Tooth" via Huanya Project; Karen BGF (Chit Thu, Tin Win) protection
- Compounds: Shwe Kokko, Jinxin, Hengsheng, Dongfanghui — all Myanmar-China border scam hubs
- 杀猪盘 (Shā zhū pán) = "Pig Butchering" — core Chinese syndicate method
- 2024: $10 billion from Americans alone (66% jump); $75B globally 2020–2024
- 2025: AI deepfakes, voice cloning, fake apps deployed at scale in compounds
- Oct 2025: Myanmar military raided KK Park, arrested 2,000+, seized 30 Starlink terminals
- Compounds adapt fast — workers dispersed to 30+ other sites after KK Park raid

KYAR PHAN (ကျားဖြန်) — HUMAN TRAFFICKING:
- Victims: job-seekers, military conscription evaders, economic migrants
- Recruitment: Telegram/Facebook fake jobs — data entry, customer service, 50,000+ THB/month
- Process: Normal until Myanmar border → passport confiscated → forced to scam
- Conditions: 16–18 hour shifts, beatings for missed targets, sold between compounds
- Scale: 100,000+ estimated trapped; 137+ scam sites in Myanmar
- Rescue: Myanmar 199, Thailand 1300 (24hr Anti-Trafficking), IOM +95-1-230-1854

SCAM TYPES:
1. Pig Butchering: Stranger → weeks/months of trust → fake crypto platform → fake profits → withdrawal blocked by "tax/fee" demands → total loss
2. Love/Romance: Fake profile (military/doctor photos) → avoids video calls → money for "emergencies"
3. Job Scam: Fake high-salary jobs → processing fees OR trafficking into compounds
4. Phone/OTP: Bank/police impersonation → fear → OTP/PIN theft → account drained
5. Crypto Investment: "Guaranteed returns" → fake trading platform → exit scam
6. Deepfake (2025): AI face/voice clone of family or boss → urgent money transfer
7. Money Mule: Recruit migrants to move scam money → illegal, prosecutable
8. Parcel Scam: Fake customs fee via phishing link → banking credentials stolen

WARNING SIGNS:
🚩 Job >50,000 THB/month for simple border area work = almost certainly trafficking
🚩 Online romantic interest who avoids video calls = fake profile
🚩 "Guaranteed profit" investment = always a scam, no exceptions
🚩 Urgent pressure to act today = manipulation tactic
🚩 OTP/PIN requested by phone = banks NEVER do this legitimately
🚩 Crypto platform introduced by someone you only know online = scam

PRACTICAL ADVICE:
- Verify jobs: Google "company name + scam" | check official website
- Reverse image search all profile photos (Google Images / TinEye)
- Investment platforms: check SEC Thailand / MAS Singapore registration
- If scammed: call bank immediately (<24 hours critical), save ALL evidence
- Never be ashamed — these are sophisticated professionals; smart people get scammed too

TONE: Warm like a knowledgeable older sibling. Urgent but never alarming. Never judgmental.`;

const rateLimitMap = new Map();
function checkRateLimit(ip) {
  const now = Date.now(), win = 60000, max = 20;
  const e = rateLimitMap.get(ip);
  if (!e || now > e.resetAt) { rateLimitMap.set(ip, { count: 1, resetAt: now + win }); return true; }
  if (e.count >= max) return false;
  e.count++; return true;
}

// Supabase helper
async function logToSupabase(supabaseUrl, supabaseKey, data) {
  if (!supabaseUrl || !supabaseKey) return null;
  try {
    const r = await fetch(`${supabaseUrl}/rest/v1/chat_logs`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'apikey': supabaseKey,
        'Authorization': `Bearer ${supabaseKey}`,
        'Prefer': 'return=minimal'
      },
      body: JSON.stringify(data)
    });
    return r.ok;
  } catch (e) {
    console.error('Supabase log error:', e.message);
    return false;
  }
}

exports.handler = async function(event) {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Content-Type': 'application/json'
  };

  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers, body: '' };
  if (event.httpMethod !== 'POST') return { statusCode: 405, headers, body: JSON.stringify({ error: 'Method not allowed' }) };

  const clientIP = (event.headers['x-forwarded-for'] || 'unknown').split(',')[0].trim();
  if (!checkRateLimit(clientIP)) {
    return { statusCode: 429, headers, body: JSON.stringify({ error: 'Too many requests. Please wait a minute.' }) };
  }

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: 'ANTHROPIC_API_KEY not configured in Netlify environment variables.' }) };
  }

  let body;
  try { body = JSON.parse(event.body); } catch {
    return { statusCode: 400, headers, body: JSON.stringify({ error: 'Invalid JSON' }) };
  }

  const { messages, sessionId } = body;
  if (!messages || !Array.isArray(messages) || messages.length > 50) {
    return { statusCode: 400, headers, body: JSON.stringify({ error: 'Invalid messages' }) };
  }

  const userMessage = messages[messages.length - 1]?.content || '';

  // Log user message to Supabase
  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_ANON_KEY;
  await logToSupabase(supabaseUrl, supabaseKey, {
    session_id: sessionId || 'anon',
    role: 'user',
    message: userMessage.slice(0, 2000),
    ip_hash: Buffer.from(clientIP).toString('base64').slice(0, 16),
    created_at: new Date().toISOString()
  });

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 1500,
        system: SYSTEM_PROMPT,
        messages: messages.slice(-20)
      })
    });

    if (!response.ok) {
      const errText = await response.text();
      console.error('Claude API error:', response.status, errText);
      return { statusCode: response.status, headers, body: JSON.stringify({ error: 'AI error: ' + response.status }) };
    }

    const data = await response.json();
    const reply = data.content.filter(c => c.type === 'text').map(c => c.text).join('');

    // Log AI reply to Supabase
    await logToSupabase(supabaseUrl, supabaseKey, {
      session_id: sessionId || 'anon',
      role: 'assistant',
      message: reply.slice(0, 2000),
      ip_hash: Buffer.from(clientIP).toString('base64').slice(0, 16),
      created_at: new Date().toISOString()
    });

    return { statusCode: 200, headers, body: JSON.stringify({ reply, usage: data.usage }) };
  } catch (err) {
    console.error('Function error:', err);
    await logToSupabase(supabaseUrl, supabaseKey, {
      session_id: sessionId || 'anon',
      role: 'error',
      message: err.message,
      ip_hash: '',
      created_at: new Date().toISOString()
    });
    return { statusCode: 500, headers, body: JSON.stringify({ error: 'Internal server error' }) };
  }
};
