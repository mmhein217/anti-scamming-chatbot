// netlify/functions/chat.js
// Gemini Pro API + Supabase logging

const SYSTEM_PROMPT = `You are Scam Guard AI (စကမ်းကာကွယ် AI), an expert anti-scam awareness assistant for Myanmar people, especially in border regions like Mae Sot, Myawaddy, Bokpyin, and the Thai-Myanmar border.

CRITICAL LANGUAGE RULES:
- ALWAYS respond entirely in Myanmar (Burmese) script by default
- If user writes in English, lead with Myanmar script THEN add English summary at the end
- Write COMPLETE sentences — never cut off mid-sentence under any circumstances
- Do NOT truncate — always finish every thought fully
- Use proper Myanmar Unicode (U+1000–U+109F range)
- Separate paragraphs with a blank line for readability in chat bubbles

RESPONSE STRUCTURE (follow every time):
1. Opening acknowledgment — 1-2 warm sentences acknowledging the question
2. Main answer — bullet points using • symbol, one point per line
3. Warning signs where relevant — use 🚩 prefix
4. One concrete actionable tip — use 💡 prefix
5. Emergency numbers for serious topics: 🇲🇲 199 | 🇹🇭 191 | 🇹🇭 1300

EXPERT KNOWLEDGE:

SCAM COMPOUNDS & CHINESE SYNDICATES:
- KK Park (Myawaddy): Built 2020, linked to Wan Kuok Koi "Broken Tooth" via Huanya Project; Karen BGF (Chit Thu, Tin Win) provides protection to Chinese crime groups
- Other compounds: Shwe Kokko, Jinxin, Hengsheng, Dongfanghui — all Myanmar-China border scam hubs
- 杀猪盘 (Shā zhū pán) = "Pig Butchering" — core Chinese syndicate method; $75B stolen globally 2020-2024
- 2024: $10 billion from Americans alone (66% increase year-over-year)
- 2025: AI deepfakes, voice cloning, fake trading apps deployed at industrial scale in compounds
- Oct 2025: Myanmar military raided KK Park, arrested 2,000+, seized 30 Starlink terminals
- Compounds adapt fast — workers dispersed to 30+ other sites after the raid

KYAR PHAN (ကျားဖြန်) — HUMAN TRAFFICKING:
- Victims: job-seekers, military conscription evaders, economic migrants
- Recruitment: Telegram/Facebook fake jobs — data entry, customer service, 50,000+ THB/month
- Process: Normal treatment until Myanmar border → passport confiscated → forced to scam
- Conditions: 16-18 hour shifts, beatings for missing targets, sold between compounds
- Scale: 100,000+ estimated trapped across Myanmar; 137+ scam sites identified
- Rescue lines: Myanmar Police 199, Thailand Anti-Trafficking 1300 (24hr), IOM +95-1-230-1854

SCAM TYPES IN DETAIL:
1. Pig Butchering: Stranger contact → weeks/months of relationship building → fake crypto platform → fake profits shown → withdrawal blocked by tax/fee demands → total loss
2. Love/Romance: Fake profile (military/doctor photos) → video call avoidance → money requests for "emergencies"
3. Job Scam: Fake high-salary jobs → processing fees OR direct trafficking into compounds
4. Phone/OTP: Bank/police impersonation → fear tactics → OTP/PIN theft → account drained
5. Crypto Investment: "Guaranteed returns" (impossible in real markets) → fake trading platform → exit scam
6. Deepfake (2025): AI face/voice clone of family member or boss → urgent money transfer
7. Money Mule: Recruit Myanmar migrants to transfer scam proceeds → illegal, prosecutable
8. Parcel Scam: Fake customs fee via phishing link → banking credentials stolen

WARNING SIGNS (always emphasize these):
🚩 Job offering >50,000 THB/month for simple work in Myanmar border area = almost certainly trafficking
🚩 Online romantic interest who avoids all video calls = almost certainly fake profile
🚩 "Guaranteed profit" investment = always a scam, no legitimate investment guarantees returns
🚩 Urgent pressure to act TODAY without time to verify = manipulation tactic
🚩 OTP/PIN requested via phone = banks and police NEVER do this legitimately
🚩 Any crypto/investment platform introduced by someone you only know online = scam

PRACTICAL ADVICE:
- Verify any job: Google the company name + "scam" | check if official website actually exists
- Reverse image search ALL profile photos using Google Images or TinEye
- Check investment platforms: SEC Thailand or MAS Singapore registration database
- If scammed: call bank immediately (first 24 hours is critical), save ALL evidence (screenshots, transaction records, chat logs)
- Never be ashamed — these are sophisticated professional criminals; doctors, engineers, and educated people get scammed too

TONE: Warm, caring, like a knowledgeable older sibling. Urgent when needed but never alarming or scary. Never judgmental toward victims.`;

// ── Rate limiter (in-memory, resets on cold start)
const rateLimitMap = new Map();
function checkRateLimit(ip) {
  const now = Date.now(), win = 60000, max = 30;
  const e = rateLimitMap.get(ip);
  if (!e || now > e.resetAt) { rateLimitMap.set(ip, { count: 1, resetAt: now + win }); return true; }
  if (e.count >= max) return false;
  e.count++;
  return true;
}

// ── Supabase logger
async function logToSupabase(url, key, data) {
  if (!url || !key) return;
  try {
    await fetch(`${url}/rest/v1/chat_logs`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'apikey': key,
        'Authorization': `Bearer ${key}`,
        'Prefer': 'return=minimal'
      },
      body: JSON.stringify(data)
    });
  } catch (e) {
    console.error('Supabase log error:', e.message);
  }
}

// ── Convert OpenAI-style messages → Gemini contents format
// Gemini uses role "user" / "model" (not "assistant")
// Gemini does not accept a system message inside contents —
// it goes in systemInstruction separately
function toGeminiContents(messages) {
  return messages.map(m => ({
    role: m.role === 'assistant' ? 'model' : 'user',
    parts: [{ text: m.content }]
  }));
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

  // Rate limit
  const clientIP = (event.headers['x-forwarded-for'] || 'unknown').split(',')[0].trim();
  if (!checkRateLimit(clientIP)) {
    return { statusCode: 429, headers, body: JSON.stringify({ error: 'Too many requests. Please wait a minute before trying again.' }) };
  }

  // API key check
  const geminiKey = process.env.GEMINI_API_KEY;
  if (!geminiKey) {
    return {
      statusCode: 500, headers,
      body: JSON.stringify({ error: 'GEMINI_API_KEY not configured. Add it to Netlify environment variables.' })
    };
  }

  // Parse body
  let body;
  try { body = JSON.parse(event.body); } catch {
    return { statusCode: 400, headers, body: JSON.stringify({ error: 'Invalid JSON body' }) };
  }

  const { messages, sessionId } = body;
  if (!messages || !Array.isArray(messages) || messages.length === 0) {
    return { statusCode: 400, headers, body: JSON.stringify({ error: 'messages array is required' }) };
  }
  if (messages.length > 50) {
    return { statusCode: 400, headers, body: JSON.stringify({ error: 'Too many messages in history (max 50)' }) };
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_ANON_KEY;
  const ipHash = Buffer.from(clientIP).toString('base64').slice(0, 16);
  const userMessage = messages[messages.length - 1]?.content || '';

  // Log user message
  await logToSupabase(supabaseUrl, supabaseKey, {
    session_id: sessionId || 'anon',
    role: 'user',
    message: userMessage.slice(0, 2000),
    ip_hash: ipHash,
    created_at: new Date().toISOString()
  });

  // ── Gemini API call
  // Model: gemini-1.5-pro (best quality, free tier: 2 RPM, 50 RPD on free; paid: 1000 RPM)
  // Alternative: gemini-2.0-flash (faster, higher free limits: 15 RPM, 1500 RPD)
  const model = process.env.GEMINI_MODEL || 'gemini-2.0-flash';
  const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${geminiKey}`;

  const geminiPayload = {
    systemInstruction: {
      parts: [{ text: SYSTEM_PROMPT }]
    },
    contents: toGeminiContents(messages.slice(-20)),
    generationConfig: {
      maxOutputTokens: 2048,
      temperature: 0.7,
      topP: 0.9,
      topK: 40
    },
    safetySettings: [
      { category: 'HARM_CATEGORY_HARASSMENT',        threshold: 'BLOCK_ONLY_HIGH' },
      { category: 'HARM_CATEGORY_HATE_SPEECH',       threshold: 'BLOCK_ONLY_HIGH' },
      { category: 'HARM_CATEGORY_SEXUALLY_EXPLICIT', threshold: 'BLOCK_ONLY_HIGH' },
      { category: 'HARM_CATEGORY_DANGEROUS_CONTENT', threshold: 'BLOCK_ONLY_HIGH' }
    ]
  };

  try {
    const response = await fetch(geminiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(geminiPayload)
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      const errMsg = errData?.error?.message || 'HTTP ' + response.status;
      console.error('Gemini API error:', response.status, errMsg);

      // Handle specific Gemini error codes clearly
      if (response.status === 429) {
        return { statusCode: 429, headers, body: JSON.stringify({ error: 'AI rate limit reached. Please wait a moment and try again.' }) };
      }
      if (response.status === 400) {
        return { statusCode: 400, headers, body: JSON.stringify({ error: 'Request error: ' + errMsg }) };
      }
      return { statusCode: response.status, headers, body: JSON.stringify({ error: 'AI service error: ' + errMsg }) };
    }

    const data = await response.json();

    // Gemini response structure: data.candidates[0].content.parts[0].text
    const candidate = data.candidates?.[0];

    // Check for safety block or empty response
    if (!candidate || candidate.finishReason === 'SAFETY') {
      console.warn('Gemini blocked response:', candidate?.finishReason);
      const fallback = 'ဆောင်ရွက်မရပါ — မေးခွန်းကို နည်းနည်းပြောင်းပြီး ထပ်မံကြိုးစားပါ။\n(Unable to respond. Please rephrase and try again.)';
      await logToSupabase(supabaseUrl, supabaseKey, { session_id: sessionId || 'anon', role: 'error', message: 'SAFETY_BLOCK: ' + (candidate?.finishReason || 'empty'), ip_hash: ipHash, created_at: new Date().toISOString() });
      return { statusCode: 200, headers, body: JSON.stringify({ reply: fallback }) };
    }

    const reply = candidate.content?.parts?.map(p => p.text || '').join('') || '';

    if (!reply.trim()) {
      return { statusCode: 200, headers, body: JSON.stringify({ reply: 'တုံ့ပြန်မှု မရရှိပါ — ထပ်မံ ကြိုးစားပါ။\n(No response received — please try again.)' }) };
    }

    // Log AI reply
    await logToSupabase(supabaseUrl, supabaseKey, {
      session_id: sessionId || 'anon',
      role: 'assistant',
      message: reply.slice(0, 2000),
      ip_hash: ipHash,
      created_at: new Date().toISOString()
    });

    // Return reply + token usage info if available
    const usage = data.usageMetadata || null;
    return { statusCode: 200, headers, body: JSON.stringify({ reply, usage, model }) };

  } catch (err) {
    console.error('Function error:', err);
    await logToSupabase(supabaseUrl, supabaseKey, {
      session_id: sessionId || 'anon',
      role: 'error',
      message: err.message,
      ip_hash: ipHash,
      created_at: new Date().toISOString()
    });
    return { statusCode: 500, headers, body: JSON.stringify({ error: 'Internal server error: ' + err.message }) };
  }
};
