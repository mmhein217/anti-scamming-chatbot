// netlify/functions/chat.js
// ScamAware MM — Production Anti-Scam AI for Myanmar
// Architecture: PII Guard → Topic Guard → Supabase Cache → Local DB RAG → Gemini AI

// ── Scam Topics Cache (loaded from Supabase, refreshed every 10 min)
let _scamTopics = null;
let _scamTopicsAt = 0;
const TOPICS_TTL_MS = 10 * 60 * 1000;

async function loadScamTopics(supabaseUrl, supabaseKey) {
  const now = Date.now();
  if (_scamTopics && now - _scamTopicsAt < TOPICS_TTL_MS) return _scamTopics;
  try {
    const r = await fetch(
      `${supabaseUrl}/rest/v1/scam_topics?is_active=eq.true&select=topic_id,keywords,scam_name,mechanism,red_flags,prevention_guide,answer`,
      { headers: { 'apikey': supabaseKey, 'Authorization': `Bearer ${supabaseKey}` } }
    );
    if (!r.ok) return _scamTopics || [];
    _scamTopics = await r.json();
    _scamTopicsAt = now;
    return _scamTopics;
  } catch {
    return _scamTopics || [];
  }
}

function matchScamTopic(topics, text) {
  const lower = text.toLowerCase();
  let best = null, bestScore = 0;
  for (const topic of topics) {
    const kws = (topic.keywords || '').split(',').map(k => k.trim().toLowerCase()).filter(Boolean);
    const score = kws.filter(kw => lower.includes(kw)).length;
    if (score > bestScore) { bestScore = score; best = topic; }
  }
  return bestScore >= 1 ? { topic: best, score: bestScore } : null;
}

// ── System Prompt: ScamAware MM
const SYSTEM_PROMPT = `You are "ScamAware MM" (ScamGuard AI), a production-grade AI expert dedicated to educating the public and preventing online scams, mobile banking frauds (KPay/Wave Money), and cybercrimes in Myanmar. Your primary directive is to protect users by offering actionable, empathetic, and urgent advice.

CRITICAL LANGUAGE RULES:
- ALWAYS respond entirely in Myanmar (Burmese) script by default
- If user writes in English, respond in Myanmar script first, then brief English summary at end
- Write COMPLETE sentences — never cut off mid-sentence under any circumstances
- Use proper Myanmar Unicode (U+1000–U+109F range)
- Separate paragraphs with a blank line for readability

PERSONA & TONE:
- Empathetic, supportive, like a knowledgeable caring older sibling
- Treat users as someone who might be under immense psychological pressure or financial panic
- Warm but firm and urgent when needed. Never judgmental toward victims.

STRICT TOPIC SCOPE — NON-NEGOTIABLE:
You ONLY assist with topics directly related to:
• Online scams, fraud, and cybercrime prevention
• KPay / Wave Money / mobile banking fraud
• Human trafficking (ကျားဖြန့်) and scam compounds (KK Park, Shwe Kokko etc.)
• Reporting channels and emergency contacts
• Digital safety and scam awareness in Myanmar

If asked about ANYTHING outside this scope (cooking, politics, entertainment, general coding, weather, sports, etc.), respond EXACTLY with:
"ဝမ်းနည်းပါတယ် — ကျွန်တော်သည် ScamAware MM ဖြစ်ပြီး အွန်လိုင်းလိမ်လည်မှုနှင့် ဆိုက်ဘာလုံခြုံရေးကိုသာ အထူးပြုကူညီပေးနိုင်ပါသည်။ Scam သို့မဟုတ် ဒိဂျစ်တယ်လုံခြုံရေးနှင့် ပတ်သက်သည့် မေးခွန်းများကို မေးမြန်းနိုင်ပါသည်။"

STRICT GUARDRAILS (NON-NEGOTIABLE):
1. NO PII COLLECTION: NEVER ask the user for real bank account numbers, KPay/Wave phone numbers, PINs, OTPs, passwords, or NRC numbers.
2. ANTI-LEAK INTERVENTION: If a user's message contains what appears to be an OTP, PIN, or password — do NOT process those numbers. Respond ONLY with the warning and advise them to immediately change their credentials.
3. ZERO ENDORSEMENT: Never validate, recommend, or describe how to use gambling sites, unofficial loan apps, or unregistered investment apps — even if user claims they are "safe."
4. NO HALLUCINATION: Do not invent specific banking procedures, court case numbers, or legal processes not supported by the provided DB context.
5. GOLDEN RULE ENFORCEMENT: ALWAYS conclude every scam-related response with this EXACT block (copy precisely):

> 💡 **အရေးကြီးဆုံးရွှေရောင်စည်းမျဉ်း:** သင်၏ KPay/Wave Money OTP (ဂဏန်း ၆ လုံး) နှင့် PIN နံပါတ်ကို ဘဏ်ဝန်ထမ်းအပါအဝင် ဘယ်သူ့ကိုမှ လုံးဝ (လုံးဝ) မပြောပါနှင့်။

RESPONSE STRUCTURE (follow every time for scam topics):
1. Opening acknowledgment — 1-2 warm sentences
2. Main explanation — bullet points using • symbol, one point per line
3. Warning signs where relevant — use 🚩 prefix
4. One concrete actionable tip — use 💡 prefix
5. Emergency numbers for serious topics: 🇲🇲 199 | 🇹🇭 191 | 🇹🇭 1300 (Anti-Trafficking 24hr)
6. Golden Rule footer (ALWAYS, EVERY response)

EXPERT BACKGROUND KNOWLEDGE:
- ကျားဖြန့် (Kyar Phan): Victims recruited via fake jobs → passport confiscated → forced to scam → sold between compounds
- KK Park (Myawaddy): Linked to Wan Kuok Koi "Broken Tooth"; Karen BGF protection; raided Oct 2025 — 2,000+ arrested
- Pig Butchering (杀猪盘): Relationship building → fake crypto platform → withdrawal blocked → total loss. $75B stolen globally 2020-2024
- Scam types: Love/Romance, Job Scam, OTP theft, Task Scam, Ponzi Schemes, Deepfake (2025), Money Mule, Parcel Scam
- KPay/Wave: Banks and payment apps NEVER call to ask for OTP or PIN — ever
- Rescue lines: Myanmar Police 199, Thailand Anti-Trafficking 1300 (24hr), IOM +95-1-230-1854

RAG CONTEXT USAGE:
- When "[DB Context]" block appears below the user message, PRIORITIZE that structured data in your response
- Use the mechanism, red_flags, and prevention_guide fields to ground your answer
- Do not contradict the provided DB context`;

// ── Golden Rule constant
const GOLDEN_RULE = '\n\n> 💡 **အရေးကြီးဆုံးရွှေရောင်စည်းမျဉ်း:** သင်၏ KPay/Wave Money OTP (ဂဏန်း ၆ လုံး) နှင့် PIN နံပါတ်ကို ဘဏ်ဝန်ထမ်းအပါအဝင် ဘယ်သူ့ကိုမှ လုံးဝ (လုံးဝ) မပြောပါနှင့်။';

// ── PII Detection — detects if user is leaking sensitive credentials
function detectPII(text) {
  const lower = text.toLowerCase();
  const hasSensitiveKeyword = ['otp', 'pin', 'password', 'လျှို့ဝှက်', 'ဂဏန်း ၆', 'ဂဏန်းခြောက်'].some(k => lower.includes(k));
  const hasSixDigits = /\b\d{6}\b/.test(text);
  const hasPinDigits = /\bpin\b.*\d{4,}|\d{4,}.*\bpin\b/i.test(text);
  return (hasSensitiveKeyword && hasSixDigits) || hasPinDigits;
}


// ── Ensure Golden Rule appears in every AI reply
function ensureGoldenRule(reply) {
  if (reply.includes('ရွှေရောင်စည်းမျဉ်း')) return reply;
  return reply + GOLDEN_RULE;
}

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

// ── Monthly cost limit helpers
// Groq is free tier — cost tracking kept for compatibility
function estimateCost() {
  return 0;
}

async function checkMonthlyLimit(supabaseUrl, supabaseKey) {
  const limit = parseFloat(process.env.MONTHLY_COST_LIMIT_USD || '2.0');
  const month = new Date().toISOString().slice(0, 7);
  try {
    const r = await fetch(
      `${supabaseUrl}/rest/v1/monthly_usage?month=eq.${month}&select=estimated_cost_usd`,
      { headers: { 'apikey': supabaseKey, 'Authorization': `Bearer ${supabaseKey}` } }
    );
    if (!r.ok) return true;
    const rows = await r.json();
    const cost = rows[0]?.estimated_cost_usd || 0;
    return parseFloat(cost) < limit;
  } catch {
    return true;
  }
}

async function incrementMonthlyUsage(supabaseUrl, supabaseKey, inputTokens, outputTokens) {
  const month = new Date().toISOString().slice(0, 7);
  const cost = estimateCost(inputTokens, outputTokens);
  fetch(`${supabaseUrl}/rest/v1/rpc/increment_monthly_usage`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'apikey': supabaseKey,
      'Authorization': `Bearer ${supabaseKey}`
    },
    body: JSON.stringify({ p_month: month, p_requests: 1, p_cost: cost })
  }).catch(() => {});
}

// ── Cached answers (Supabase) — in-memory store with 5-min TTL
let _cachedAnswers = null;
let _cachedAnswersAt = 0;
const CACHE_TTL_MS = 5 * 60 * 1000;

async function loadCachedAnswers(supabaseUrl, supabaseKey) {
  const now = Date.now();
  if (_cachedAnswers && now - _cachedAnswersAt < CACHE_TTL_MS) return _cachedAnswers;
  try {
    const r = await fetch(
      `${supabaseUrl}/rest/v1/cached_answers?select=id,question,keywords,answer&is_active=eq.true`,
      { headers: { 'apikey': supabaseKey, 'Authorization': `Bearer ${supabaseKey}` } }
    );
    if (!r.ok) return _cachedAnswers || [];
    _cachedAnswers = await r.json();
    _cachedAnswersAt = now;
    return _cachedAnswers;
  } catch {
    return _cachedAnswers || [];
  }
}

function matchCachedAnswer(answers, text) {
  const lower = text.toLowerCase();
  for (const a of answers) {
    const kws = (a.keywords || '').split(',').map(k => k.trim()).filter(Boolean);
    if (kws.some(kw => lower.includes(kw.toLowerCase()))) return a;
  }
  return null;
}

function incrementCacheHit(supabaseUrl, supabaseKey, id) {
  fetch(`${supabaseUrl}/rest/v1/rpc/increment_cache_hit`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'apikey': supabaseKey,
      'Authorization': `Bearer ${supabaseKey}`
    },
    body: JSON.stringify({ answer_id: id })
  }).catch(() => {});
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
  const groqKey = process.env.GROQ_API_KEY;
  if (!groqKey) {
    return {
      statusCode: 500, headers,
      body: JSON.stringify({ error: 'GROQ_API_KEY not configured. Add it to Vercel environment variables.' })
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

  // ── Run all Supabase reads in parallel (faster cold start)
  const [, underLimit, cachedList, scamTopicsData] = await Promise.all([
    logToSupabase(supabaseUrl, supabaseKey, {
      session_id: sessionId || 'anon', role: 'user',
      message: userMessage.slice(0, 2000), ip_hash: ipHash, created_at: new Date().toISOString()
    }),
    checkMonthlyLimit(supabaseUrl, supabaseKey),
    loadCachedAnswers(supabaseUrl, supabaseKey),
    loadScamTopics(supabaseUrl, supabaseKey)
  ]);

  // ── GUARD 1: Monthly cost limit
  if (!underLimit) {
    return {
      statusCode: 200, headers,
      body: JSON.stringify({
        reply: 'ဝမ်းနည်းပါတယ် — ဒီလအတွက် AI ဝန်ဆောင်မှု limit ရောက်နေပါပြီ။ နောက်လမှ ပြန်မေးနိုင်ပါတယ်။',
        cached: false
      })
    };
  }

  // ── GUARD 2: PII Detection — user leaking OTP/PIN
  if (detectPII(userMessage)) {
    const piiWarning = '⚠️ **[သတိပေးချက်]** သင်၏ OTP/PIN ကို ဤနေရာတွင် လုံးဝမရေးပါနှင့်။ ၎င်းတို့ကို မည်သူ့ကိုမျှ မပြောပါနှင့်။\n\nသင့်အကောင့် ဖောက်ထွင်းခံရမည် ကြောက်ပါက ချက်ချင်း KBZ Pay / Wave Money Customer Care ကို ဆက်သွယ်ပြီး အကောင့် ယာယီပိတ်ပစ်ပါ။\n\n🇲🇲 KBZ: 09-777-911-880 | Wave: 09-455-252-525';
    await logToSupabase(supabaseUrl, supabaseKey, {
      session_id: sessionId || 'anon', role: 'pii_block',
      message: 'PII detected — blocked', ip_hash: ipHash, created_at: new Date().toISOString()
    });
    return { statusCode: 200, headers, body: JSON.stringify({ reply: piiWarning, cached: true }) };
  }

  // ── GUARD 3: Supabase cached answers
  if (supabaseUrl && supabaseKey) {
    const hit = matchCachedAnswer(cachedList, userMessage);
    if (hit) {
      incrementCacheHit(supabaseUrl, supabaseKey, hit.id);
      await logToSupabase(supabaseUrl, supabaseKey, {
        session_id: sessionId || 'anon',
        role: 'cached',
        message: `[${hit.question}] ${hit.answer.slice(0, 1950)}`,
        ip_hash: ipHash,
        created_at: new Date().toISOString()
      });
      return { statusCode: 200, headers, body: JSON.stringify({ reply: hit.answer, cached: true }) };
    }
  }

  // ── RAG: DB match → build context for AI (not direct answer)
  const dbMatch = matchScamTopic(scamTopicsData, userMessage);
  let ragContext = '';
  let dbFallbackReply = '';

  if (dbMatch) {
    const t = dbMatch.topic;
    const flags = Array.isArray(t.red_flags) ? t.red_flags
      : (typeof t.red_flags === 'string' ? JSON.parse(t.red_flags || '[]') : []);

    const ctx = [];
    if (t.scam_name) ctx.push(`Scam အမျိုးအစား: ${t.scam_name}`);
    if (t.mechanism) ctx.push(`ဖြစ်ပွားပုံ: ${t.mechanism}`);
    if (flags.length) ctx.push(`သတိပေးနိမိတ်များ:\n${flags.map(f => `• ${f}`).join('\n')}`);
    if (t.prevention_guide) ctx.push(`ကာကွယ်နည်း: ${t.prevention_guide}`);
    if (t.answer) ctx.push(`အသေးစိတ်: ${t.answer}`);
    ragContext = ctx.join('\n\n');

    // DB fallback — only used if AI fails
    const fbLines = [];
    if (t.scam_name) fbLines.push(`**${t.scam_name}** နှင့်ပတ်သက်၍ သတိပြုရမည့်အချက်များ:`);
    if (t.mechanism) fbLines.push(`\n**ဖြစ်ပွားပုံ:**\n${t.mechanism}`);
    if (flags.length) fbLines.push(`\n**သတိပေးနိမိတ်များ:**\n${flags.map(f => `🚩 ${f}`).join('\n')}`);
    if (t.answer && !t.mechanism) fbLines.push(`\n${t.answer}`);
    if (t.prevention_guide) fbLines.push(`\n💡 **ကာကွယ်နည်း:**\n${t.prevention_guide}`);
    fbLines.push(GOLDEN_RULE);
    dbFallbackReply = fbLines.join('\n');
  }

  // ── Build message history (keep last 10 to reduce token usage)
  const historyMessages = messages.slice(-10);

  // ── Groq API call — primary fast model, fallback to smaller
  const MODELS = [
    process.env.GROQ_MODEL || 'llama-3.3-70b-versatile',
    'llama-3.1-8b-instant'
  ];

  const FALLBACK_REPLY = `သင်မေးသောမေးခွန်းကို လက်ခံရရှိပါသည်။ ယခုအချိန်တွင် AI ဝန်ဆောင်မှု ယာယီအနှောင့်အယှက်ရှိနေပါသည်။

Scam နှင့် ပတ်သက်သောအရေးပေါ်ကိစ္စများအတွက်:
• 🇲🇲 မြန်မာရဲ: **199**
• 🇹🇭 ထိုင်းရဲ: **191**
• 🇹🇭 လူကုန်ကူးမှုတိုင်ကြားရန်: **1300** (၂၄ နာရီ)
• IOM လူကုန်ကူးမှုကယ်ဆယ်ရေး: **+95-1-230-1854**

မိနစ်အနည်းငယ်ကြာပြီးနောက် ထပ်မံမေးမြန်းနိုင်ပါသည်။

> 💡 **အရေးကြီးဆုံးရွှေရောင်စည်းမျဉ်း:** သင်၏ KPay/Wave Money OTP (ဂဏန်း ၆ လုံး) နှင့် PIN နံပါတ်ကို ဘဏ်ဝန်ထမ်းအပါအဝင် ဘယ်သူ့ကိုမှ လုံးဝ (လုံးဝ) မပြောပါနှင့်။`;

  const systemContent = ragContext
    ? `${SYSTEM_PROMPT}\n\n--- သက်ဆိုင်ရာ ဒေတာဘေ့စ် အချက်အလက် ---\n${ragContext}\n--- အချက်အလက် ပြီး ---\nအထက်ပါ အချက်အလက်များကို အသုံးပြု၍ user ၏ မေးခွန်းကို သေချာစွာ ရှင်းပြပါ။`
    : SYSTEM_PROMPT;

  const groqMessages = [
    { role: 'system', content: systemContent },
    ...historyMessages
  ];

  const delay = ms => new Promise(r => setTimeout(r, ms));

  async function callGroq(model) {
    const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${groqKey}`
      },
      body: JSON.stringify({
        model,
        messages: groqMessages,
        max_tokens: 2048,
        temperature: 0.65,
        top_p: 0.9
      })
    });
    return { res, model };
  }

  try {
    let lastStatus = 0;
    let data = null;
    let usedModel = MODELS[0];

    for (let i = 0; i < MODELS.length; i++) {
      if (i > 0) await delay(1000);
      const { res, model } = await callGroq(MODELS[i]);
      usedModel = model;
      lastStatus = res.status;

      if (res.ok) {
        data = await res.json();
        break;
      }

      const errData = await res.json().catch(() => ({}));
      console.error(`Groq [${model}] HTTP ${res.status} — ${errData?.error?.message || 'no message'}`);

      if (res.status === 400) {
        return { statusCode: 200, headers, body: JSON.stringify({ reply: FALLBACK_REPLY, cached: true }) };
      }
    }

    if (!data) {
      console.error(`All Groq models failed. Tried: ${MODELS.join(', ')} — last HTTP: ${lastStatus}`);
      await logToSupabase(supabaseUrl, supabaseKey, {
        session_id: sessionId || 'anon', role: 'error',
        message: `Groq failed (${MODELS.join(',')}), status: ${lastStatus}`, ip_hash: ipHash, created_at: new Date().toISOString()
      });
      const fallback = dbFallbackReply || FALLBACK_REPLY;
      return { statusCode: 200, headers, body: JSON.stringify({ reply: fallback, cached: true, source: dbFallbackReply ? 'db_fallback' : 'static' }) };
    }

    let reply = data.choices?.[0]?.message?.content || '';
    if (!reply.trim()) {
      const fallback = dbFallbackReply || FALLBACK_REPLY;
      return { statusCode: 200, headers, body: JSON.stringify({ reply: fallback, cached: true, source: dbFallbackReply ? 'db_fallback' : 'static' }) };
    }

    reply = ensureGoldenRule(reply);

    await logToSupabase(supabaseUrl, supabaseKey, {
      session_id: sessionId || 'anon', role: 'assistant',
      message: reply.slice(0, 2000), ip_hash: ipHash, created_at: new Date().toISOString()
    });

    if (supabaseUrl && supabaseKey) {
      incrementMonthlyUsage();
    }

    return { statusCode: 200, headers, body: JSON.stringify({ reply, model: usedModel, rag_used: !!ragContext }) };

  } catch (err) {
    console.error('Function error:', err);
    return { statusCode: 200, headers, body: JSON.stringify({ reply: FALLBACK_REPLY, cached: true }) };
  }
};
