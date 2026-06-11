// api/chat.js — Vercel adapter for netlify/functions/chat.js
const { handler } = require('../netlify/functions/chat');

module.exports = async (req, res) => {
  const event = {
    httpMethod: req.method,
    headers: req.headers,
    body: typeof req.body === 'string' ? req.body : JSON.stringify(req.body ?? {})
  };

  const result = await handler(event);

  Object.entries(result.headers || {}).forEach(([k, v]) => res.setHeader(k, v));
  res.status(result.statusCode).send(result.body);
};
