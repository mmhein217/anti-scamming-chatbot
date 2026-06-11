// api/admin.js — Vercel adapter for netlify/functions/admin.js
const { handler } = require('../netlify/functions/admin');

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
