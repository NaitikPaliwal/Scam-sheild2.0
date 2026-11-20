const { verifyLink } = require('../../api/verify-link');

exports.handler = async (event) => {
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS'
  };

  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode: 200,
      headers: corsHeaders,
      body: ''
    };
  }

  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers: { 'Content-Type': 'application/json', ...corsHeaders },
      body: JSON.stringify({ error: 'Method Not Allowed. Send POST { "url": "..." }' })
    };
  }

  try {
    let body = {};
    if (event.body) {
      body = typeof event.body === 'string' ? JSON.parse(event.body) : event.body;
    }
    const result = await verifyLink(body.url);
    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json', ...corsHeaders },
      body: JSON.stringify(result)
    };
  } catch (err) {
    const status = err.status || 500;
    const errorMsg = err.message || 'An error occurred during link verification';
    return {
      statusCode: status,
      headers: { 'Content-Type': 'application/json', ...corsHeaders },
      body: JSON.stringify({ error: errorMsg })
    };
  }
};
