// Vercel serverless — POST /api/genlayer-rpc
// Proxy: meneruskan POST JSON-RPC apa pun ke studio.genlayer.com/api,
// menyisipkan header CORS agar frontend browser juga bisa memakainya.
const TARGET = process.env.GENLAYER_RPC_TARGET || "https://studio.genlayer.com/api";

export async function POST(request) {
  let bodyText = "";
  try {
    bodyText = await request.text();
  } catch (e) {
    return json({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Bad request" } }, 400);
  }

  const t0 = Date.now();
  try {
    const ctrl = new AbortController();
    const to = setTimeout(() => ctrl.abort(), 60000);
    const up = await fetch(TARGET, {
      method: "POST",
      signal: ctrl.signal,
      headers: { "Content-Type": "application/json", "cache-control": "no-cache" },
      body: bodyText || "{}",
    });
    clearTimeout(to);
    const text = await up.text();
    return new Response(text, {
      status: up.status,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "X-Rpc-Ms": String(Date.now() - t0),
      },
    });
  } catch (e) {
    return json({ jsonrpc: "2.0", id: null, error: { code: -32603, message: String(e && e.message || e) } }, 502);
  }
}

export async function OPTIONS() {
  return new Response(null, { status: 204, headers: corsHeaders() });
}

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Cache-Control": "no-store",
  };
}

function json(d, s = 200) {
  return new Response(JSON.stringify(d), { status: s, headers: { "Content-Type": "application/json", ...corsHeaders() } });
}
