// Vercel serverless — GET /api/ping
// Zero-dependency check: apakah fungsi Vercel benar-benar berjalan.
export default function handler() {
  return new Response(
    JSON.stringify({ ok: true, node: process.version, ts: Date.now() }),
    { status: 200, headers: { "Content-Type": "application/json" } }
  );
}