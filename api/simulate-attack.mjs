// Vercel serverless — POST /api/simulate-attack
// Fires a REAL on-chain attempt_unlock using an ephemeral gasless account.
import { createClient, createAccount } from "genlayer-js";
import { TransactionStatus } from "genlayer-js/types";
import { studionet } from "genlayer-js/chains";

const client = createClient({ chain: studionet });

const HONEYPOT = "0xde2CEE8354a747037403D8f8E4854AA8f5F23d40";

export default async function handler(req) {
  let body = {};
  try { body = await req.json(); } catch { /* ignore */ }
  const plea = String(body?.plea || "").trim();
  const honeypot = body?.honeypot || HONEYPOT;

  if (!plea) {
    return json({ ok: false, error: "plea is required" }, 400);
  }
  if (plea.length > 2000) {
    return json({ ok: false, error: `plea too long (${plea.length} > 2000)` }, 400);
  }

  const account = createAccount();

  try {
    const txHash = await client.writeContract({
      account,
      address: honeypot,
      functionName: "attempt_unlock",
      args: [plea],
    });

    let receipt = null;
    let waitError = null;
    try {
      receipt = await client.waitForTransactionReceipt({
        hash: txHash,
        status: TransactionStatus.ACCEPTED,
        interval: 2500,
        retries: 120, // ~5 min; Vercel maxDuration restericts final duration
      });
    } catch (e) {
      waitError = e;
    }

    if (!receipt && waitError) {
      return json({
        ok: true, pending: true, txHash,
        status: String(waitError?.message || waitError).slice(0, 220),
        verdict: null, attackerAddress: account.address,
      });
    }

    let verdict = null;
    try {
      const info = await client.readContract({ address: honeypot, functionName: "get_vault_info" });
      const total = Number(info.total_attempts);
      verdict = await client.readContract({ address: honeypot, functionName: "get_attempt", args: [total - 1] });
    } catch {}

    return json({
      ok: true, pending: false, txHash,
      status: receipt?.status_name || receipt?.status,
      verdict: normalize(verdict), attackerAddress: account.address,
    });
  } catch (e) {
    return json({ ok: false, error: String(e?.message || e).slice(0, 300) }, 500);
  }
}

function normalize(obj) {
  if (typeof obj === "bigint") return Number(obj);
  if (Array.isArray(obj)) return obj.map(normalize);
  if (obj && typeof obj === "object") {
    const out = {};
    for (const [k, v] of Object.entries(obj)) out[k] = normalize(v);
    return out;
  }
  return obj;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}