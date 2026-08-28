// Vercel serverless ΓÇö GET /api/dashboard?scope=<page>
// - Lazy-import genlayer-js (cold-start aman: import di dalam handler).
// - Hard deadline ~15s: fungsi SELALU balas cepat (data parsial + __error),
//   tidak pernah kena FUNCTION_INVOCATION_TIMEOUT.
// - Read dibatasi per-call; hasil di-cache 40s per instance.
import { parse as parseUrl } from "node:url";

const LIVE_CONTRACTS = {
  honeypot: "0xde2CEE8354a747037403D8f8E4854AA8f5F23d40",
  analyzer: "0xC8d9D831005401d8b5B19c73f2De1657607C4baC",
  auditor: "0x44b8748b54b40b1cce572Cff046864ed6C5e8046",
  lab: "0xd72cccA524f49F348C247E45afFf1406D86c3EFe",
  hardened: "0xe8f6349F3AbE79523Ff50AA4B55E8c55CE86fDCB",
};
const RPC_ENDPOINT = process.env.RPC_URL || "https://studio.genlayer.com/api";

const SCOPES = {
  monitor: ["honeypot", "attempts", "analyzer", "reports", "hardened"],
  research: ["analyzer", "reports"],
  audit: ["auditor", "audits", "vectors"],
  lab: ["lab", "lab_vaults", "auditor", "tests", "vectors"],
};
const CACHE_TTL = 40000;
const cache = new Map();
function cacheGet(k) { const e = cache.get(k); return (e && Date.now() - e.t < CACHE_TTL) ? e.v : null; }
function cacheSet(k, v) { if (cache.size > 40) cache.clear(); cache.set(k, { v, t: Date.now() }); }

const READ_MS = 6000;
function bound(fn, fallback) {
  return Promise.race([
    Promise.resolve().then(fn),
    new Promise((r) => setTimeout(() => r(fallback), READ_MS)),
  ]);
}
const parseS = (x) => { try { return JSON.parse(x); } catch { return []; } };
function normalize(o) {
  if (typeof o === "bigint") return Number(o);
  if (Array.isArray(o)) return o.map(normalize);
  if (o && typeof o === "object") { const r = {}; for (const [k, v] of Object.entries(o)) r[k] = normalize(v); return r; }
  return o;
}
function json(d, s = 200) {
  return new Response(JSON.stringify(d), { status: s, headers: { "Content-Type": "application/json" } });
}
const withDeadline = (p, ms, fb) => Promise.race([p, new Promise((r) => setTimeout(() => r(fb), ms))]);

export default async function handler(req) {
  const params = Object.fromEntries(new URL(req.url, "http://x").searchParams);
  const scope = (params.scope || "monitor").toLowerCase();
  const want = SCOPES[scope] || SCOPES.monitor;
  const wn = (k) => want.includes(k);
  const cacheKey = scope;
  const cached = cacheGet(cacheKey);
  if (cached) return json({ ...cached, cached: true, fetchedAt: new Date().toISOString() });

  const base = { network: "studionet", scope, addresses: LIVE_CONTRACTS };

  // Lazy import + deadline: walaupun cold-start genlayer-js lambat, kita balas Γëñ ~15s
  const init = await withDeadline(
    (async () => {
      const m = await import("genlayer-js");
      const chains = await import("genlayer-js/chains");
      const client = m.createClient({ chain: chains.studionet, endpoint: RPC_ENDPOINT });
      return { client };
    })(),
    12000,
    null
  );
  if (!init || !init.client) {
    return json({ ...base, __error: `genlayer-js init failed/timed out (endpoint ${RPC_ENDPOINT})` });
  }
  const { client } = init;

  const read = (address, fn, args = []) =>
    bound(client.readContract({ address, functionName: fn, args }), null);

  const jobs = [];
  if (wn("honeypot")) jobs.push(["honeypot", read(LIVE_CONTRACTS.honeypot, "get_vault_info")]);
  if (wn("attempts")) jobs.push(["attempts", read(LIVE_CONTRACTS.honeypot, "get_recent_attempts", [10])]);
  if (wn("analyzer")) jobs.push(["analyzer", read(LIVE_CONTRACTS.analyzer, "get_stats")]);
  if (wn("reports")) jobs.push(["reports", read(LIVE_CONTRACTS.analyzer, "get_recent_reports", [10])]);
  if (wn("hardened")) jobs.push(["hardened", read(LIVE_CONTRACTS.hardened, "get_vault_info")]);
  if (wn("auditor")) jobs.push(["auditor", read(LIVE_CONTRACTS.auditor, "get_stats")]);
  if (wn("audits")) jobs.push(["audits", read(LIVE_CONTRACTS.auditor, "get_recent_audits", [8])]);
  if (wn("tests")) jobs.push(["tests", read(LIVE_CONTRACTS.auditor, "get_recent_tests", [8])]);
  if (wn("vectors")) jobs.push(["vectors", read(LIVE_CONTRACTS.auditor, "get_attack_vectors")]);
  if (wn("lab")) jobs.push(["lab", read(LIVE_CONTRACTS.lab, "get_stats")]);
  if (wn("lab_vaults")) jobs.push(["lab_vaults", read(LIVE_CONTRACTS.lab, "get_recent_vaults", [8])]);

  const resolved = {};
  await Promise.all(jobs.map(async ([k, p]) => { resolved[k] = await p; }));

  const out = { ...base, fetchedAt: new Date().toISOString() };
  for (const k of Object.keys(resolved)) {
    const v = resolved[k];
    if (v == null) continue;
    if (k === "honeypot" || k === "analyzer" || k === "hardened" || k === "auditor" || k === "lab") {
      out[k === "lab" ? "attackLab" : k] = normalize(v);
    } else if (k === "attempts") out.attempts = parseS(v);
    else if (k === "reports") out.reports = parseS(v);
    else if (k === "audits") out.audits = parseS(v);
    else if (k === "tests") out.tests = parseS(v);
    else if (k === "vectors") out.vectors = parseS(v);
    else if (k === "lab_vaults") {
      const arr = parseS(v);
      out.lab_vaults = await withDeadline(
        Promise.all(arr.slice(0, 4).map(async (vv) => {
          try {
            const info = await read(vv.address, "get_info");
            let last = null;
            try { last = parseS(await read(vv.address, "get_latest_attempt")); } catch {}
            return { ...vv, info: normalize(info), last_attempt: normalize(last && last[0]) };
          } catch { return vv; }
        })),
        30000, arr
      );
    }
  }

  cacheSet(cacheKey, out);
  return json(out);
}
