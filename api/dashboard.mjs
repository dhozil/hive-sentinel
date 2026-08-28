// Vercel serverless — GET /api/dashboard?scope=<page>
// Reads live chain state from HIVE SENTINEL contracts on StudioNet.
// Robust to slow StudioNet: each RPC read bounded (never hangs), plus a short
// in-memory cache so page refreshes are instant and 504 practically goes away.
import { createClient } from "genlayer-js";
import { studionet } from "genlayer-js/chains";

const client = createClient({ chain: studionet });

const LIVE_CONTRACTS = {
  honeypot: "0xde2CEE8354a747037403D8f8E4854AA8f5F23d40",
  analyzer: "0xC8d9D831005401d8b5B19c73f2De1657607C4baC",
  auditor: "0x44b8748b54b40b1cce572Cff046864ed6C5e8046",
  lab: "0xd72cccA524f49F348C247E45afFf1406D86c3EFe",
  hardened: "0xe8f6349F3AbE79523Ff50AA4B55E8c55CE86fDCB",
};

const SCOPES = {
  monitor: ["honeypot", "attempts", "analyzer", "reports", "hardened"],
  research: ["analyzer", "reports"],
  audit: ["auditor", "audits", "vectors"],
  lab: ["lab", "lab_vaults", "auditor", "tests", "vectors"],
};
const ALL = [...new Set(Object.values(SCOPES).flat())];

// ---- cache in-memory (per instance) supaya refresh cepat ----
const CACHE_TTL_MS = 20000;
const cache = new Map();
function cacheGet(key) {
  const e = cache.get(key);
  if (e && Date.now() - e.t < CACHE_TTL_MS) return e.v;
  return null;
}
function cacheSet(key, val) {
  if (cache.size > 40) cache.clear(); // jaga ukuran
  cache.set(key, { v: val, t: Date.now() });
}

// ---- bound call: selalu selesai dalam <80% budget, tidak menggantung ----
const READ_TIMEOUT_MS = 7000;
function bound(fn, fallback) {
  return Promise.race([
    Promise.resolve().then(fn),
    new Promise((resolve) => setTimeout(() => resolve(fallback), READ_TIMEOUT_MS)),
  ]);
}

async function readContract(address, fn, args = []) {
  return client.readContract({ address, functionName: fn, args });
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
async function safe(fn, fallback) {
  try { return await bound(fn, fallback); } catch (e) { return fallback; }
}
const parse = (s) => { try { return JSON.parse(s); } catch { return []; } };

export default async function handler(req) {
  const params = Object.fromEntries(new URL(req.url, "http://x").searchParams);
  const scope = (params.scope || "monitor").toLowerCase();
  const want = SCOPES[scope] ? SCOPES[scope] : (scope === "all" ? ALL : SCOPES.monitor);
  const wn = (k) => want.includes(k);

  const honeypot = params.honeypot || LIVE_CONTRACTS.honeypot;
  const analyzer = params.analyzer || LIVE_CONTRACTS.analyzer;
  const hardened = params.hardened || LIVE_CONTRACTS.hardened;
  const auditor = params.auditor || LIVE_CONTRACTS.auditor;
  const lab = params.lab || LIVE_CONTRACTS.lab;
  const cacheKey = `${scope}|${honeypot}|${analyzer}|${hardened}|${auditor}|${lab}`;

  const cached = cacheGet(cacheKey);
  if (cached) {
    return json({ ...cached, cached: true });
  }

  const emptyObj = {};
  const emptyArr = [];

  const jobs = [];
  if (wn("honeypot")) jobs.push(["honeypot", safe(() => readContract(honeypot, "get_vault_info"), emptyObj)]);
  if (wn("attempts")) jobs.push(["attempts", safe(() => readContract(honeypot, "get_recent_attempts", [10]), emptyArr)]);
  if (wn("analyzer")) jobs.push(["analyzer", safe(() => readContract(analyzer, "get_stats"), emptyObj)]);
  if (wn("reports")) jobs.push(["reports", safe(() => readContract(analyzer, "get_recent_reports", [10]), emptyArr)]);
  if (wn("hardened")) jobs.push(["hardened", safe(() => readContract(hardened, "get_vault_info"), emptyObj)]);
  if (wn("auditor")) jobs.push(["auditor", safe(() => readContract(auditor, "get_stats"), emptyObj)]);
  if (wn("audits")) jobs.push(["audits", safe(() => readContract(auditor, "get_recent_audits", [8]), emptyArr)]);
  if (wn("tests")) jobs.push(["tests", safe(() => readContract(auditor, "get_recent_tests", [8]), emptyArr)]);
  if (wn("vectors")) jobs.push(["vectors", safe(() => readContract(auditor, "get_attack_vectors"), emptyArr)]);
  if (wn("lab")) jobs.push(["lab", safe(() => readContract(lab, "get_stats"), emptyObj)]);
  if (wn("lab_vaults")) jobs.push(["lab_vaults_raw", safe(() => readContract(lab, "get_recent_vaults", [8]), emptyArr)]);

  const resolved = {};
  await Promise.all(jobs.map(async ([k, p]) => { resolved[k] = await p; }));

  let lab_vaults = parse(resolved["lab_vaults_raw"] || "[]");
  if (wn("lab_vaults") && Array.isArray(resolved["lab_vaults_raw"]) && resolved["lab_vaults_raw"].length) {
    lab_vaults = await Promise.all(lab_vaults.slice(0, 5).map(async (v) => {
      try {
        const info = await safe(() => readContract(v.address, "get_info"), null);
        let last = null;
        if (info) {
          last = await safe(() => readContract(v.address, "get_latest_attempt").then(x => JSON.parse(x || "{}")), null);
        }
        return { ...v, info: normalize(info), last_attempt: normalize(last) };
      } catch { return v; }
    }));
  }

  const out = {
    network: "studionet",
    scope,
    addresses: { honeypot, analyzer, hardened, auditor, lab },
    fetchedAt: new Date().toISOString(),
  };
  for (const k of ALL) {
    if (wn("lab_vaults") && k === "lab_vaults") { out.lab_vaults = normalize(lab_vaults); continue; }
    if (k in resolved) {
      if (k === "honeypot") out.honeypot = normalize(resolved[k]);
      else if (k === "analyzer") out.analyzer = normalize(resolved[k]);
      else if (k === "hardened") out.hardened = normalize(resolved[k]);
      else if (k === "auditor") out.auditor = normalize(resolved[k]);
      else if (k === "lab") out.attackLab = normalize(resolved[k]);
      else if (k === "attempts") out.attempts = parse(resolved[k]);
      else if (k === "reports") out.reports = parse(resolved[k]);
      else if (k === "audits") out.audits = parse(resolved[k]);
      else if (k === "tests") out.tests = parse(resolved[k]);
      else if (k === "vectors") out.vectors = parse(resolved[k]);
    }
  }

  cacheSet(cacheKey, out);
  return json(out);
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}