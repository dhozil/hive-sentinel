// Vercel serverless — GET /api/dashboard
// Reads live chain state from all 5 HIVE SENTINEL contracts on StudioNet.
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

async function readContract(address, functionName, args = []) {
  return client.readContract({ address, functionName, args });
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
  try {
    return await fn();
  } catch (e) {
    return { __error: String(e?.message || e).slice(0, 200), ...(fallback || {}) };
  }
}

export default async function handler(req) {
  const params = Object.fromEntries(new URL(req.url, "http://x").searchParams);
  const honeypot = params.honeypot || LIVE_CONTRACTS.honeypot;
  const analyzer = params.analyzer || LIVE_CONTRACTS.analyzer;
  const hardened = params.hardened || LIVE_CONTRACTS.hardened;
  const auditor = params.auditor || LIVE_CONTRACTS.auditor;
  const lab = params.lab || LIVE_CONTRACTS.lab;

  const [
    hpInfo, hpAttempts, azStats, azReports, hzInfo,
    adStats, adAudits, adVectors, adTests, labStats, labVaults,
  ] = await Promise.all([
    safe(() => readContract(honeypot, "get_vault_info"), {}),
    safe(() => readContract(honeypot, "get_recent_attempts", [10]), []),
    safe(() => readContract(analyzer, "get_stats"), {}),
    safe(() => readContract(analyzer, "get_recent_reports", [10]), []),
    safe(() => readContract(hardened, "get_vault_info"), {}),
    safe(() => readContract(auditor, "get_stats"), {}),
    safe(() => readContract(auditor, "get_recent_audits", [8]), []),
    safe(() => readContract(auditor, "get_attack_vectors"), []),
    safe(() => readContract(auditor, "get_recent_tests", [8]), []),
    safe(() => readContract(lab, "get_stats"), {}),
    safe(() => readContract(lab, "get_recent_vaults", [8]), []),
  ]);

  const parse = (s) => { try { return JSON.parse(s); } catch { return []; } };

  let labVaultsEnriched = parse(labVaults);
  try {
    labVaultsEnriched = await Promise.all(labVaultsEnriched.slice(0, 8).map(async (v) => {
      try {
        const info = await readContract(v.address, "get_info");
        let last = null;
        try { last = JSON.parse(await readContract(v.address, "get_latest_attempt") || "{}"); } catch {}
        return { ...v, info: normalize(info), last_attempt: normalize(last) };
      } catch { return v; }
    }));
  } catch {}

  const data = {
    network: "studionet",
    addresses: { honeypot, analyzer, hardened, auditor, lab },
    honeypot: normalize(hpInfo),
    hardened: normalize(hzInfo),
    analyzer: normalize(azStats),
    auditor: normalize(adStats),
    attackLab: normalize(labStats),
    attempts: parse(hpAttempts),
    reports: parse(azReports),
    audits: parse(adAudits),
    tests: parse(adTests),
    lab_vaults: normalize(labVaultsEnriched),
    vectors: parse(adVectors),
    fetchedAt: new Date().toISOString(),
  };

  return new Response(JSON.stringify(data), {
    status: 200,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}