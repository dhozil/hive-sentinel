// Dashboard API server ΓÇö menjembatani genlayer-js (Node) ke UI statis.
// Jalankan: node server.mjs  lalu buka http://localhost:8080

import http from "node:http";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join, extname } from "node:path";
import { fileURLToPath } from "node:url";
import { createClient, createAccount } from "genlayer-js";
import { TransactionStatus } from "genlayer-js/types";
import { studionet } from "genlayer-js/chains";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 8080;

const client = createClient({ chain: studionet });

// Live deployed contracts on StudioNet ΓÇö REAL on-chain targets, not mock
// data. Override via query params: ?honeypot=0x..&analyzer=0x..&hardened=0x..
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

function jnum(v) {
  if (typeof v === "bigint") return Number(v);
  return v;
}

function normalize(obj) {
  // konversi bigint -> number rekursif agar aman di-JSON
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
  // No mock fallback: on failure we surface the raw error to the UI so
  // the dashboard never fabricates or substitutes data.
  try {
    return await fn();
  } catch (e) {
    return { __error: String(e?.message || e).slice(0, 200), ...(fallback || {}) };
  }
}

async function dashboard(params) {
  const scope = (url.searchParams.get("scope") || "monitor").toLowerCase();
  const SCOPES = {
    monitor: ["honeypot","attempts","analyzer","reports","hardened"],
    research: ["analyzer","reports"],
    audit: ["auditor","audits","vectors"],
    lab: ["lab","lab_vaults","auditor","tests","vectors"],
  };
  const want = SCOPES[scope] || SCOPES.monitor;
  const wn = (k) => want.includes(k);

  const honeypot = params.honeypot || LIVE_CONTRACTS.honeypot;
  const analyzer = params.analyzer || LIVE_CONTRACTS.analyzer;
  const hardened = params.hardened || LIVE_CONTRACTS.hardened;
  const auditor = params.auditor || LIVE_CONTRACTS.auditor;
  const lab = params.lab || LIVE_CONTRACTS.lab;

  const [hpInfo, hpAttempts, azStats, azReports, hzInfo, adStats, adAudits, adVectors, adTests, labStats, labVaults] = await Promise.all([
    wn("honeypot") ? safe(() => readContract(honeypot, "get_vault_info"), {}) : Promise.resolve({}),
    wn("attempts") ? safe(() => readContract(honeypot, "get_recent_attempts", [10]), []) : Promise.resolve([]),
    wn("analyzer") ? safe(() => readContract(analyzer, "get_stats"), {}) : Promise.resolve({}),
    wn("reports") ? safe(() => readContract(analyzer, "get_recent_reports", [10]), []) : Promise.resolve([]),
    wn("hardened") ? safe(() => readContract(hardened, "get_vault_info"), {}) : Promise.resolve({}),
    wn("auditor") ? safe(() => readContract(auditor, "get_stats"), {}) : Promise.resolve({}),
    wn("audits") ? safe(() => readContract(auditor, "get_recent_audits", [8]), []) : Promise.resolve([]),
    wn("vectors") ? safe(() => readContract(auditor, "get_attack_vectors"), []) : Promise.resolve([]),
    wn("tests") ? safe(() => readContract(auditor, "get_recent_tests", [8]), []) : Promise.resolve([]),
    wn("lab") ? safe(() => readContract(lab, "get_stats"), {}) : Promise.resolve({}),
    wn("lab_vaults") ? safe(() => readContract(lab, "get_recent_vaults", [8]), []) : Promise.resolve([]),
  ]);

  // parse attempt/report JSON strings
  let attempts = [];
  try {
    attempts = JSON.parse(hpAttempts);
  } catch {}

  let reports = [];
  try {
    reports = JSON.parse(azReports);
  } catch {}

  let audits = [];
  try {
    audits = JSON.parse(adAudits);
  } catch {}

  let vectors = [];
  try {
    vectors = JSON.parse(adVectors);
  } catch {}

  let tests = [];
  try {
    tests = JSON.parse(adTests);
  } catch {}

  let lab_vaults = [];
  try {
    const parsed = JSON.parse(labVaults);
    // enrich each vault with live on-chain state (info + latest verdict)
    lab_vaults = await Promise.all((parsed.slice(0, 8)).map(async (v) => {
      try {
        const info = await readContract(v.address, "get_info");
        let last = null;
        try {
          const raw = await readContract(v.address, "get_latest_attempt");
          last = JSON.parse(raw || "{}");
        } catch {}
        return { ...v, info: normalize(info), last_attempt: normalize(last) };
      } catch {
        return v;
      }
    }));
  } catch {}

  return normalize({
    network: "studionet",
    addresses: { honeypot, analyzer, hardened, auditor, lab },
    honeypot: hpInfo,
    hardened: hzInfo,
    analyzer: azStats,
    auditor: adStats,
    attackLab: labStats,
    attempts,
    reports,
    audits,
    tests,
    lab_vaults,
    vectors,
    fetchedAt: new Date().toISOString(),
  });
}

async function simulateAttack(body) {
  const plea = String(body?.plea || "").trim();
  if (!plea) {
    return { ok: false, error: "plea is required" };
  }
  if (plea.length > 2000) {
    return { ok: false, error: `plea too long (${plea.length} > 2000)` };
  }

  const honeypot = body?.honeypot || LIVE_CONTRACTS.honeypot;

  // Ephemeral gasless account per attack ΓÇö the attacker address shown
  // on-chain is unique per simulation. No wallet, no owner key involved.
  const account = createAccount();

  const txHash = await client.writeContract({
    account,
    address: honeypot,
    functionName: "attempt_unlock",
    args: [plea],
  });

  // Consensus on StudioNet can be slow ΓÇö give validators plenty of time.
  let receipt = null;
  let waitError = null;
  try {
    receipt = await client.waitForTransactionReceipt({
      hash: txHash,
      status: TransactionStatus.ACCEPTED,
      interval: 2500,
      retries: 120, // ~5 minutes before giving up
    });
  } catch (e) {
    waitError = e;
  }

  // If the tx exists but consensus isn't decided yet, be honest: report it
  // as PENDING instead of a hard FAILED ΓÇö the verdict may still land.
  if (!receipt && waitError) {
    return normalize({
      ok: true,
      pending: true,
      txHash,
      status: String(waitError?.message || waitError).slice(0, 220),
      verdict: null,
      attackerAddress: account.address,
    });
  }

  // Consensus outcome lives in result_name (e.g. MAJORITY_AGREE);
  // execution success is then verified by reading the verdict back.
  const succeeded =
    receipt?.result_name === "MAJORITY_AGREE" ||
    receipt?.status_name === "ACCEPTED" ||
    receipt?.status_name === "FINALIZED";

  // Read back the guard's verdict for the freshest attempt.
  let verdict = null;
  if (succeeded) {
    try {
      const info = await readContract(honeypot, "get_vault_info");
      const total = Number(info.total_attempts);
      const record = await readContract(honeypot, "get_attempt", [total - 1]);
      verdict = normalize(record);
    } catch {
      verdict = null;
    }
  }

  return normalize({
    ok: succeeded,
    txHash,
    status: receipt?.status_name || receipt?.status,
    execution: receipt?.txExecutionResultName,
    verdict,
    attackerAddress: account.address,
  });
}

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript",
  ".css": "text/css",
  ".json": "application/json",
  ".svg": "image/svg+xml",
};

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  if (url.pathname === "/api/dashboard") {
    const data = await dashboard(url.searchParams);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(data));
    return;
  }

  if (url.pathname === "/api/simulate-attack" && req.method === "POST") {
    let body = "";
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > 10_000) req.destroy();
      else body += c;
    });
    req.on("end", async () => {
      try {
        const parsed = JSON.parse(body || "{}");
        const result = await simulateAttack(parsed);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(result));
      } catch (e) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: false, error: String(e?.message || e).slice(0, 300) }));
      }
    });
    return;
  }

  // static files
  let filePath = join(__dirname, url.pathname === "/" ? "index.html" : url.pathname);
  if (!filePath.startsWith(__dirname)) {
    res.writeHead(403).end("Forbidden");
    return;
  }
  if (existsSync(filePath) && extname(filePath)) {
    res.writeHead(200, { "Content-Type": MIME[extname(filePath)] || "application/octet-stream" });
    res.end(readFileSync(filePath));
    return;
  }
  res.writeHead(404).end("Not found");
});

server.on("error", (err) => {
  if (err.code === "EADDRINUSE") {
    console.error(`\nΓ¥î Port ${PORT} is already in use.`);
    console.error("   Another HIVE SENTINEL server is probably running.");
    console.error("   Fix it with one of:");
    console.error(`   - Run from the frontend folder:  npx kill-port ${PORT}`);
    console.error(`   - Or:   netstat -ano | findstr :${PORT}   then:  taskkill /PID <pid> /F`);
    console.error(`   - Or start on another port:  $env:PORT=8081 ; npm run dev`);
    process.exit(1);
  }
  throw err;
});

server.listen(PORT, () => {
  console.log(`ΓÜí HIVE SENTINEL dashboard: http://localhost:${PORT}`);
});
