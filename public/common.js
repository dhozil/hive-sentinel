// HIVE SENTINEL — shared runtime (loaded by every page)
let autoTimer = null;
let liveAddresses = { honeypot: null, analyzer: null, auditor: null, lab: null, hardened: null };
let walletState = { address: null, writeClient: null, analyzer: null, auditor: null, lab: null };
let discoveredWallets = [];

// ---- EIP-6963 multi-wallet discovery ----
window.addEventListener("eip6963:announceProvider", (e) => {
  const d = e.detail;
  if (d && d.info && d.provider && !discoveredWallets.some(w => w.info.uuid === d.info.uuid)) {
    discoveredWallets.push(d);
  }
});
window.dispatchEvent(new Event("eip6963:requestProvider"));

const STUDIONET_CHAIN_ID = "0xf22f";
const STUDIONET_RPC = "https://studio.genlayer.com/api";

const el = (id) => document.getElementById(id);
const QUERY = () => new URLSearchParams(location.search);

// SDK di-pre-cache sejak halaman dimuat (hindari hang saat import CDN)
let sdkPromise = null;
function loadSdk() {
  if (!sdkPromise) {
    sdkPromise = Promise.all([
      import("https://esm.sh/genlayer-js@1.1.8"),
      import("https://esm.sh/genlayer-js@1.1.8/chains"),
    ]);
  }
  return sdkPromise;
}

function withTimeout(promise, ms, label) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error(label)), ms)),
  ]);
}

// ---- shared helpers ----
function num(v, d) { return (v === undefined || v === null) ? (d ?? "-") : v; }
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}
function sevBadge(sev) {
  const s = Number(sev) || 0;
  const cls = s >= 7 ? "sev-high" : s >= 4 ? "sev-med" : "sev-low";
  const icon = s >= 7 ? "🔴 " : s >= 4 ? "🟠 " : "🟢 ";
  return `<span class="badge ${cls}">${icon}${s}/10</span>`;
}
function riskBadge(risk) {
  const map = {
    low: ["sev-low", "🟢 low"],
    medium: ["sev-med", "🟠 medium"],
    high: ["sev-high", "🔴 high"],
    critical: ["sev-high", "☠️ critical"],
  };
  const m = map[risk] || ["sev-med", escapeHtml(risk || "-")];
  return `<span class="badge ${m[0]}">${m[1]}</span>`;
}
function srcBadge(src) {
  if (!src) return "-";
  return src === "honeypot_verified"
    ? '<span class="badge verified">✔ honeypot_verified</span>'
    : '<span class="badge unverified">⚠ community_unverified</span>';
}
function footBadge(enrichment) {
  const fp = enrichment && enrichment.footprint;
  if (!fp) return "-";
  const icon = fp === "empty" ? "👻" : fp === "low_activity" ? "🐍" : "🏛️";
  return `<span class="badge ${fp}-footprint">${icon} ${fp}</span>`;
}

// ---- nav ----
function setActiveNav(name) {
  document.querySelectorAll(".nav a[data-page]").forEach(a => {
    a.classList.toggle("active", a.dataset.page === name);
  });
}

// ---- dashboard fetch ----
async function fetchDashboard() {
  const res = await fetch(`/api/dashboard?${QUERY().toString()}`);
  return res.json();
}

// ---- chain error banner ----
function updateChainErrors(d) {
  const errs = [d.honeypot?.__error, d.analyzer?.__error, d.hardened?.__error, d.auditor?.__error, d.attackLab?.__error].filter(Boolean);
  const banner = el("chain-error");
  if (!banner) return;
  if (errs.length) {
    banner.style.display = "flex";
    el("chain-error-text").textContent = "RPC READ FAILED — LIVE DATA UNAVAILABLE: " + errs.join(" | ");
  } else {
    banner.style.display = "none";
  }
}

// ---- auto-refresh ----
function toggleAuto(millis = 15000) {
  const btn = el("auto-btn");
  if (!btn) return;
  if (autoTimer) { clearInterval(autoTimer); autoTimer = null; btn.textContent = "OFF"; btn.classList.remove("active"); }
  else { autoTimer = setInterval(loadAll, millis); btn.textContent = "ON"; btn.classList.add("active"); loadAll(); }
}

// ---- wallet modal ----
function _closeWalletModal() { el("wallet-modal").style.display = "none"; }
function _render_wallet_chooser(onPick) {
  const list = el("wallet-list");
  list.innerHTML = "";
  discoveredWallets.forEach(w => {
    const b = document.createElement("button");
    b.className = "preset";
    const img = w.info.icon ? `<img src="${w.info.icon}" width="18" height="18" style="vertical-align:-4px;margin-right:7px;border-radius:4px">` : "👛 ";
    b.innerHTML = `${img}${w.info.name}`;
    b.onclick = () => { _closeWalletModal(); onPick(w); };
    list.appendChild(b);
  });
  if (discoveredWallets.length) {
    const fb = document.createElement("button");
    fb.className = "preset";
    fb.textContent = "Browser default (window.ethereum)";
    fb.onclick = () => { _closeWalletModal(); onPick(null); };
    list.appendChild(fb);
  }
  el("wallet-modal").style.display = "flex";
}

function _openWalletModalContent(innerHtml) {
  const list = el("wallet-list");
  list.innerHTML = innerHtml;
  el("wallet-modal").style.display = "flex";
}

async function _ensure_studionet(provider) {
  try {
    await provider.request({ method: "wallet_switchEthereumChain", params: [{ chainId: STUDIONET_CHAIN_ID }] });
  } catch (err) {
    const code = err?.code ?? err?.data?.originalError?.code;
    if (code === 4902 || !err?.code || String(err?.message).includes("not")) {
      await provider.request({
        method: "wallet_addEthereumChain",
        params: [{ chainId: STUDIONET_CHAIN_ID, chainName: "GenLayer StudioNet",
                   nativeCurrency: { name: "GEN Token", symbol: "GEN", decimals: 18 },
                   rpcUrls: [STUDIONET_RPC] }],
      });
    } else {
      throw err;
    }
  }
}

// ---- session persistence: keep wallet across page navigation ----
const SESSION_KEY = "hs_wallet_session";

function persistWallet(snap) {
  try { sessionStorage.setItem(SESSION_KEY, JSON.stringify(snap)); } catch (e) {}
}
function clearWalletSession() {
  try { sessionStorage.removeItem(SESSION_KEY); } catch (e) {}
}

async function _do_connect(detail) {
  const btn = el("wallet-btn");
  const walletName = detail ? detail.info.name : "EVM Wallet";
  btn.disabled = true;
  try {
    btn.textContent = "⏳ LOADING SDK…";
    const sdkLoad = await withTimeout(loadSdk(), 20000, "SDK load timed out — cek koneksi internet / CDN.");
    const sdk = sdkLoad[0];

    // loading baru dipasang TEPAT sebelum popup, bukan sejak awal
    btn.textContent = `⏳ AWAITING ${walletName.toUpperCase()} POPUP…`;

    // SELALU pakai provider dari EIP-6963 bila dipilih — bukan window.ethereum
    const provider = detail ? detail.provider : window.ethereum;
    if (!provider) throw new Error("No EVM wallet found. Install MetaMask, Rabby, or any EVM wallet extension.");

    const accounts = await withTimeout(
      provider.request({ method: "eth_requestAccounts" }),
      60000,
      "Wallet did not respond in 60s — pastikan popup tidak terblokir (popup blocker), lalu klik lagi."
    );
    const address = accounts[0];
    await _ensure_studionet(provider);
    const writeClient = sdk.createClient({ chain: (await sdkLoad)[1].studionet, account: address, provider });

    const qs = QUERY();
    await ensureAddresses();   // muat otomatis bila alamat belum siap
    walletState = {
      address, writeClient,
      analyzer: qs.get("analyzer") || liveAddresses.analyzer,
      auditor: qs.get("auditor") || liveAddresses.auditor,
      lab: qs.get("lab") || liveAddresses.lab,
    }; 
    if (!walletState.analyzer) throw new Error("Analyzer address unavailable yet - refresh and try again.");
    if (!walletState.auditor) throw new Error("Auditor address unavailable yet - refresh and try again.");
    if (!walletState.lab) throw new Error("AttackLab address unavailable yet - refresh and try again.");

    const wa = el("wallet-addr"); if (wa) wa.textContent = address;
    btn.textContent = `👛 ${address.slice(0, 6)}…${address.slice(-4)} (${walletName})`;
    btn.classList.add("active");

    // remember for silent re-connect on the next page load
    persistWallet({ address, providerUuid: detail ? detail.info.uuid : "default", walletName });
    window.dispatchEvent(new CustomEvent("walletconnected"));
  } catch (e) {
    const msg = String(e?.message || e);
    let hint = "";
    if (/getter|another.*wallet|already.*set|only a getter/i.test(msg)) {
      hint = " Sepertinya ada konflik antar-extension wallet (ex: MetaMask vs Rabby) yang berebut window.ethereum. Pilih extension yang benar dari daftar, atau nonaktifkan salah satu extension, lalu reload.";
    } else if (/rejected|user rejected/i.test(msg)) {
      hint = " Penolakan dari wallet Anda — coba lagi dan baca permintaan sign-nya.";
    } else if (/timed out/i.test(msg)) {
      hint = " Periksa apakah popup wallet muncul & tidak diblokir browser, lalu klik connect sekali lagi.";
    } else if (/not found|unavailable yet/i.test(msg)) {
      hint = " Tunggu halaman memuat alamat kontrak, lalu coba lagi.";
    }
    alert("Wallet connect failed: " + msg.slice(0, 180) + hint);
    btn.textContent = "👛 CONNECT WALLET";
  } finally {
    btn.disabled = false;
  }
}

async function connectWallet() {
  const btn = el("wallet-btn");
  if (walletState.address) {
    // sudah connect — konfirmasi disconnect yang JELAS identitasnya
    if (confirm(`Wallet connected: ${walletState.address}\n\nClick OK to disconnect.`)) {
      walletState = { address: null, writeClient: null, analyzer: null, auditor: null, lab: null };
      clearWalletSession();
      btn.textContent = "👛 CONNECT WALLET";
      btn.classList.remove("active");
    }
    return;
  }

  btn.disabled = true;
  btn.textContent = "⏳ DETECTING WALLETS…";
  await new Promise(r => setTimeout(r, 400));

  if (discoveredWallets.length === 0 && !window.ethereum) {
    btn.disabled = false;
    btn.textContent = "👛 CONNECT WALLET";
    _openWalletModalContent('<div class="verdict-card denied"><b>❌ NO WALLET FOUND</b><br>Install an EVM wallet extension (MetaMask, Rabby, Brave Wallet, OKX…) then reload this page.</div>');
    return;
  }
  if (discoveredWallets.length === 1) {
    await _do_connect(discoveredWallets[0]);
    return;
  }
  if (discoveredWallets.length === 0 && window.ethereum) {
    await _do_connect(null);
    return;
  }
  // beberapa wallet terdeteksi — biarkan user memilih
  btn.disabled = false;
  btn.textContent = "👛 CONNECT WALLET";
  _render_wallet_chooser((w) => _do_connect(w));
}

// ensure dashboard shows live addresses for this session fallback
async function seedLiveAddresses() {
  try {
    const d = await fetchDashboard();
    liveAddresses = d.addresses || liveAddresses;
    return d;
  } catch (e) {
    console.error(e);
    return null;
  }
}

// pastikan alamat kontrak sudah terisi sebelum wallet membutuhkannya
async function ensureAddresses() {
  if (!liveAddresses.analyzer || !liveAddresses.auditor || !liveAddresses.lab) {
    await seedLiveAddresses();
  }
  return liveAddresses;
}

// silent re-connect after page navigation — no popup if wallet auto-grants
async function tryRestoreWallet() {
  let snap = null;
  try { snap = JSON.parse(sessionStorage.getItem(SESSION_KEY)); } catch (e) {}
  if (!snap || !snap.address) return false;
  // biarkan EIP-6963 discovery selesai dulu
  await new Promise(r => setTimeout(r, 600));

  let provider = null;
  if (snap.providerUuid && snap.providerUuid !== "default") {
    const w = discoveredWallets.find(x => x.info.uuid === snap.providerUuid);
    provider = w && w.provider;
  } else if (window.ethereum) {
    provider = window.ethereum;
  }
  if (!provider) return false;

  try {
    const accounts = await provider.request({ method: "eth_requestAccounts" });
    if (!accounts || !accounts[0] || String(accounts[0]).toLowerCase() !== String(snap.address).toLowerCase()) {
      return false;
    }
    const sdkLoad = await withTimeout(loadSdk(), 20000, "SDK load timed out");
    const sdk = sdkLoad[0];
    await _ensure_studionet(provider);

    // Pastikan alamat kontrak sudah terisi — kalau belum, BATAL restore
    // daripada menyimpan state setengah jadi (address ada, analyzer null).
    await ensureAddresses();
    if (!liveAddresses.analyzer || !liveAddresses.auditor || !liveAddresses.lab) {
      clearWalletSession();
      return false;
    }

    walletState = {
      address: snap.address,
      writeClient: sdk.createClient({ chain: sdkLoad[1].studionet, account: snap.address, provider }),
      analyzer: liveAddresses.analyzer,
      auditor: liveAddresses.auditor,
      lab: liveAddresses.lab,
    };

    const btn = el("wallet-btn");
    if (btn) {
      btn.textContent = `👛 ${snap.address.slice(0, 6)}…${snap.address.slice(-4)} (${snap.walletName || "EVM Wallet"})`;
      btn.classList.add("active");
    }
    const wa = el("wallet-addr");
    if (wa) wa.textContent = snap.address;
    window.dispatchEvent(new CustomEvent("walletconnected"));
    return true;
  } catch (e) {
    console.warn("wallet restore skipped:", e && e.message);
    clearWalletSession();
    return false;
  }
}

// wire modal close
function wireWalletModal() {
  const closeBtn = el("wallet-modal-close");
  if (closeBtn) closeBtn.addEventListener("click", _closeWalletModal);
  const modal = el("wallet-modal");
  if (modal) modal.addEventListener("click", (e) => { if (e.target === modal) _closeWalletModal(); });
}
// pre-warm SDK di latar agar connect cepat & tidak hang
loadSdk().catch(() => {});

