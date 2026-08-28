// HIVE SENTINEL — shared runtime (loaded by every page)
let autoTimer = null;
let liveAddresses = { honeypot: null, analyzer: null, auditor: null, lab: null, hardened: null };
let walletState = { address: null, writeClient: null, provider: null, analyzer: null, auditor: null, lab: null };
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

// Fallback alamat yang pasti (identik dgn yang live StudioNet) — alamat kontrak
// TIDAK boleh null untuk fitur write. Data tambahan tetap dicoba dari API.
const FALLBACK_ADDRESSES = {
  honeypot: "0xde2CEE8354a747037403D8f8E4854AA8f5F23d40",
  analyzer: "0xC8d9D831005401d8b5B19c73f2De1657607C4baC",
  auditor: "0x44b8748b54b40b1cce572Cff046864ed6C5e8046",
  lab: "0xd72cccA524f49F348C247E45afFf1406D86c3EFe",
  hardened: "0xe8f6349F3AbE79523Ff50AA4B55E8c55CE86fDCB",
};

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

// akses window.ethereum yang AMAN — getter bisa melempar karena konflik extension
function safeWindowEthereum() {
  try { return window.ethereum || null; } catch (e) { return null; }
}

// error ditampilkan INLINE (bukan alert) supaya tidak ketutupan header loading
function reportError(title, msg) {
  let box = el("connect-error");
  if (!box) {
    box = document.createElement("div");
    box.id = "connect-error";
    box.style.cssText = "position:fixed;right:16px;top:76px;z-index:1000;max-width:360px;" +
      "background:#3a1620;border:1px solid var(--red,#d9606f);color:#ffd7db;padding:12px 14px;" +
      "border-radius:10px;font-size:12.5px;line-height:1.6;box-shadow:0 6px 24px rgba(0,0,0,.4);";
    document.body.appendChild(box);
  }
  box.innerHTML = `<b>❌ ${title}</b><br>${escapeHtml(msg)}`;
  clearTimeout(box._t);
  box._t = setTimeout(() => { box.remove(); }, 12000);
}

// hint netral (amber) untuk memandu user saat menunggu popup wallet
function reportInfo(title, msg) {
  let box = el("connect-hint");
  if (!box) {
    box = document.createElement("div");
    box.id = "connect-hint";
    box.style.cssText = "position:fixed;right:16px;top:76px;z-index:1000;max-width:360px;" +
      "background:#2b2313;border:1px solid var(--accent,#d8b45a);color:#f6e7c0;padding:12px 14px;" +
      "border-radius:10px;font-size:12.5px;line-height:1.6;box-shadow:0 6px 24px rgba(0,0,0,.4);";
    document.body.appendChild(box);
  }
  box.innerHTML = `<b>⏳ ${title}</b><br>${escapeHtml(msg)}`;
  clearTimeout(box._t);
  box._t = setTimeout(() => { box.remove(); }, 10000);
}

// ---- transaksi terpusat (pola wagerduel: requestAccounts saat klik,
// write lewat client ber-account, error wallet dipetakan ramah) ----
function _friendlyWalletError(e) {
  const err = e || {};
  const code = err.code ?? err.data?.originalError?.code ?? err.data?.code;
  const msg = String(err.shortMessage || err.message || err).slice(0, 220);
  if (code === 4001 || /user rejected|rejected|denied/i.test(msg)) {
    return "Transaction rejected in your wallet — you cancelled the signature.";
  }
  if (code === -32002 || /pending/i.test(msg)) {
    return "A previous wallet request is still pending — check the wallet popup and try again.";
  }
  if (code === 4902 || /chain|network/i.test(msg)) {
    return "Network not set up — click CONNECT WALLET again so it auto-switches to StudioNet.";
  }
  if (/execution reverted|out of gas/i.test(msg)) {
    return "Transaction failed in the contract: " + msg;
  }
  return "Wallet/transaction error: " + msg;
}

async function walletWrite(contractAddress, functionName, args) {
  if (!walletState.writeClient || !walletState.address) {
    throw new Error("Wallet not connected — click CONNECT WALLET first.");
  }
  if (!contractAddress || String(contractAddress) === "null") {
    throw new Error("Contract address is empty — refresh the page so addresses load, then retry.");
  }

  // pastikan jaringan benar sebelum sign (best-effort, tidak memblok)
  if (walletState.provider) {
    await withTimeout(_ensure_studionet(walletState.provider), 10000, "network switch")
      .catch(() => {});
  }

  try {
    // timeout signing — tidak boleh stuck 'submitting' selamanya
    const txHash = await withTimeout(
      walletState.writeClient.writeContract({
        address: contractAddress,
        functionName,
        args,
      }),
      60000,
      "Wallet signing timed out — check the wallet popup and approve it, then retry."
    );
    return txHash;
  } catch (e) {
    let err = e;
    if (err && err.name === "Error" && /timed out/.test(String(err.message))) {
      err = new Error("Wallet signing timed out — the wallet popup may be blocked or not visible. Approve it, or check popup settings, then retry.");
    }
    throw new Error(_friendlyWalletError(err));
  }
}

// tunggu transaksi sampai di-ACCEPTED (konsensus) — tombol tetap terkunci
async function waitWalletTx(txHash, retries = 50) {
  return walletState.writeClient.waitForTransactionReceipt({
    hash: txHash,
    status: "ACCEPTED",
    interval: 3000,
    retries,
  });
}

// poll dashboard (scope halaman aktif) hingga kondisi terpenuhi / timeout
async function pollScopeUntil(cond, timeoutMs = 40000) {
  const t0 = Date.now();
  let last = null;
  while (Date.now() - t0 < timeoutMs) {
    try {
      last = await fetchDashboard();
      if (cond(last)) return last;
    } catch (e) { /* retry */ }
    await new Promise(r => setTimeout(r, 1500));
  }
  try { last = await fetchDashboard(); } catch (e) {}
  return last;
}

// ---- listener wallet (accountsChanged/disconnect) supaya tombol & state sinkron ----
const _eventBound = new WeakSet();
function attachWalletEvents(provider) {
  if (!provider || _eventBound.has(provider)) return;
  _eventBound.add(provider);
  const syncBtn = () => {
    const btn = el("wallet-btn");
    if (!btn) return;
    if (walletState.address) {
      btn.textContent = `👛 ${walletState.address.slice(0, 6)}…${walletState.address.slice(-4)}`;
      btn.classList.add("active");
    } else {
      btn.textContent = "👛 CONNECT WALLET";
      btn.classList.remove("active");
    }
  };
  if (typeof provider.on === "function") {
    provider.on("accountsChanged", (accounts) => {
      if (!accounts || accounts.length === 0) {
        walletState = { address: null, writeClient: null, provider: null, analyzer: null, auditor: null, lab: null };
        clearWalletSession();
        try { localStorage.setItem(DISCONNECT_FLAG, "true"); } catch (e) {}
        window.dispatchEvent(new CustomEvent("walletdisconnected"));
      } else {
        walletState.address = accounts[0];
        window.dispatchEvent(new CustomEvent("walletconnected"));
      }
      syncBtn();
    });
    provider.on("disconnect", () => {
      walletState = { address: null, writeClient: null, provider: null, analyzer: null, auditor: null, lab: null };
      clearWalletSession();
      window.dispatchEvent(new CustomEvent("walletdisconnected"));
      syncBtn();
    });
  }
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
function currentPageScope() {
  const active = document.querySelector(".view.active");
  if (active && active.id) return active.id.replace("view-", "");
  return "monitor";
}

async function fetchDashboard() {
  const scope = currentPageScope() || "monitor";
  const qs = QUERY().toString();
  for (let attempt = 0; attempt < 2; attempt++) {
    const res = await fetch(`/api/dashboard?scope=${encodeURIComponent(scope)}&${qs}`);
    if (res.ok) return res.json();
    if (res.status === 504 && attempt === 0) {
      await new Promise(r => setTimeout(r, 1500));
      continue;
    }
    throw new Error(`API status ${res.status}`);
  }
  throw new Error("API status 504 (retried)");
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

// ---- network switch BEST-EFFORT: kalau popup jaringan diabaikan, tetap lanjut
// (koneksi sudah sukses; peringatan ditampilkan, write bisa dicoba nanti) ----
async function _ensure_studionet(provider) {
  try {
    await provider.request({ method: "wallet_switchEthereumChain", params: [{ chainId: STUDIONET_CHAIN_ID }] });
    return true;
  } catch (err) {
    const code = err?.code ?? err?.data?.originalError?.code;
    if (code === 4902 || String(err?.message).includes("not")) {
      try {
        await provider.request({
          method: "wallet_addEthereumChain",
          params: [{ chainId: STUDIONET_CHAIN_ID, chainName: "GenLayer StudioNet",
                     nativeCurrency: { name: "GEN Token", symbol: "GEN", decimals: 18 },
                     rpcUrls: [STUDIONET_RPC] }],
        });
        return true;
      } catch (e2) {
        return false;
      }
    }
    return false; // rejected/timeout — bukan gagal fatal, lanjut dengan peringatan
  }
}

// ---- session persistence: keep wallet across page navigation ----
const SESSION_KEY = "hs_wallet_session";
// localStorage flag: user intent to disconnect → jangan auto-reconnect.
// (Pola dari referensi wagerduel: eth_accounts saat mount, requestAccounts hanya saat klik.)
const DISCONNECT_FLAG = "hs_wallet_disconnected";

function persistWallet(snap) {
  try { sessionStorage.setItem(SESSION_KEY, JSON.stringify(snap)); } catch (e) {}
}
function clearWalletSession() {
  try { sessionStorage.removeItem(SESSION_KEY); } catch (e) {}
}

async function _do_connect(detail) {
  const btn = el("wallet-btn");
  const walletName = detail
    ? detail.info.name
    : (safeWindowEthereum() && safeWindowEthereum().isMetaMask ? "MetaMask" : "EVM Wallet");
  btn.disabled = true;
  // HARD global timeout: apa pun yang menggantung, UI DIPAKSA pulih
  let bounced = false;
  const hardTimeout = setTimeout(() => {
    bounced = true;
    btn.disabled = false;
    btn.textContent = "👛 CONNECT WALLET";
    reportError("Timeout", "Connection did not finish. The popup may be blocked, or the tab is not focused. Try again.");
  }, 45000);
  const done = () => { clearTimeout(hardTimeout); };

  try {
    btn.textContent = "⏳ LOADING SDK…";
    const sdkLoad = await withTimeout(loadSdk(), 20000, "SDK load timed out — check your internet / CDN.");
    const sdk = sdkLoad[0];
    if (bounced) return;

    // loading baru dipasang TEPAT sebelum popup, bukan sejak awal
    btn.textContent = `⏳ AWAITING ${walletName.toUpperCase()} POPUP…`;
    reportInfo("Waiting for wallet",
      `Popup ${walletName} is waiting for your approval — look in the browser corner / taskbar and click <b>Connect/Approve</b>. Also approve the second \"switch to StudioNet\" popup if it appears.`);

    const provider = detail ? detail.provider : safeWindowEthereum();
    if (!provider) throw new Error("No EVM wallet found. Install MetaMask, Rabby, or any EVM wallet extension.");

    const accounts = await withTimeout(
      provider.request({ method: "eth_requestAccounts" }),
      45000,
      "Wallet did not respond in 45s — make sure the wallet popup appears and is not blocked."
    );
    if (bounced) return; 
    const address = accounts[0];

    // network switch best-effort — jangan blok koneksi
    await withTimeout(_ensure_studionet(provider), 12000, "switch").catch(() => {});

    const writeClient = sdk.createClient({ chain: (await sdkLoad)[1].studionet, account: address, provider });

    // ALWAYS rekam state setelah eth_requestAccounts sukses → tombol tampil alamat.
    const qs = QUERY();
    await withTimeout(ensureAddresses(), 20000, "addr").catch(() => {});
    walletState = {
      address, writeClient, provider,
      analyzer: qs.get("analyzer") || liveAddresses.analyzer,
      auditor: qs.get("auditor") || liveAddresses.auditor,
      lab: qs.get("lab") || liveAddresses.lab,
    };

    if (!walletState.analyzer) walletState.analyzer = FALLBACK_ADDRESSES.analyzer;
    if (!walletState.auditor) walletState.auditor = FALLBACK_ADDRESSES.auditor;
    if (!walletState.lab) walletState.lab = FALLBACK_ADDRESSES.lab;

    const wa = el("wallet-addr"); if (wa) wa.textContent = address;
    btn.textContent = `👛 ${address.slice(0, 6)}…${address.slice(-4)} (${walletName})`;
    btn.classList.add("active");

    persistWallet({ address, providerUuid: detail ? detail.info.uuid : "default", walletName });
    try { localStorage.removeItem(DISCONNECT_FLAG); } catch (e) {}
    attachWalletEvents(provider);
    window.dispatchEvent(new CustomEvent("walletconnected"));

    // (Optional) alamat dari API mungkin lebih akurat; tapi fallback sudah cukup
    // untuk semua fitur write. Hapus popup "Contract addresses" yang lama.
  } catch (e) {
    if (!bounced) {
      const msg = String(e?.message || e);
      let hint = "";
      if (/getter|another.*wallet|already.*set|only a getter/i.test(msg)) {
        hint = " Extension conflict (MetaMask vs Rabby) fighting over window.ethereum. Pick a wallet, disable one extension, then reload.";
      } else if (/rejected|user rejected/i.test(msg)) {
        hint = " You rejected the connection in your wallet.";
      } else if (/timed out|did not respond/i.test(msg)) {
        hint = " The popup did not appear/respond — make sure popups are allowed for this site.";
      }
      reportError("Connect failed", msg.slice(0, 200) + hint);
    }
  } finally {
    done();
    btn.disabled = false;
    if (!walletState.address) btn.textContent = "👛 CONNECT WALLET";
  }
}

async function connectWallet() {
  const btn = el("wallet-btn");
if (walletState.address) {
    // sudah connect — konfirmasi disconnect yang JELAS identitasnya
    if (confirm(`Wallet connected: ${walletState.address}\n\nClick OK to disconnect.`)) {
      walletState = { address: null, writeClient: null, provider: null, analyzer: null, auditor: null, lab: null };
      clearWalletSession();
      try { localStorage.setItem(DISCONNECT_FLAG, "true"); } catch (e) {}
      btn.textContent = "👛 CONNECT WALLET";
      btn.classList.remove("active");
    }
    return;
  }

  btn.disabled = true;
  btn.textContent = "⏳ DETECTING WALLETS…";
  await new Promise(r => setTimeout(r, 400));
  btn.disabled = false;
  btn.textContent = "👛 CONNECT WALLET";

  // Pilihan provider:
  //  - >=2 wallet terdeteksi  → CHOOSER (explicit, label sesuai yang dipilih, mis. "(Rabby)")
  //  - tepat 1 terdeteksi     → pakai provider itu persis
  //  - 0 terdeteksi           → fallback window.ethereum (pola wagerduel)
  if (discoveredWallets.length >= 2) {
    _render_wallet_chooser((w) => _do_connect(w));
    return;
  }
  if (discoveredWallets.length === 1) {
    await _do_connect(discoveredWallets[0]);
    return;
  }
  const we = safeWindowEthereum();
  if (!we) {
    _openWalletModalContent('<div class="verdict-card denied"><b>❌ NO WALLET FOUND</b><br>Install an EVM wallet extension (MetaMask, Rabby, Brave Wallet, OKX…) then reload this page.</div>');
    return;
  }
  await _do_connect(null);
}

// ensure dashboard shows live addresses for this session fallback
async function seedLiveAddresses(retries = 3) {
  for (let i = 0; i < retries; i++) {
    try {
      const d = await fetchDashboard();
      if (d && d.addresses) {
        liveAddresses = d.addresses;
        return d;
      }
    } catch (e) { /* retry */ }
    if (i < retries - 1) await new Promise(r => setTimeout(r, 900));
  }
  return null;
}

// pastikan alamat kontrak sudah terisi sebelum wallet membutuhkannya
// Fallback bawaan menjamin TIDAK pernah null (write tidak mungkin "Address null").
async function ensureAddresses() {
  if (!liveAddresses.analyzer || !liveAddresses.auditor || !liveAddresses.lab) {
    await seedLiveAddresses();
  }
  for (const k of Object.keys(FALLBACK_ADDRESSES)) {
    if (!liveAddresses[k]) liveAddresses[k] = FALLBACK_ADDRESSES[k];
  }
  return liveAddresses;
}

// tunggu provider wallet siap (discovery EIP-6963 / window.ethereum) hingga 2.5s
async function waitForWalletProvider(ms = 2500) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    if (safeWindowEthereum() || discoveredWallets.length) return true;
    await new Promise(r => setTimeout(r, 150));
  }
  return false;
}

// silent re-connect after refresh — NO popup, pakai eth_accounts (pola wagerduel)
async function tryRestoreWallet() {
  let snap = null;
  try { snap = JSON.parse(sessionStorage.getItem(SESSION_KEY)); } catch (e) {}
  if (!snap || !snap.address) return false;

  // user pernah disconnect → hormati, jangan auto-reconnect
  if (typeof localStorage !== "undefined" && localStorage.getItem(DISCONNECT_FLAG) === "true") {
    clearWalletSession();
    return false;
  }

  // tunggu discovery selesai (bukan sekadar 600ms)
  await waitForWalletProvider(2500);

  // resolve provider: uuid tersimpan → window.ethereum → wallet pertama
  let provider = null;
  if (snap.providerUuid && snap.providerUuid !== "default") {
    const w = discoveredWallets.find(x => x.info.uuid === snap.providerUuid);
    provider = w && w.provider;
  }
  if (!provider) provider = safeWindowEthereum();
  if (!provider && discoveredWallets.length) provider = discoveredWallets[0].provider;
  if (!provider) return false;

  // eth_accounts dengan retry (wallet kadang butuh momen setelah load untuk unlock)
  let accounts = null;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      accounts = await withTimeout(provider.request({ method: "eth_accounts" }), 3000, "getAccounts");
    } catch (e) { accounts = null; }
    if (accounts && accounts.length) break;
    await new Promise(r => setTimeout(r, 700));
  }
  if (!accounts || !accounts.length) {
    clearWalletSession();
    return false;
  }
  const address = String(accounts[0]);

  try {
    const sdkLoad = await withTimeout(loadSdk(), 20000, "SDK load timed out");
    const sdk = sdkLoad[0];
    // TIDAK switch jaringan di sini — restore harus benar-benar SENYAP (tanpa popup).

    await withTimeout(ensureAddresses(), 20000, "addr").catch(() => {});
    // alamat DIJAMIN terisi oleh fallback — tidak perlu bail di sini.

    walletState = {
      address,
      provider,
      writeClient: sdk.createClient({ chain: sdkLoad[1].studionet, account: address, provider }),
      analyzer: liveAddresses.analyzer,
      auditor: liveAddresses.auditor,
      lab: liveAddresses.lab,
    };

    persistWallet({ address, providerUuid: snap.providerUuid || "default", walletName: snap.walletName || "EVM Wallet" });

    const btn = el("wallet-btn");
    if (btn) {
      btn.textContent = `👛 ${address.slice(0, 6)}…${address.slice(-4)} (${snap.walletName || "EVM Wallet"})`;
      btn.classList.add("active");
    }
    const wa = el("wallet-addr");
    if (wa) wa.textContent = address;
    attachWalletEvents(provider);
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

