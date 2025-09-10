/* ==========================================================
 * Frontend Script – Kick/Discord Verification UI
 * ========================================================== */

/* ---- Helpers ---- */
const $ = (s, root=document) => root.querySelector(s);
const $$ = (s, root=document) => Array.from(root.querySelectorAll(s));
const qParams = () => new URLSearchParams(location.search);

function show(el){ if (!el) return; el.style.display = ""; }
function hide(el){ if (!el) return; el.style.display = "none"; }

function showToast(msg, type="info", ms=2000){
  const t = $("#toast");
  if (!t) return;
  t.textContent = msg;
  t.style.borderColor = type === "error" ? "rgba(239,68,68,0.5)" : type === "success" ? "rgba(34,197,94,0.5)" : "rgba(255,255,255,0.2)";
  t.classList.add("show");
  setTimeout(()=> t.classList.remove("show"), ms);
}

function apiBase(){
  // same origin
  return `${location.origin}`;
}

/* ---- Routing ---- */
function currentSlug(){
  const p = location.pathname.replace(/^\/+/, "");
  return p.split("/")[0] || "";
}

function handleRouting(){
  const slug = currentSlug();
  const isAdmin = slug.toLowerCase() === "admin";
  if (isAdmin){
    hide($("#home-page"));
    hide($("#channel-page"));
    show($("#admin-page"));
    initAdmin();
    return;
  }

  if (slug){
    hide($("#home-page"));
    hide($("#admin-page"));
    show($("#channel-page"));
    initChannel(slug);
  } else {
    hide($("#channel-page"));
    hide($("#admin-page"));
    show($("#home-page"));
    loadStreamersList();
  }
}

/* ---- API ---- */
async function fetchJSON(url, opts){
  const r = await fetch(url, opts);
  const txt = await r.text();
  try{
    const j = txt ? JSON.parse(txt) : {};
    if (!r.ok) throw new Error(j?.error || txt || `HTTP ${r.status}`);
    return j;
  }catch(e){
    if (!r.ok) throw new Error(txt || `HTTP ${r.status}`);
    throw e;
  }
}

async function listStreamers(){
  return fetchJSON(`${apiBase()}/api/streamers`);
}
async function getStreamer(slug){
  return fetchJSON(`${apiBase()}/api/streamers/${encodeURIComponent(slug)}`);
}
async function addStreamer(payload){
  return fetchJSON(`${apiBase()}/api/streamers`, {
    method:"POST",
    headers:{ "Content-Type":"application/json" },
    body: JSON.stringify(payload)
  });
}
async function deleteStreamer(slug, password){
  return fetchJSON(`${apiBase()}/api/streamers/${encodeURIComponent(slug)}`, {
    method:"DELETE",
    headers:{ "Content-Type":"application/json" },
    body: JSON.stringify({ password })
  });
}
async function adminLogin(password){
  return fetchJSON(`${apiBase()}/api/login`, {
    method:"POST",
    headers:{ "Content-Type":"application/json" },
    body: JSON.stringify({ password })
  });
}

/* ---- Channel Page ---- */
async function initChannel(slug){
  // Streamer oku
  let streamer = null;
  try{
    const res = await getStreamer(slug);
    streamer = res;
  }catch(e){
    $("#streamer-title").textContent = slug;
    $("#streamer-subtitle").textContent = "Yayıncı bulunamadı.";
    showToast("Yayıncı bulunamadı", "error");
    return;
  }

  // UI doldur
  $("#streamer-title").textContent = streamer.displayText || slug;
  $("#streamer-subtitle").textContent = "Aboneliğini doğrulamak için giriş yap.";
  if (streamer.customBackgroundUrl) {
    $("#hero-bg").style.background = `center/cover no-repeat url('${streamer.customBackgroundUrl}')`;
  }

  // Login butonları
  $("#kick-login")?.addEventListener("click", ()=>{
    const url = new URL(`${apiBase()}/api/auth/redirect/kick`);
    url.searchParams.set("streamer", slug);
    location.href = url.toString();
  });
  $("#discord-login")?.addEventListener("click", ()=>{
    const url = new URL(`${apiBase()}/api/auth/redirect/discord`);
    url.searchParams.set("streamer", slug);
    location.href = url.toString();
  });

  // Callback geldiyse UI'ı güncelle
  await handleCallbackAndUI(slug);
}

function createBadge(ok){
  if (ok) {
    return `<span class="status-badge status-badge-green">✓ Abone</span>`;
  }
  return `<span class="status-badge status-badge-red">X Abone Değil</span>`;
}

async function handleCallbackAndUI(slug){
  const url = new URL(location.href);
  const provider   = url.searchParams.get("provider");
  const subscribed = url.searchParams.get("subscribed");

  const data = {
    provider: null,
    kick: { linked: false, subscribed: false },
    discord: { linked: false }
  };

  if (provider) {
    data.provider = provider;
    if (provider === "kick") {
      data.kick.linked = true;
      data.kick.subscribed = (subscribed === "true");
    } else if (provider === "discord") {
      data.discord.linked = true;
    }

    // persist minimal
    try {
      const auth = { provider, slug, subscribed: data.kick.subscribed, ts: Date.now() };
      sessionStorage.setItem("auth", JSON.stringify(auth));
    } catch {}

    // query temizle
    url.searchParams.delete("provider");
    url.searchParams.delete("subscribed");
    url.searchParams.delete("method");
    url.searchParams.delete("expires_at");
    history.replaceState({}, document.title, url.pathname + (url.search ? url.search : "") + url.hash);
  } else {
    // persist'ten yükle
    try {
      const auth = JSON.parse(sessionStorage.getItem("auth") || localStorage.getItem("auth") || "null");
      if (auth && auth.slug === slug) {
        if (auth.provider === "kick") {
          data.kick.linked = true;
          data.kick.subscribed = !!auth.subscribed;
        } else if (auth.provider === "discord") {
          data.discord.linked = true;
        }
      }
    } catch {}
  }

  updateUI(data);
}

function updateUI(data){
  const status = $("#status-container");
  if (data?.kick?.linked) {
    status.innerHTML = createBadge(!!data.kick.subscribed);
  } else {
    status.innerHTML = ""; // giriş yapılmamışsa boş kalsın
  }
}

/* ---- Home Page ---- */
async function loadStreamersList(){
  const wrap = $("#streamers-list");
  wrap.innerHTML = "";
  let list = [];
  try{
    list = await listStreamers();
  }catch(e){
    wrap.innerHTML = `<div class="subtitle">Yayıncı yok.</div>`;
    return;
  }
  if (!Array.isArray(list) || list.length === 0){
    wrap.innerHTML = `<div class="subtitle">Yayıncı yok.</div>`;
    return;
  }

  for (const it of list){
    const slug = it.slug;
    const card = document.createElement("div");
    card.className = "card";
    card.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;">
        <div>
          <div style="font-weight:700">${it.displayText || slug}</div>
          <div class="subtitle" style="font-size:12px;">/${slug}</div>
        </div>
        <div style="display:flex;gap:8px;">
          <a class="btn btn-primary btn-press" href="/${slug}">Git</a>
        </div>
      </div>
    `;
    wrap.appendChild(card);
  }
}

/* ---- Admin ---- */
function initAdmin(){
  const loginForm = $("#admin-login-form");
  const pwInput = $("#admin-password");
  const loginStatus = $("#admin-login-status");

  loginForm?.addEventListener("submit", async (e)=>{
    e.preventDefault();
    const pw = pwInput.value.trim();
    try{
      const r = await adminLogin(pw);
      sessionStorage.setItem("isAdminAuthenticated", "true");
      sessionStorage.setItem("adminPassword", pw);
      loginStatus.textContent = "Giriş başarılı.";
      loadAdminTables();
    }catch(e){
      loginStatus.textContent = "Giriş başarısız.";
    }
  });

  // auto if session ok
  if (sessionStorage.getItem("isAdminAuthenticated") === "true") {
    loadAdminTables();
  }

  // add new streamer
  $("#add-streamer-form")?.addEventListener("submit", async (e)=>{
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    const payload = Object.fromEntries(fd.entries());
    try{
      await addStreamer({ ...payload, password: sessionStorage.getItem("adminPassword") || "" });
      showToast("Yayıncı eklendi", "success");
      e.currentTarget.reset();
      loadAdminTables();
    }catch(err){
      showToast("Ekleme hatası", "error");
    }
  });

  // edit modal wires
  $("#edit-cancel")?.addEventListener("click", ()=>{
    $("#edit-modal")?.classList.remove("show");
  });
  $("#edit-streamer-form")?.addEventListener("submit", async (e)=>{
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    const payload = Object.fromEntries(fd.entries());
    const slug = payload.slug;
    delete payload.slug;
    try{
      await fetchJSON(`${apiBase()}/api/streamers/${encodeURIComponent(slug)}`, {
        method:"PUT",
        headers:{ "Content-Type":"application/json" },
        body: JSON.stringify({ ...payload, password: sessionStorage.getItem("adminPassword") || "" })
      });
      showToast("Güncellendi", "success");
      $("#edit-modal")?.classList.remove("show");
      loadAdminTables();
    }catch(err){
      showToast("Güncelleme hatası", "error");
    }
  });
}

async function loadAdminTables(){
  const listWrap = $("#streamers-table");
  listWrap.innerHTML = "";
  let list = [];
  try{ list = await listStreamers(); } catch {}
  if (!Array.isArray(list) || list.length === 0){
    listWrap.innerHTML = `<div class="subtitle">Kayıt yok</div>`;
    return;
  }

  list.forEach(it=>{
    const row = document.createElement("div");
    row.className = "glass-card";
    row.style.cssText = "border-radius:12px;padding:12px;margin-bottom:10px;";
    row.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;">
        <div style="display:flex;flex-direction:column;gap:4px;">
          <div style="font-weight:700">${it.displayText || it.slug}</div>
          <div class="subtitle" style="font-size:12px;">/${it.slug}</div>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;">
          <button class="btn btn-press btn-outline" data-edit="${it.slug}">Düzenle</button>
          <button class="btn btn-danger btn-press" data-del="${it.slug}">Sil</button>
        </div>
      </div>
    `;
    listWrap.appendChild(row);

    // wires
    row.querySelector(`[data-edit="${it.slug}"]`)?.addEventListener("click", ()=>{
      const m = $("#edit-modal");
      m?.classList.add("show");
      const f = $("#edit-streamer-form");
      f.slug.value = it.slug;
      f.displayText.value = it.displayText || "";
      f.discordGuildId.value = it.discordGuildId || "";
      f.discordRoleId.value = it.discordRoleId || "";
      f.discordBotToken.value = it.discordBotToken || "";
      f.broadcaster_user_id.value = it.broadcaster_user_id || "";
    });

    row.querySelector(`[data-del="${it.slug}"]`)?.addEventListener("click", async ()=>{
      if (!confirm(`${it.slug} silinsin mi?`)) return;
      try{
        await deleteStreamer(it.slug, sessionStorage.getItem("adminPassword") || "");
        showToast("Silindi", "success");
        loadAdminTables();
      }catch(e){
        showToast("Silme hatası", "error");
      }
    });
  });
}

/* ---- DOMReady ---- */
document.addEventListener("DOMContentLoaded", () => {
  handleRouting();
});

/* --- Global Logout UX + Status Badge Render --- */
(function(){
  const btn = document.getElementById("global-logout");

  function currentSlug(){
    const p = location.pathname.replace(/^\/+/, "");
    return p.split("/")[0] || "";
  }

  function ensureStatusContainer(){
    let el = document.getElementById("status-container");
    if (!el) {
      const host = document.getElementById("streamer-card") || document.getElementById("app") || document.body;
      el = document.createElement("div");
      el.id = "status-container";
      el.style.marginTop = "8px";
      host.prepend(el);
    }
    return el;
  }

  function renderStatusBadgeFromState(){
    const url = new URL(location.href);
    const qProvider   = url.searchParams.get("provider");
    const qSubscribed = url.searchParams.get("subscribed");
    let subscribed = null;
    if (qProvider) {
      subscribed = (qSubscribed === "true");
    } else {
      try {
        const auth = JSON.parse(sessionStorage.getItem("auth") || localStorage.getItem("auth") || "null");
        if (auth && typeof auth.subscribed === "boolean") subscribed = auth.subscribed;
      } catch {}
    }
    if (subscribed === null) return;
    const c = ensureStatusContainer();
    if (subscribed) {
      c.innerHTML = '<span class="status-badge status-badge-green">✓ Abone</span>';
    } else {
      c.innerHTML = '<span class="status-badge status-badge-red">X Abone Değil</span>';
    }
  }

  // OAuth callback query -> session'a yaz & URL’i temizle; sonra rozeti çiz
  (function syncAuthFromQuery(){
    try{
      const url = new URL(location.href);
      const provider   = url.searchParams.get("provider");
      const subscribed = url.searchParams.get("subscribed");
      if (provider){
        const auth = { provider, slug: currentSlug(), subscribed: subscribed === "true", ts: Date.now() };
        sessionStorage.setItem("auth", JSON.stringify(auth));
        ["provider","subscribed","method","expires_at","logged_out"].forEach(k=>url.searchParams.delete(k));
        const clean = url.pathname + (url.searchParams.toString() ? "?"+url.searchParams.toString() : "") + url.hash;
        history.replaceState({}, document.title, clean);
      }
    }catch(e){ console.warn("syncAuthFromQuery error", e); }
    renderStatusBadgeFromState();
  })();

  // Kanal sayfasında değilsek butonu sakla (kanaldaysa görünür)
  function updateVisibility(){
    const slug = currentSlug();
    const onChannel = !!slug;
    if (btn) btn.style.display = onChannel ? "" : "none";
  }
  updateVisibility();
  window.addEventListener("popstate", updateVisibility);

  // Depo değişirse rozet/görünürlük güncelle
  window.addEventListener("storage", (ev)=>{
    if (ev.key === "auth") renderStatusBadgeFromState();
  });

  // Çıkış
  btn?.addEventListener("click", (e)=>{
    e.preventDefault();
    try{
      sessionStorage.removeItem("auth");
      sessionStorage.removeItem("isAdminAuthenticated");
      sessionStorage.removeItem("adminPassword");
    }catch{}

    const slug = currentSlug();
    const url = new URL("/"+slug, location.origin);
    url.searchParams.set("logged_out","1");
    location.href = url.toString();
  });
})();
