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

  $("#streamer-title").textContent = streamer.displayText || slug;
  $("#streamer-subtitle").textContent = "Aboneliğini doğrulamak için giriş yap.";
  if (streamer.customBackgroundUrl) {
    $("#hero-bg").style.background = `center/cover no-repeat url('${streamer.customBackgroundUrl}')`;
  }

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

    try {
      const auth = { provider, slug, subscribed: data.kick.subscribed, ts: Date.now() };
      sessionStorage.setItem("auth", JSON.stringify(auth));
    } catch {}

    url.searchParams.delete("provider");
    url.searchParams.delete("subscribed");
    url.searchParams.delete("method");
    url.searchParams.delete("expires_at");
    history.replaceState({}, document.title, url.pathname + (url.search ? url.search : "") + url.hash);
  } else {
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
    status.innerHTML = "";
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

  if (sessionStorage.getItem("isAdminAuthenticated") === "true") {
    loadAdminTables();
  }

  // CREATE (trim + validate, UI değiştirmeden)
  $("#add-streamer-form")?.addEventListener("submit", async (e)=>{
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    const payload = Object.fromEntries(fd.entries());

    payload.slug = (payload.slug || "").trim().toLowerCase();
    payload.displayText = (payload.displayText || "").trim();
    if (!payload.slug || !payload.displayText){
      showToast("Lütfen slug ve görünen metni doldurun.", "error");
      return;
    }

    try{
      await addStreamer({ ...payload, password: sessionStorage.getItem("adminPassword") || "" });
      showToast("Yayıncı eklendi", "success");
      e.currentTarget.reset();
      loadAdminTables();
    }catch(err){
      showToast(err.message || "Ekleme hatası", "error");
    }
  });

  $("#edit-cancel")?.addEventListener("click", ()=>{
    $("#edit-modal")?.classList.remove("show");
  });
  $("#edit-streamer-form")?.addEventListener("submit", async (e)=>{
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    const payload = Object.fromEntries(fd.entries());
    const slug = (payload.slug || "").trim().toLowerCase();
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
