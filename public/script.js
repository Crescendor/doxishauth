/* ==========================================================
 * Frontend Script — UI'ya dokunmadan login/subscribe akışı
 * ZORUNLULUK: Kick + Discord login şart, aksi halde "X Abone Değil"
 * ========================================================== */

const $ = (s, r=document) => r.querySelector(s);

function show(el){ if(el) el.style.display=""; }
function hide(el){ if(el) el.style.display="none"; }

function apiBase(){ return location.origin; }
function currentSlug(){ const p=location.pathname.replace(/^\/+/, ""); return p.split("/")[0]||""; }

function showToast(msg,type="info",ms=2000){
  const t=$("#toast"); if(!t) return;
  t.textContent=msg;
  t.style.borderColor = type==="error" ? "rgba(239,68,68,0.5)" :
                        type==="success" ? "rgba(34,197,94,0.5)" : "rgba(255,255,255,0.2)";
  t.classList.add("show"); setTimeout(()=>t.classList.remove("show"), ms);
}

/* ---------------- API helpers ---------------- */
async function fetchJSON(url,opts){
  const r=await fetch(url,opts); const txt=await r.text();
  try{ const j=txt?JSON.parse(txt):{}; if(!r.ok) throw new Error(j?.error||txt||`HTTP ${r.status}`); return j; }
  catch(e){ if(!r.ok) throw new Error(txt||`HTTP ${r.status}`); throw e; }
}
const listStreamers = ()=> fetchJSON(`${apiBase()}/api/streamers`);
const getStreamer  = slug => fetchJSON(`${apiBase()}/api/streamers/${encodeURIComponent(slug)}`);
const addStreamer  = payload => fetchJSON(`${apiBase()}/api/streamers`, {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
const deleteStreamer = (slug,password) => fetchJSON(`${apiBase()}/api/streamers/${encodeURIComponent(slug)}`, {method:"DELETE",headers:{"Content-Type":"application/json"},body:JSON.stringify({password})});
const adminLogin = password => fetchJSON(`${apiBase()}/api/login`, {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({password})});

/* ---------------- Auth state (tek obje) ---------------- */
function defaultAuth(slug){
  return { slug, kick:{ linked:false, subscribed:false }, discord:{ linked:false }, ts: Date.now() };
}
function readAuth(slug){
  try{
    const raw = sessionStorage.getItem("auth") || localStorage.getItem("auth");
    if (!raw) return defaultAuth(slug);
    const a = JSON.parse(raw);
    if (a.slug !== slug) return defaultAuth(slug);
    // backward-compat
    if (!a.kick) a.kick = { linked: a.provider==="kick", subscribed: !!a.subscribed };
    if (!a.discord) a.discord = { linked: a.provider==="discord" };
    return a;
  }catch{ return defaultAuth(slug); }
}
function writeAuth(a){
  try{ sessionStorage.setItem("auth", JSON.stringify(a)); }catch{}
}
function clearAuth(){
  try{ sessionStorage.removeItem("auth"); localStorage.removeItem("auth"); }catch{}
}

/* ---------------- Routing ---------------- */
function handleRouting(){
  const slug=currentSlug(); const isAdmin=slug.toLowerCase()==="admin";
  if (isAdmin){ hide($("#home-page")); hide($("#channel-page")); show($("#admin-page")); initAdmin(); return; }
  if (slug){ hide($("#home-page")); hide($("#admin-page")); show($("#channel-page")); initChannel(slug); }
  else { hide($("#channel-page")); hide($("#admin-page")); show($("#home-page")); loadStreamersList(); }
}

/* ---------------- Channel Page ---------------- */
async function initChannel(slug){
  // streamer data + statik başlıklar
  try{
    const s=await getStreamer(slug);
    $("#streamer-title").textContent = s.displayText || slug;
    $("#streamer-subtitle").textContent = "Aboneliğini doğrulamak için giriş yap.";
    if (s.customBackgroundUrl) $("#hero-bg").style.background = `center/cover no-repeat url('${s.customBackgroundUrl}')`;
  }catch{
    $("#streamer-title").textContent = slug;
    $("#streamer-subtitle").textContent = "Yayıncı bulunamadı.";
    showToast("Yayıncı bulunamadı","error");
    return;
  }

  const kickBtn = $("#kick-login");
  const discBtn = $("#discord-login");

  // login yönlendirmeleri
  kickBtn?.addEventListener("click", ()=>{
    const u=new URL(`${apiBase()}/api/auth/redirect/kick`); u.searchParams.set("streamer", slug); location.href=u.toString();
  });
  discBtn?.addEventListener("click", ()=>{
    const u=new URL(`${apiBase()}/api/auth/redirect/discord`); u.searchParams.set("streamer", slug); location.href=u.toString();
  });

  // callback → auth merge → UI
  await hydrateAndRender(slug);
}

function createBadge(ok){
  return ok
    ? `<span class="status-badge status-badge-green">✓ Abone</span>`
    : `<span class="status-badge status-badge-red">X Abone Değil</span>`;
}

function setButtonsState(auth){
  const kickBtn=$("#kick-login"); const discBtn=$("#discord-login");

  // Discord: login yapıldıysa gri (disabled)
  if (discBtn){
    if (auth.discord.linked){ discBtn.classList.add("disabled"); discBtn.setAttribute("disabled","disabled"); }
    else { discBtn.classList.remove("disabled"); discBtn.removeAttribute("disabled"); }
  }

  // Kick: login yapıldıysa butonu "Çıkış Yap" davranışına çevir (UI'yı bozma: aynı buton)
  if (kickBtn){
    // eski handler'ları temizlemek için klonla
    const fresh = kickBtn.cloneNode(true);
    fresh.id = "kick-login";
    kickBtn.replaceWith(fresh);

    if (auth.kick.linked){
      fresh.textContent = "Çıkış Yap";
      fresh.classList.remove("btn-primary"); // görünümü çok değiştirmiyoruz
      fresh.addEventListener("click", (e)=>{
        e.preventDefault();
        clearAuth();                // tüm provider state'lerini temizle
        location.href = `/${currentSlug()}`; // sayfayı temiz paramla yenile
      });
    } else {
      // normal "Kick ile Giriş Yap"
      fresh.textContent = "Kick ile Giriş Yap";
      fresh.addEventListener("click", ()=>{
        const u=new URL(`${apiBase()}/api/auth/redirect/kick`);
        u.searchParams.set("streamer", currentSlug());
        location.href=u.toString();
      });
    }
  }
}

async function hydrateAndRender(slug){
  const url = new URL(location.href);
  const provider = url.searchParams.get("provider");
  const subscribed = url.searchParams.get("subscribed");

  // auth oku/başlat
  let auth = readAuth(slug);

  // callback geldiyse merge et
  if (provider){
    if (provider === "kick"){
      auth.kick.linked = true;
      auth.kick.subscribed = (subscribed === "true");
    } else if (provider === "discord"){
      auth.discord.linked = true;
    }
    auth.ts = Date.now();
    writeAuth(auth);

    // query temizle
    url.searchParams.delete("provider");
    url.searchParams.delete("subscribed");
    url.searchParams.delete("method");
    url.searchParams.delete("expires_at");
    history.replaceState({}, document.title, url.pathname + (url.search?url.search:"") + url.hash);
  }

  // --- ZORUNLULUK KURALI ---
  // “✓ Abone” yalnızca: Kick.linked && Discord.linked && Kick.subscribed === true
  const bothLinked = auth.kick.linked && auth.discord.linked;
  const ok = bothLinked && auth.kick.subscribed === true;

  // status rozet
  const status = $("#status-container");
  status.innerHTML = createBadge(ok);

  // buton durumları
  setButtonsState(auth);
}

/* ---------------- Home/Admin ---------------- */
async function loadStreamersList(){
  const wrap=$("#streamers-list"); wrap.innerHTML="";
  let list=[]; try{ list=await listStreamers(); }catch{}
  if(!Array.isArray(list)||!list.length){ wrap.innerHTML=`<div class="subtitle">Yayıncı yok.</div>`; return; }
  for(const it of list){
    const slug=it.slug;
    const card=document.createElement("div"); card.className="card";
    card.innerHTML=`
      <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;">
        <div><div style="font-weight:700">${it.displayText||slug}</div><div class="subtitle" style="font-size:12px;">/${slug}</div></div>
        <div style="display:flex;gap:8px;"><a class="btn btn-primary btn-press" href="/${slug}">Git</a></div>
      </div>`;
    wrap.appendChild(card);
  }
}

/* ------ Admin (aynen kalsın, sadece güvenli ekleme) ------ */
function initAdmin(){
  const loginForm=$("#admin-login-form"); const pw=$("#admin-password"); const st=$("#admin-login-status");
  loginForm?.addEventListener("submit", async e=>{
    e.preventDefault();
    try{ await adminLogin(pw.value.trim()); sessionStorage.setItem("isAdminAuthenticated","true"); sessionStorage.setItem("adminPassword", pw.value.trim()); st.textContent="Giriş başarılı."; loadAdminTables(); }
    catch{ st.textContent="Giriş başarısız."; }
  });
  if (sessionStorage.getItem("isAdminAuthenticated")==="true") loadAdminTables();

  $("#add-streamer-form")?.addEventListener("submit", async (e)=>{
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    const payload = Object.fromEntries(fd.entries());

    // hafif slugify + trim
    const rawSlug = (payload.slug || "").trim();
    payload.slug = rawSlug
      .normalize("NFD").replace(/[\u0300-\u036f]/g,"")
      .replace(/ı/g,"i").replace(/İ/g,"I").replace(/ş/g,"s").replace(/Ş/g,"S")
      .replace(/ğ/g,"g").replace(/Ğ/g,"G").replace(/ç/g,"c").replace(/Ç/g,"C")
      .replace(/ö/g,"o").replace(/Ö/g,"O").replace(/ü/g,"u").replace(/Ü/g,"U")
      .toLowerCase().replace(/[^a-z0-9._-]+/g,"-").replace(/^-+|-+$/g,"").replace(/-+/g,"-");

    payload.displayText = (payload.displayText || "").trim();

    try{
      await addStreamer({ ...payload, password: sessionStorage.getItem("adminPassword") || "" });
      showToast("Yayıncı eklendi", "success");
      e.currentTarget.reset();
      loadAdminTables();
    }catch(err){
      showToast(`Ekleme hatası: ${err.message || err}`, "error");
    }
  });

  document.getElementById("edit-cancel")?.addEventListener("click",()=>document.getElementById("edit-modal")?.classList.remove("show"));
  document.getElementById("edit-streamer-form")?.addEventListener("submit", async e=>{
    e.preventDefault();
    const fd=new FormData(e.currentTarget); const data=Object.fromEntries(fd.entries()); const slug=data.slug; delete data.slug;
    try{
      await fetchJSON(`${apiBase()}/api/streamers/${encodeURIComponent(slug)}`, {method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify({...data, password: sessionStorage.getItem("adminPassword")||""})});
      showToast("Güncellendi","success"); document.getElementById("edit-modal")?.classList.remove("show"); loadAdminTables();
    }catch{ showToast("Güncelleme hatası","error"); }
  });
}

async function loadAdminTables(){
  const wrap=$("#streamers-table"); wrap.innerHTML=""; let list=[]; try{ list=await listStreamers(); }catch{}
  if(!Array.isArray(list)||!list.length){ wrap.innerHTML=`<div class="subtitle">Kayıt yok</div>`; return; }
  list.forEach(it=>{
    const row=document.createElement("div"); row.className="glass-card"; row.style.cssText="border-radius:12px;padding:12px;margin-bottom:10px;";
    row.innerHTML=`
      <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;">
        <div style="display:flex;flex-direction:column;gap:4px;">
          <div style="font-weight:700">${it.displayText||it.slug}</div>
          <div class="subtitle" style="font-size:12px;">/${it.slug}</div>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;">
          <button class="btn btn-press btn-outline" data-edit="${it.slug}">Düzenle</button>
          <button class="btn btn-danger btn-press" data-del="${it.slug}">Sil</button>
        </div>
      </div>`;
    wrap.appendChild(row);

    row.querySelector(`[data-edit="${it.slug}"]`)?.addEventListener("click", ()=>{
      const m=$("#edit-modal"); m?.classList.add("show");
      const f=$("#edit-streamer-form");
      f.slug.value=it.slug; f.displayText.value=it.displayText||""; f.discordGuildId.value=it.discordGuildId||"";
      f.discordRoleId.value=it.discordRoleId||""; f.discordBotToken.value=it.discordBotToken||""; f.broadcaster_user_id.value=it.broadcaster_user_id||"";
    });
    row.querySelector(`[data-del="${it.slug}"]`)?.addEventListener("click", async ()=>{
      if(!confirm(`${it.slug} silinsin mi?`)) return;
      try{ await deleteStreamer(it.slug, sessionStorage.getItem("adminPassword")||""); showToast("Silindi","success"); loadAdminTables(); }
      catch{ showToast("Silme hatası","error"); }
    });
  });
}

/* ---------------- Boot ---------------- */
document.addEventListener("DOMContentLoaded", handleRouting);
