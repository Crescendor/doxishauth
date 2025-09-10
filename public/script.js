/* ==========================================================
 * Frontend Script — UI'ya DOKUNMADAN akış
 * - Routing: /, /admin, /:slug
 * - Zorunluluk: Kick + Discord login && Kick.subscribed === true -> ✓ Abone
 * - Debug: URL'e ?debug=1 eklersen provider/subscribed paramları temizlenmez
 * ========================================================== */

const $  = (s, r=document) => r.querySelector(s);
const $$ = (s, r=document) => Array.from(r.querySelectorAll(s));

/* ---------------- Small utils ---------------- */
function showToast(msg,type="info",ms=2500){
  const t=$("#toast"); if(!t) return;
  t.textContent=msg;
  t.style.borderColor = type==="error" ? "rgba(239,68,68,0.5)" :
                        type==="success" ? "rgba(34,197,94,0.5)" : "rgba(255,255,255,0.2)";
  t.classList.add("show"); setTimeout(()=>t.classList.remove("show"), ms);
}
function apiBase(){ return location.origin; }
function currentSlug(){
  const p=location.pathname.replace(/^\/+/, "");
  const s=p.split("/")[0]||"";
  return s.toLowerCase()==="admin" ? "" : s; // admin ayrı ele alınıyor
}
function isAdminPath(){ return location.pathname.replace(/^\/+/, "").split("/")[0]==="admin"; }

function activate(el){ if(!el) return; el.classList.add("active"); el.style.display="flex"; }
function deactivate(el){ if(!el) return; el.classList.remove("active"); el.style.display="none"; }

/* ---------------- API helpers ---------------- */
async function fetchJSON(url,opts){
  const r=await fetch(url,opts);
  const txt=await r.text();
  let j={}; try{ j=txt?JSON.parse(txt):{} }catch{ /* ignore */ }
  if(!r.ok) throw new Error(j?.error || txt || `HTTP ${r.status}`);
  return j;
}
const listStreamers = ()=> fetchJSON(`${apiBase()}/api/streamers`);
const getStreamer  = slug => fetchJSON(`${apiBase()}/api/streamers/${encodeURIComponent(slug)}`);
const addStreamer  = payload => fetchJSON(`${apiBase()}/api/streamers`, {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
const updateStreamer = (slug, payload) => fetchJSON(`${apiBase()}/api/streamers/${encodeURIComponent(slug)}`, {method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
const deleteStreamer = (slug,password) => fetchJSON(`${apiBase()}/api/streamers/${encodeURIComponent(slug)}`, {method:"DELETE",headers:{"Content-Type":"application/json"},body:JSON.stringify({password})});
const adminLogin = password => fetchJSON(`${apiBase()}/api/login`, {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({password})});

/* ---------------- Auth state (stored per slug) ---------------- */
function defaultAuth(slug){ return { slug, kick:{linked:false, subscribed:false}, discord:{linked:false}, ts:Date.now() }; }
function readAuth(slug){
  try{
    const raw=sessionStorage.getItem("auth") || localStorage.getItem("auth");
    if(!raw) return defaultAuth(slug);
    const a=JSON.parse(raw);
    if(a.slug!==slug) return defaultAuth(slug);
    a.kick ||= {linked:false, subscribed:false};
    a.discord ||= {linked:false};
    return a;
  }catch{ return defaultAuth(slug); }
}
function writeAuth(a){ try{ sessionStorage.setItem("auth", JSON.stringify(a)); }catch{} }
function clearAuth(){ try{ sessionStorage.removeItem("auth"); localStorage.removeItem("auth"); }catch{} }

/* ---------------- Badges & buttons ---------------- */
function badge(ok){
  return ok
    ? `<span class="status-badge status-badge-green">✓ Abone</span>`
    : `<span class="status-badge status-badge-red">X Abone Değil</span>`;
}

function wireButtonsForChannel(slug, auth){
  const kickBtn=$("#kick-login");
  const discBtn=$("#discord-login");

  // Discord login butonu: girişliyse gri
  if (discBtn){
    discBtn.onclick = () => {
      const u=new URL(`${apiBase()}/api/auth/redirect/discord`);
      u.searchParams.set("streamer", slug);
      location.href=u.toString();
    };
    if (auth.discord.linked){ discBtn.classList.add("disabled"); discBtn.setAttribute("disabled","disabled"); }
    else { discBtn.classList.remove("disabled"); discBtn.removeAttribute("disabled"); }
  }

  // Kick butonu: login olduysa aynı buton "Çıkış Yap"
  if (kickBtn){
    if (auth.kick.linked){
      kickBtn.textContent = "Çıkış Yap";
      kickBtn.onclick = (e)=>{ e.preventDefault(); clearAuth(); location.href=`/${slug}`; };
    } else {
      kickBtn.textContent = "Kick ile Giriş Yap";
      kickBtn.onclick = () => {
        const u=new URL(`${apiBase()}/api/auth/redirect/kick`);
        u.searchParams.set("streamer", slug);
        location.href=u.toString();
      };
    }
  }
}

/* ---------------- Channel page flow ---------------- */
async function initChannel(slug){
  // sayfaları konumlandır
  deactivate($("#home-page"));
  activate($("#content-page"));
  $("#admin-card").style.display="none";
  $("#streamer-card").style.display="block";

  // başlıkları getir
  try{
    const s=await getStreamer(slug);
    $("#streamer-title").textContent   = s.displayText || s.title || slug;
    $("#streamer-subtitle").textContent= s.subtitle || "Aboneliğini doğrulamak için giriş yap.";
  }catch{
    $("#streamer-title").textContent   = slug;
    $("#streamer-subtitle").textContent= "Yayıncı bulunamadı.";
    showToast("Yayıncı bulunamadı","error");
  }

  // callback paramlarını işle
  const url = new URL(location.href);
  const provider   = url.searchParams.get("provider");
  const subscribed = url.searchParams.get("subscribed");
  const debugMode  = url.searchParams.get("debug")==="1";

  let auth = readAuth(slug);

  if (provider){
    if (provider==="kick"){ auth.kick.linked=true; auth.kick.subscribed=(subscribed==="true"); }
    if (provider==="discord"){ auth.discord.linked=true; }
    auth.ts=Date.now();
    writeAuth(auth);

    // debug değilse paramları temizle
    if (!debugMode){
      url.searchParams.delete("provider");
      url.searchParams.delete("subscribed");
      url.searchParams.delete("method");
      url.searchParams.delete("expires_at");
      history.replaceState({}, document.title, url.pathname + (url.search?url.search:"") + url.hash);
    }
  }

  // zorunluluk kuralı
  const bothLinked = auth.kick.linked && auth.discord.linked;
  const ok = bothLinked && auth.kick.subscribed===true;

  // rozet
  const status=$("#status-container");
  status.innerHTML = badge(ok);

  // debug görünürse ham paramları da göster
  if (debugMode){
    const dbg=document.createElement("pre");
    dbg.style.cssText="text-align:left; white-space:pre-wrap; font-size:12px; opacity:.8;";
    dbg.textContent = `DEBUG:
provider=${provider}
subscribed=${subscribed}
auth=${JSON.stringify(auth,null,2)}`;
    status.appendChild(dbg);
  }

  // buton davranışları
  wireButtonsForChannel(slug, auth);
}

/* ---------------- Admin page flow ---------------- */
function initAdmin(){
  deactivate($("#home-page"));
  activate($("#content-page"));
  $("#streamer-card").style.display="none";
  $("#admin-card").style.display="block";

  const isAuthed = sessionStorage.getItem("isAdminAuthenticated")==="true";
  if (isAuthed){ activate($("#admin-panel-page")); deactivate($("#admin-login-page")); loadAdmin(); }
  else { activate($("#admin-login-page")); deactivate($("#admin-panel-page")); }

  // admin login
  $("#admin-login-form")?.addEventListener("submit", async (e)=>{
    e.preventDefault();
    const pass=$("#admin-password-input").value.trim();
    try{
      await adminLogin(pass);
      sessionStorage.setItem("isAdminAuthenticated","true");
      sessionStorage.setItem("adminPassword", pass);
      activate($("#admin-panel-page")); deactivate($("#admin-login-page"));
      loadAdmin();
    }catch(err){ showToast(`Giriş başarısız: ${err.message||err}`,"error"); }
  });

  // admin logout
  $("#logout-btn")?.addEventListener("click", ()=>{
    sessionStorage.removeItem("isAdminAuthenticated");
    sessionStorage.removeItem("adminPassword");
    activate($("#admin-login-page")); deactivate($("#admin-panel-page"));
  });

  // ekleme formu
  $("#add-streamer-form")?.addEventListener("submit", async (e)=>{
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    const data = Object.fromEntries(fd.entries());

    // slugify + mapping: title -> displayText
    const slug = (data.slug||"").trim()
      .normalize("NFD").replace(/[\u0300-\u036f]/g,"")
      .replace(/ı/g,"i").replace(/İ/g,"I").replace(/ş/g,"s").replace(/Ş/g,"S")
      .replace(/ğ/g,"g").replace(/Ğ/g,"G").replace(/ç/g,"c").replace(/Ç/g,"C")
      .replace(/ö/g,"o").replace(/Ö/g,"O").replace(/ü/g,"u").replace(/Ü/g,"U")
      .toLowerCase().replace(/[^a-z0-9._-]+/g,"-").replace(/^-+|-+$/g,"").replace(/-+/g,"-");

    const payload = {
      slug,
      displayText: (data.title||"").trim(),
      // backend ekstra alanları opsiyonel görür, gönderirsek sorun olmaz:
      subtitle: (data.subtitle||"").trim(),
      customBackgroundUrl: (data.customBackgroundUrl||"").trim(),
      botghostWebhookUrl: (data.botghostWebhookUrl||"").trim(),
      password: sessionStorage.getItem("adminPassword") || ""
    };

    if (!payload.slug || !payload.displayText){
      showToast("Slug ve Başlık zorunlu","error"); return;
    }

    try{
      await addStreamer(payload);
      showToast("Yayıncı eklendi","success");
      e.currentTarget.reset();
      await loadAdmin();
    }catch(err){ showToast(`Ekleme hatası: ${err.message||err}`,"error"); }
  });

  $("#refresh-list-btn")?.addEventListener("click", loadAdmin);

  // modal cancel
  $("#cancel-edit-btn")?.addEventListener("click", ()=> $("#edit-modal")?.classList.remove("active"));

  // edit submit
  $("#edit-streamer-form")?.addEventListener("submit", async (e)=>{
    e.preventDefault();
    const fd=new FormData(e.currentTarget); const data=Object.fromEntries(fd.entries());
    const slug=data.slug; delete data.slug;

    const payload = {
      displayText: (data.title||"").trim(),
      subtitle: (data.subtitle||"").trim(),
      customBackgroundUrl: (data.customBackgroundUrl||"").trim(),
      botghostWebhookUrl: (data.botghostWebhookUrl||"").trim(),
      password: sessionStorage.getItem("adminPassword") || ""
    };

    try{
      await updateStreamer(slug, payload);
      showToast("Güncellendi","success");
      $("#edit-modal")?.classList.remove("active");
      await loadAdmin();
    }catch(err){ showToast(`Güncelleme hatası: ${err.message||err}`,"error"); }
  });
}

async function loadAdmin(){
  const listBox=$("#streamer-list-container"); listBox.innerHTML="";
  let list=[]; try{ list=await listStreamers(); }catch{}
  if(!Array.isArray(list)||!list.length){
    listBox.innerHTML = `<div class="text-gray-400 text-sm">Kayıt yok</div>`; return;
  }
  list.forEach(it=>{
    const row=document.createElement("div");
    row.className="glass-card rounded-xl p-4";
    row.innerHTML=`
      <div class="flex items-center justify-between gap-3">
        <div>
          <div class="font-bold text-white">${it.displayText||it.title||it.slug}</div>
          <div class="text-xs text-gray-400">/${it.slug}</div>
        </div>
        <div class="flex gap-2">
          <a class="bg-green-600/70 hover:bg-green-600 text-white text-sm font-bold py-2 px-3 rounded-lg btn-press" href="/${it.slug}">Git</a>
          <button class="bg-gray-600/50 hover:bg-gray-600/80 text-white text-sm font-bold py-2 px-3 rounded-lg btn-press" data-edit="${it.slug}">Düzenle</button>
          <button class="bg-red-600 hover:bg-red-700 text-white text-sm font-bold py-2 px-3 rounded-lg btn-press" data-del="${it.slug}">Sil</button>
        </div>
      </div>`;
    listBox.appendChild(row);

    row.querySelector(`[data-edit="${it.slug}"]`)?.addEventListener("click", ()=>{
      const m=$("#edit-modal"); m?.classList.add("active");
      const f=$("#edit-streamer-form");
      f.slug.value=it.slug;
      f.title.value=it.displayText||it.title||"";
      f.subtitle.value=it.subtitle||"";
      f.customBackgroundUrl.value=it.customBackgroundUrl||"";
      f.botghostWebhookUrl.value=it.botghostWebhookUrl||"";
    });
    row.querySelector(`[data-del="${it.slug}"]`)?.addEventListener("click", async ()=>{
      if(!confirm(`${it.slug} silinsin mi?`)) return;
      try{
        await deleteStreamer(it.slug, sessionStorage.getItem("adminPassword")||"");
        showToast("Silindi","success"); await loadAdmin();
      }catch(err){ showToast(`Silme hatası: ${err.message||err}`,"error"); }
    });
  });
}

/* ---------------- Router ---------------- */
function handleRouting(){
  if (isAdminPath()){ initAdmin(); return; }
  const slug=currentSlug();
  if (slug){ initChannel(slug); }
  else {
    // Ana sayfa
    activate($("#home-page"));
    deactivate($("#content-page"));
  }
}

/* ---------------- Boot ---------------- */
document.addEventListener("DOMContentLoaded", handleRouting);
