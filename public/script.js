/* ==========================================================
 * Frontend Script — UI'ya DOKUNMADAN akış
 * - Routing: /, /admin, /:slug (admin kısmı dokunulmadı)
 * - Zorunluluk: Kick + Discord login && Kick.subscribed === true -> ✓ Abone
 * - Debug: ?debug=1 ise method/expire + kick_viewer_id/kick_username/discord_user_id göster
 * ========================================================== */

const $  = (s, r=document) => r.querySelector(s);

/* ---------------- Toast ---------------- */
function showToast(msg,type="info",ms=2500){
  const t=$("#toast"); if(!t) return;
  t.textContent=msg;
  t.style.borderColor = type==="error" ? "rgba(239,68,68,0.5)" :
                        type==="success" ? "rgba(34,197,94,0.5)" : "rgba(255,255,255,0.2)";
  t.classList.add("show"); setTimeout(()=>t.classList.remove("show"), ms);
}

/* ---------------- API helpers ---------------- */
function apiBase(){ return location.origin; }
async function fetchJSON(url,opts){ const r=await fetch(url,opts); const txt=await r.text(); let j={}; try{ j=txt?JSON.parse(txt):{} }catch{} if(!r.ok) throw new Error(j?.error||txt||`HTTP ${r.status}`); return j; }
const getStreamer  = slug => fetchJSON(`${apiBase()}/api/streamers/${encodeURIComponent(slug)}`);

/* ---------------- Auth state ---------------- */
function defaultAuth(slug){ return { slug, kick:{linked:false, subscribed:false, method:"", expires_at:"", viewerId:"", username:""}, discord:{linked:false, userId:""}, ts:Date.now() }; }
function readAuth(slug){
  try{
    const raw=sessionStorage.getItem("auth") || localStorage.getItem("auth");
    if(!raw) return defaultAuth(slug);
    const a=JSON.parse(raw);
    if(a.slug!==slug) return defaultAuth(slug);
    a.kick ||= {linked:false, subscribed:false, method:"", expires_at:"", viewerId:"", username:""};
    a.discord ||= {linked:false, userId:""};
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

function setButtonsState(slug, auth){
  const kickBtn=$("#kick-login");
  const discBtn=$("#discord-login");

  // Discord: girişliyse gri
  if (discBtn){
    discBtn.onclick = () => {
      const u=new URL(`${apiBase()}/api/auth/redirect/discord`);
      u.searchParams.set("streamer", slug);
      location.href=u.toString();
    };
    if (auth.discord.linked){ discBtn.classList.add("disabled"); discBtn.setAttribute("disabled","disabled"); }
    else { discBtn.classList.remove("disabled"); discBtn.removeAttribute("disabled"); }
  }

  // Kick: girişliyse aynı buton "Çıkış Yap"
  if (kickBtn){
    // önce eski handler'ı sıfırlamak için klon tekniği
    const fresh=kickBtn.cloneNode(true); fresh.id="kick-login"; kickBtn.replaceWith(fresh);
    if (auth.kick.linked){
      fresh.textContent = "Çıkış Yap";
      fresh.onclick = (e)=>{ e.preventDefault(); clearAuth(); location.href=`/${slug}`; };
    } else {
      fresh.textContent = "Kick ile Giriş Yap";
      fresh.onclick = ()=>{ const u=new URL(`${apiBase()}/api/auth/redirect/kick`); u.searchParams.set("streamer", slug); location.href=u.toString(); };
    }
  }
}

/* ---------------- Channel page ---------------- */
async function initChannel(slug){
  // başlıklar
  try{
    const s=await getStreamer(slug);
    const t=$("#streamer-title"); if(t) t.textContent = s.displayText || s.title || slug;
    const st=$("#streamer-subtitle"); if(st) st.textContent= s.subtitle || "Aboneliğini doğrulamak için giriş yap.";
  }catch{
    const t=$("#streamer-title"); if(t) t.textContent = slug;
    const st=$("#streamer-subtitle"); if(st) st.textContent= "Yayıncı bulunamadı.";
    showToast("Yayıncı bulunamadı","error");
  }

  // callback paramları
  const url = new URL(location.href);
  const debugMode  = url.searchParams.get("debug")==="1";
  const provider   = url.searchParams.get("provider");
  const subscribed = url.searchParams.get("subscribed");
  const method     = url.searchParams.get("method") || "";
  const expires_at = url.searchParams.get("expires_at") || "";
  const kick_viewer_id = url.searchParams.get("kick_viewer_id") || "";
  const kick_username  = url.searchParams.get("kick_username") || "";
  const discord_user_id= url.searchParams.get("discord_user_id") || "";

  let auth = readAuth(slug);

  // gelen paramları merge et
  if (provider){
    if (provider==="kick"){
      auth.kick.linked = true;
      auth.kick.subscribed = (subscribed==="true");
      if (method)     auth.kick.method = method;
      if (expires_at) auth.kick.expires_at = expires_at;
      if (kick_viewer_id) auth.kick.viewerId = kick_viewer_id;
      if (kick_username)  auth.kick.username = kick_username;
    }
    if (provider==="discord"){
      auth.discord.linked = true;
      if (discord_user_id) auth.discord.userId = discord_user_id;
    }
    auth.ts = Date.now();
    writeAuth(auth);

    // debug değilse query temizle
    if (!debugMode){
      ["provider","subscribed","method","expires_at","kick_viewer_id","kick_username","discord_user_id"]
        .forEach(k=>url.searchParams.delete(k));
      history.replaceState({}, document.title, url.pathname + (url.search?url.search:"") + url.hash);
    }
  }

  // zorunluluk kuralı
  const bothLinked = auth.kick.linked && auth.discord.linked;
  const ok = bothLinked && auth.kick.subscribed===true;

  // rozet
  const status=$("#status-container");
  if (status) status.innerHTML = badge(ok);

  // debug bloğu (yalnızca ?debug=1)
  if (debugMode && status){
    const dbg=document.createElement("pre");
    dbg.style.cssText="text-align:left; white-space:pre-wrap; font-size:12px; opacity:.8; margin-top:8px;";
    dbg.textContent = `DEBUG:
provider=${provider}
subscribed=${subscribed}
method=${method}
expires_at=${expires_at}
kick_viewer_id=${kick_viewer_id || auth.kick.viewerId}
kick_username=${kick_username || auth.kick.username}
discord_user_id=${discord_user_id || auth.discord.userId}
auth=${JSON.stringify(auth,null,2)}`;
    status.appendChild(dbg);
  }

  // buton durumları
  setButtonsState(slug, auth);
}

/* ---------------- Routing (sadece channel’ı kullanıyoruz) ---------------- */
function currentSlug(){ const p=location.pathname.replace(/^\/+/, ""); const s=p.split("/")[0]||""; return s.toLowerCase()==="admin" ? "" : s; }
function handleRouting(){ const slug=currentSlug(); if(slug) initChannel(slug); }

document.addEventListener("DOMContentLoaded", handleRouting);
