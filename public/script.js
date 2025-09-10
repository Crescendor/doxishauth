/**
 * Front glue (UI'ya dokunmaz)
 * - Admin: şifre boşsa Kick ile girişe yönlendirir (/api/admin/redirect/kick)
 * - /admin?admin=1 geldiğinde paneli açar ve sessionStorage'a yazar
 * - /api/admin/check ile HttpOnly admin_auth çerezini de doğrular
 * - Streamer akışı ve abonelik göstergesi aynı kalır
 */
(function () {
  "use strict";
  const $ = (sel, root = document) => root.querySelector(sel);

  const apiBase = () => location.origin;
  const defaultBg = "url('https://i.ibb.co/7Nbkyyss/Untitled-design.png')";

  function showToast(msg, isError = false, ms = 2500) {
    const t = $("#toast"); if (!t) return;
    t.textContent = msg;
    t.className = `toast fixed bottom-5 right-5 text-white py-2 px-5 rounded-lg shadow-lg border ${isError ? 'bg-red-600/80 border-red-500' : 'bg-gray-800/80 border-gray-700'}`;
    void t.offsetWidth; t.classList.add("show");
    setTimeout(() => t.classList.remove("show"), ms);
  }

  async function fetchJSON(url, opts) {
    const r = await fetch(url, opts);
    const txt = await r.text();
    let j = {}; try { j = txt ? JSON.parse(txt) : {}; } catch {}
    if (!r.ok) throw new Error(j?.error || txt || `HTTP ${r.status}`);
    return j;
  }

  const getStreamer = (slug) => fetchJSON(`${apiBase()}/api/streamers/${encodeURIComponent(slug)}`);
  const listStreamers = () => fetchJSON(`${apiBase()}/api/streamers`);

  function defaultAuth(slug) {
    return { slug,
      kick:{ linked:false, subscribed:false, method:"", expires_at:"", viewerId:"", username:"" },
      discord:{ linked:false, userId:"" },
      ts: Date.now()
    };
  }
  function readAuth(slug){
    try{
      const raw = sessionStorage.getItem("auth") || localStorage.getItem("auth");
      if(!raw) return defaultAuth(slug);
      const a = JSON.parse(raw);
      if(a.slug !== slug) return defaultAuth(slug);
      a.kick ||= { linked:false, subscribed:false, method:"", expires_at:"", viewerId:"", username:"" };
      a.discord ||= { linked:false, userId:"" };
      return a;
    }catch{ return defaultAuth(slug); }
  }
  function writeAuth(a){ try{ sessionStorage.setItem("auth", JSON.stringify(a)); }catch{} }
  function clearAuth(){ try{ sessionStorage.removeItem("auth"); localStorage.removeItem("auth"); }catch{} }

  function badge(isSub){
    return isSub
      ? `<span class="status-badge status-badge-green">✓ Abone</span>`
      : `<span class="status-badge status-badge-red">X Abone Değil</span>`;
  }

  function wireLoginButtons(slug, auth){
    const d = $("#discord-login");
    if(d){
      const x=d.cloneNode(true); x.id="discord-login"; d.replaceWith(x);
      x.addEventListener("click", (e)=>{ e.preventDefault(); location.href=`/api/auth/redirect/discord?streamer=${slug}`; });
      if(auth.discord.linked){ x.classList.add("disabled"); x.setAttribute("disabled","disabled"); }
      else { x.classList.remove("disabled"); x.removeAttribute("disabled"); }
    }
    const k = $("#kick-login");
    if(k){
      const x=k.cloneNode(true); x.id="kick-login"; k.replaceWith(x);
      if(auth.kick.linked){
        x.textContent = "Çıkış Yap";
        x.addEventListener("click",(e)=>{ e.preventDefault(); clearAuth(); location.href=`/${slug}`; });
      } else {
        x.textContent = "Kick ile Giriş Yap";
        x.addEventListener("click",(e)=>{ e.preventDefault(); location.href=`/api/auth/redirect/kick?streamer=${slug}`; });
      }
    }
  }

  async function mountStreamerPage(slug){
    try{
      const s=await getStreamer(slug);
      const title=$("#streamer-title"); if(title) title.textContent = s.title || s.displayText || slug;
      const sub=$("#streamer-subtitle"); if(sub) sub.textContent = s.subtitle || "Aboneliğini doğrulamak için giriş yap.";
      document.body.style.backgroundImage = s.customBackgroundUrl ? `url('${s.customBackgroundUrl}')` : defaultBg;
    }catch{
      const title=$("#streamer-title"); if(title) title.textContent = slug;
      const sub=$("#streamer-subtitle"); if(sub) sub.textContent = "Yayıncı bulunamadı.";
      document.body.style.backgroundImage = defaultBg;
      showToast("Yayıncı bulunamadı", true);
    }

    const url = new URL(location.href);
    const debugMode  = url.searchParams.get("debug")==="1";
    const provider   = url.searchParams.get("provider");
    const subscribed = url.searchParams.get("subscribed");
    const method     = url.searchParams.get("method") || "";
    const expires_at = url.searchParams.get("expires_at") || "";
    const kick_viewer_id = url.searchParams.get("kick_viewer_id") || "";
    const kick_username  = url.searchParams.get("kick_username") || "";
    const discord_user_id= url.searchParams.get("discord_user_id") || "";

    let auth=readAuth(slug);
    if(provider){
      if(provider==="kick"){
        auth.kick.linked = true;
        auth.kick.subscribed = (subscribed==="true");
        if(method) auth.kick.method = method;
        if(expires_at) auth.kick.expires_at = expires_at;
        if(kick_viewer_id) auth.kick.viewerId = kick_viewer_id;
        if(kick_username)  auth.kick.username = kick_username;
      } else if(provider==="discord"){
        auth.discord.linked = true;
        if(discord_user_id) auth.discord.userId = discord_user_id;
      }
      auth.ts = Date.now();
      writeAuth(auth);

      if(!debugMode){
        ["provider","subscribed","method","expires_at","kick_viewer_id","kick_username","discord_user_id"]
          .forEach((k)=>url.searchParams.delete(k));
        try{ history.replaceState({}, document.title, url.pathname + (url.search?("?"+url.searchParams.toString()):"") + url.hash); }catch{}
      }
    }

    const bothLinked = auth.kick.linked && auth.discord.linked;
    const ok = bothLinked && auth.kick.subscribed===true;

    const status=$("#status-container");
    if(status) status.innerHTML = badge(ok);

    if(debugMode && status){
      const dbg=document.createElement("pre");
      dbg.style.cssText="text-align:left; white-space:pre-wrap; font-size:12px; opacity:.8; margin-top:8px;";
      dbg.textContent = `DEBUG:
method=${method || auth.kick.method}
expires_at=${expires_at || auth.kick.expires_at}
kick_viewer_id=${kick_viewer_id || auth.kick.viewerId}
kick_username=${kick_username || auth.kick.username}
discord_user_id=${discord_user_id || auth.discord.userId}
auth=${JSON.stringify(auth,null,2)}`;
      status.appendChild(dbg);
    }

    wireLoginButtons(slug, auth);
  }

  /* ---- Admin helpers ---- */
  async function adminCheckAndShow(){
    const pages = {
      home: $("#home-page"),
      content: $("#content-page"),
      streamer: $("#streamer-card"),
      admin: $("#admin-card"),
      adminLogin: $("#admin-login-page"),
      adminPanel: $("#admin-panel-page"),
    };
    const showPage = (name)=>{
      if(!pages.home || !pages.content || !pages.streamer || !pages.admin) return;
      Object.values(pages).forEach(p => p && p.classList && p.classList.remove('active'));
      if(name==="home"){ pages.home.classList.add('active'); return; }
      pages.content.classList.add('active');
      pages.streamer.style.display = 'none';
      pages.admin.style.display = 'block';
      pages.adminLogin && (pages.adminLogin.style.display = name==="adminLogin" ? 'flex':'none');
      pages.adminPanel && (pages.adminPanel.style.display = name==="adminPanel" ? 'flex':'none');
    };

    // URL paramından gelen admin=1 ise sessionStorage’a yaz ve paramı temizle
    const u = new URL(location.href);
    const adminParam = u.searchParams.get("admin");
    if(adminParam === "1"){
      sessionStorage.setItem("isAdminAuthenticated","true");
      // temizle (kick_username vs kalsın istersen kalsın, ama sadeleştirelim):
      ["admin"].forEach(k=>u.searchParams.delete(k));
      try{ history.replaceState({}, document.title, u.pathname + (u.search?("?"+u.searchParams.toString()):"") + u.hash); }catch{}
    }

    // Çerez tabanlı admin kontrolü (backend doğrusu)
    try{
      const chk = await fetchJSON(`/api/admin/check`);
      if(chk.authenticated) sessionStorage.setItem("isAdminAuthenticated","true");
    }catch{}

    if(sessionStorage.getItem("isAdminAuthenticated")){
      showPage("adminPanel");
      // Listeyi yükleyen mevcut fonksiyonun varsa tetikle:
      const btn = $("#refresh-list-btn"); btn && btn.click();
    } else {
      showPage("adminLogin");
    }
  }

  async function handleRouting(){
    const path = location.pathname.replace(/^\/+/, "");
    if(path.toLowerCase()==="admin"){
      document.body.style.backgroundImage = defaultBg;
      await adminCheckAndShow();
      return;
    }

    if(path){
      try{
        const r = await fetch(`/api/streamers/${path}`);
        if(!r.ok){
          showToast(`'${path}' adlı yayıncı bulunamadı.`, true);
          document.body.style.backgroundImage = defaultBg;
          const home=$("#home-page"), content=$("#content-page"); if(home && content){ content.classList.remove("active"); home.classList.add("active"); }
          history.replaceState({}, document.title, `/`);
          return;
        }
        const s = await r.json();
        $("#streamer-title") && ($("#streamer-title").textContent = s.title || s.displayText || path);
        $("#streamer-subtitle") && ($("#streamer-subtitle").textContent = s.subtitle || "Aboneliğini doğrulamak için giriş yap.");
        document.body.style.backgroundImage = s.customBackgroundUrl ? `url('${s.customBackgroundUrl}')` : defaultBg;

        const home=$("#home-page"), content=$("#content-page"), streamer=$("#streamer-card"), admin=$("#admin-card");
        if(home && content && streamer && admin){
          home.classList.remove("active");
          content.classList.add("active");
          streamer.style.display = 'block';
          admin.style.display = 'none';
        }

        await mountStreamerPage(path);
      }catch(err){
        console.error("Yayıncı sayfası hata:", err);
        document.body.style.backgroundImage = defaultBg;
        const home=$("#home-page"), content=$("#content-page"); if(home && content){ content.classList.remove("active"); home.classList.add("active"); }
      }
    } else {
      document.body.style.backgroundImage = defaultBg;
      const home=$("#home-page"), content=$("#content-page"); if(home && content){ content.classList.add("active"); home.classList.remove("active"); }
    }
  }

  document.addEventListener("DOMContentLoaded", ()=>{
    // Admin login form: şifre boşsa Kick OAuth’a yönlendir
    $("#admin-login-form")?.addEventListener("submit", async (e)=>{
      e.preventDefault();
      const pwd = $("#admin-password")?.value || "";
      if(pwd.trim()===""){
        location.href = "/api/admin/redirect/kick";
        return;
      }
      try{
        const r = await fetch(`/api/login`, { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ password: pwd }) });
        if(r.ok){
          sessionStorage.setItem("isAdminAuthenticated","true");
          location.pathname="/admin";
        } else {
          showToast("Hatalı şifre!", true);
        }
      }catch{ showToast("Giriş sırasında bir hata oluştu.", true); }
    });

    // Eğer index'te ayrı bir buton koyduysan:
    $("#admin-kick-login")?.addEventListener("click", (e)=>{ e.preventDefault(); location.href="/api/admin/redirect/kick"; });

    // Admin logout hem çerezi hem session'ı temizler
    $("#logout-btn")?.addEventListener("click", async ()=>{
      try{ await fetch(`/api/admin/logout`, { method:"POST" }); }catch{}
      sessionStorage.clear(); location.pathname="/";
    });

    handleRouting();
  });

  window.addEventListener("error", e => console.error("JS error:", e?.error||e?.message||e));
  window.addEventListener("unhandledrejection", e => console.error("Promise rejection:", e?.reason||e));
})();
