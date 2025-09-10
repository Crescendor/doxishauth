/**
 * Admin sadece Kick ile giriş (şifresiz)
 * - /admin sayfasında admin_auth yoksa otomatik Kick OAuth’a gönderir.
 * - Yine de görünür bir "Kick ile Giriş Yap" butonu istersen,
 *   admin-login bölümüne non-intrusive olarak enjekte eder (mevcut buton stilini kopyalar).
 * - Yayıncı sayfası akışı, abonelik rozeti, çıkış butonu ve çift giriş şartı (Kick+Discord) korunur.
 */

(function () {
  "use strict";

  const $ = (sel, root = document) => root.querySelector(sel);
  const apiBase = () => location.origin;
  const defaultBg = "url('https://i.ibb.co/7Nbkyyss/Untitled-design.png')";

  function showToast(msg, isError = false, ms = 2500) {
    const t = $("#toast");
    if (!t) return;
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

  function defaultAuth(slug) {
    return {
      slug,
      kick: { linked:false, subscribed:false, method:"", expires_at:"", viewerId:"", username:"" },
      discord: { linked:false, userId:"" },
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
    // Discord login
    const d = $("#discord-login");
    if(d){
      const x=d.cloneNode(true); x.id="discord-login"; d.replaceWith(x);
      x.addEventListener("click", (e)=>{ e.preventDefault(); location.href=`/api/auth/redirect/discord?streamer=${slug}`; });
      if(auth.discord.linked){ x.classList.add("disabled"); x.setAttribute("disabled","disabled"); }
      else { x.classList.remove("disabled"); x.removeAttribute("disabled"); }
    }

    // Kick login (yayıncı sayfası, kullanıcı oturumu)
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
      $("#streamer-title") && ($("#streamer-title").textContent = s.title || s.displayText || slug);
      $("#streamer-subtitle") && ($("#streamer-subtitle").textContent = s.subtitle || "Aboneliğini doğrulamak için giriş yap.");
      document.body.style.backgroundImage = s.customBackgroundUrl ? `url('${s.customBackgroundUrl}')` : defaultBg;
    }catch{
      $("#streamer-title") && ($("#streamer-title").textContent = slug);
      $("#streamer-subtitle") && ($("#streamer-subtitle").textContent = "Yayıncı bulunamadı.");
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

    // Çift giriş şartı: Kick + Discord
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

    // /yayıncı sayfasında sağ-üst "Çıkış Yap" (Kick oturumu kapatır, UI tasarımına dokunmadan)
    const logout = $("#logout-btn");
    if(logout){
      const l = logout.cloneNode(true); l.id="logout-btn"; logout.replaceWith(l);
      l.addEventListener("click", (e)=>{ e.preventDefault(); clearAuth(); location.href=`/${slug}`; });
    }
  }

  /* ------------ Admin only Kick flow ------------- */
  async function ensureAdminAuthUI(){
    // Mevcut sayfa parçaları (tasarıma dokunmuyoruz)
    const pages = {
      home: $("#home-page"),
      content: $("#content-page"),
      streamer: $("#streamer-card"),
      admin: $("#admin-card"),
      adminLogin: $("#admin-login-page"),
      adminPanel: $("#admin-panel-page"),
    };
    const showAdminPage = (name)=>{
      if(!pages.home || !pages.content || !pages.streamer || !pages.admin) return;
      Object.values(pages).forEach(p => p && p.classList && p.classList.remove('active'));
      pages.content.classList.add('active');
      pages.streamer && (pages.streamer.style.display = 'none');
      pages.admin && (pages.admin.style.display = 'block');
      pages.adminLogin && (pages.adminLogin.style.display = name==="adminLogin" ? 'flex':'none');
      pages.adminPanel && (pages.adminPanel.style.display = name==="adminPanel" ? 'flex':'none');
    };

    // Sunucudan gerçek oturum kontrolü (HttpOnly cookie)
    let authenticated = false, user = null;
    try{
      const chk = await fetchJSON(`/api/admin/check`);
      authenticated = !!chk.authenticated;
      user = chk.user || null;
    }catch{}

    if(authenticated){
      showAdminPage("adminPanel");
      // varsa mevcut “listeyi yenile” butonunu tetikle
      $("#refresh-list-btn")?.click();
      return;
    }

    // Oturum yoksa: 1) admin-login sayfasını göster
    showAdminPage("adminLogin");

    // 2) Görünür bir “Kick ile Giriş Yap” butonu yoksa nazikçe enjekte et
    if(!$("#admin-kick-login")){
      const host = $("#admin-login-page") || pages.adminLogin || pages.admin;
      if(host){
        // Stil bozmayalım: varsa yayıncı sayfasındaki Kick butonunun class'ını klonla
        const sampleBtn = $("#kick-login") || $("#discord-login") || $("#some-existing-btn");
        const btn = document.createElement("button");
        btn.id = "admin-kick-login";
        btn.type = "button";
        btn.textContent = "Kick ile Giriş Yap";
        if(sampleBtn){
          btn.className = sampleBtn.className; // mevcut buton stilini kopyala
        } else {
          // En minimal stiller (tasarımı bozmasın diye nötr)
          btn.style.cssText = "padding:10px 16px;border-radius:8px;border:1px solid rgba(255,255,255,.2);background:rgba(0,0,0,.4);color:#fff;cursor:pointer;";
        }
        host.appendChild(btn);
      }
    }

    // 3) Butona tıklayınca direkt Kick OAuth
    $("#admin-kick-login")?.addEventListener("click", (e)=>{
      e.preventDefault(); location.href = "/api/admin/redirect/kick";
    });

    // 4) İstersen hiç buton göstermeden de otomatik yönlendirebilirim:
    //    Auto-redirect (yorumdan çıkarırsan /admin'e gelince direkt Kick sayfasına gider)
    // location.href = "/api/admin/redirect/kick";
  }

  /* ------------- Router -------------- */
  async function handleRouting(){
    const path = location.pathname.replace(/^\/+/, "");
    if(path.toLowerCase()==="admin"){
      document.body.style.backgroundImage = defaultBg;
      await ensureAdminAuthUI();
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
    // Admin logout -> hem çerez hem session temizliği (UI tasarımına dokunmadan)
    $("#logout-btn")?.addEventListener("click", async ()=>{
      try{ await fetch(`/api/admin/logout`, { method:"POST" }); }catch{}
      sessionStorage.clear(); location.pathname="/";
    });

    handleRouting();
  });

  window.addEventListener("error", e => console.error("JS error:", e?.error||e?.message||e));
  window.addEventListener("unhandledrejection", e => console.error("Promise rejection:", e?.reason||e));
})();
