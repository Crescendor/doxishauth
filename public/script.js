/**
 * Frontend glue – minimal, UI’ya dokunmaz.
 * - Element yoksa no-op; boş ekran yaratmaz.
 * - Kick & Discord OAuth callback param'larını okur, state'e yazar.
 * - ?debug=1 iken status alanına debug info basar:
 *    method, expires_at, kick_viewer_id, kick_username, discord_user_id
 * - Admin panel form’ları: slug + title/subtitle/customBackgroundUrl... gönderir.
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
    // Arkaplan + başlıklar
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

    // Callback paramları
    const url = new URL(location.href);
    const debugMode  = url.searchParams.get("debug")==="1";
    const provider   = url.searchParams.get("provider");
    const subscribed = url.searchParams.get("subscribed");
    const method     = url.searchParams.get("method") || "";
    const expires_at = url.searchParams.get("expires_at") || "";
    const kick_viewer_id = url.searchParams.get("kick_viewer_id") || "";
    const kick_username  = url.searchParams.get("kick_username") || "";
    const discord_user_id= url.searchParams.get("discord_user_id") || "";

    // Auth merge
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

      // debug yoksa query’yi temizle
      if(!debugMode){
        ["provider","subscribed","method","expires_at","kick_viewer_id","kick_username","discord_user_id"]
          .forEach((k)=>url.searchParams.delete(k));
        try{ history.replaceState({}, document.title, url.pathname + (url.search?("?"+url.searchParams.toString()):"") + url.hash); }catch{}
      }
    }

    // Kural: Kick + Discord linked && Kick.subscribed === true → ✓ Abone
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

  /* ---- Routing (boş ekranı önlemek için ultra güvenli) ---- */
  function currentPathSlug(){
    try{
      const p = location.pathname.replace(/^\/+/, "");
      const s = p.split("/")[0] || "";
      return s.toLowerCase()==="admin" ? "" : s;
    }catch{ return ""; }
  }

  async function handleRouting(){
    // Sayfa bölümleri varsa kullan; yoksa no-op
    const pages = {
      home: $("#home-page"),
      content: $("#content-page"),
      streamer: $("#streamer-card"),
      admin: $("#admin-card"),
      adminLogin: $("#admin-login-page"),
      adminPanel: $("#admin-panel-page"),
    };
    const showPage = (name)=>{
      if(!pages.home || !pages.content || !pages.streamer || !pages.admin) return; // UI yoksa no-op
      Object.values(pages).forEach(p => p && p.classList && p.classList.remove('active'));
      if(name==="home"){ pages.home.classList.add('active'); return; }
      pages.content.classList.add('active');
      pages.streamer.style.display = 'none';
      pages.admin.style.display = 'none';
      if(name==="streamer"){ pages.streamer.style.display = 'block'; }
      else if(name.startsWith('admin')){
        pages.admin.style.display = 'block';
        pages.adminLogin && (pages.adminLogin.style.display = name==="adminLogin" ? 'flex':'none');
        pages.adminPanel && (pages.adminPanel.style.display = name==="adminPanel" ? 'flex':'none');
      }
    };

    const path = location.pathname.replace(/^\/+/, "");
    if(path.toLowerCase()==="admin"){
      document.body.style.backgroundImage = defaultBg;
      if(sessionStorage.getItem("isAdminAuthenticated")){ showPage("adminPanel"); await loadAdminPanel(); }
      else { showPage("adminLogin"); }
      return;
    }

    if(path){
      // /:slug
      try{
        const r = await fetch(`/api/streamers/${path}`);
        if(!r.ok){
          showToast(`'${path}' adlı yayıncı bulunamadı.`, true);
          document.body.style.backgroundImage = defaultBg;
          showPage("home");
          history.replaceState({}, document.title, `/`);
          return;
        }
        const s = await r.json();
        $("#streamer-title") && ($("#streamer-title").textContent = s.title || s.displayText || path);
        $("#streamer-subtitle") && ($("#streamer-subtitle").textContent = s.subtitle || "Aboneliğini doğrulamak için giriş yap.");
        document.body.style.backgroundImage = s.customBackgroundUrl ? `url('${s.customBackgroundUrl}')` : defaultBg;
        showPage("streamer");
        await mountStreamerPage(path);
      }catch(err){
        console.error("Yayıncı sayfası hata:", err);
        document.body.style.backgroundImage = defaultBg;
        showPage("home");
      }
    } else {
      // home
      document.body.style.backgroundImage = defaultBg;
      showPage("home");
    }
  }

  /* ---- Admin: login + CRUD (field adları backend ile uyumlu) ---- */
  document.addEventListener("DOMContentLoaded", ()=>{
    // Login
    $("#admin-login-form")?.addEventListener("submit", async (e)=>{
      e.preventDefault();
      const pwd = $("#admin-password")?.value || "";
      try{
        const r = await fetch(`/api/login`, { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ password: pwd }) });
        if(r.ok){ sessionStorage.setItem("isAdminAuthenticated","true"); sessionStorage.setItem("adminPassword", pwd); location.pathname="/admin"; }
        else showToast("Hatalı şifre!", true);
      }catch{ showToast("Giriş sırasında bir hata oluştu.", true); }
    });

    $("#logout-btn")?.addEventListener("click", ()=>{
      sessionStorage.clear(); location.pathname="/";
    });

    $("#refresh-list-btn")?.addEventListener("click", ()=>{
      showToast("Liste yenileniyor..."); loadAdminPanel();
    });

    async function loadAdminPanel(){
      const list = $("#streamer-list-container");
      if(!list) return;
      list.innerHTML = '<div class="loader mx-auto"></div>';
      try{
        const items = await listStreamers();
        if(!Array.isArray(items) || !items.length){ list.innerHTML = '<div class="text-gray-400 text-center">Kayıt yok.</div>'; return; }
        list.innerHTML = items.map(it=>`
          <div class="glass-card p-4 rounded-xl flex justify-between items-center">
            <div class="text-white">
              <div class="font-semibold">${it.slug}</div>
              <div class="text-sm text-gray-400">${it.title || it.displayText || ''}</div>
            </div>
            <div class="flex gap-2">
              <button class="edit-btn bg-gray-700 hover:bg-gray-600 text-white py-2 px-3 rounded-lg btn-press" data-slug="${it.slug}">Düzenle</button>
              <button class="del-btn bg-red-600/80 hover:bg-red-600 text-white py-2 px-3 rounded-lg btn-press" data-slug="${it.slug}">Sil</button>
            </div>
          </div>
        `).join("");

        // edit/delete bind
        list.querySelectorAll(".del-btn").forEach(btn=>{
          btn.addEventListener("click", async ()=>{
            const slug = btn.getAttribute("data-slug");
            if(!confirm(`${slug} silinsin mi?`)) return;
            const r = await fetch(`/api/streamers/${slug}`, {
              method:"DELETE",
              headers:{ "Content-Type":"application/json" },
              body: JSON.stringify({ password: sessionStorage.getItem("adminPassword")||"" })
            });
            if(r.ok){ showToast("Silindi"); loadAdminPanel(); } else { const txt=await r.text(); showToast(txt||"Silinemedi", true); }
          });
        });

        list.querySelectorAll(".edit-btn").forEach(btn=>{
          btn.addEventListener("click", async ()=>{
            const slug = btn.getAttribute("data-slug");
            try{
              const it = await getStreamer(slug);
              // Modal alanlarını doldur (index’te id/name’ler zaten var)
              $("#edit-modal")?.classList?.add("active");
              const f = $("#edit-streamer-form"); if(!f) return;
              f.querySelector('[name="slug"]').value = slug;
              f.querySelector('[name="title"]').value = it.title || it.displayText || "";
              f.querySelector('[name="subtitle"]').value = it.subtitle || "";
              f.querySelector('[name="customBackgroundUrl"]').value = it.customBackgroundUrl || "";
              f.querySelector('[name="kickRedirectorUrl"]').value = it.kickRedirectorUrl || "";
              f.querySelector('[name="discordRedirectorUrl"]').value = it.discordRedirectorUrl || "";
              f.querySelector('[name="botghostWebhookUrl"]').value = it.botghostWebhookUrl || "";
            }catch(e){ showToast("Kayıt alınamadı", true); }
          });
        });

      }catch(e){
        console.error(e); showToast("Liste alınamadı", true);
      }
    }

    $("#cancel-edit-btn")?.addEventListener("click", ()=> $("#edit-modal")?.classList?.remove("active") );

    $("#edit-streamer-form")?.addEventListener("submit", async (e)=>{
      e.preventDefault();
      const f = e.currentTarget;
      const slug = f.querySelector('[name="slug"]').value.trim();
      const data = {
        title: f.querySelector('[name="title"]').value.trim(),
        subtitle: f.querySelector('[name="subtitle"]').value.trim(),
        customBackgroundUrl: f.querySelector('[name="customBackgroundUrl"]').value.trim(),
        kickRedirectorUrl: f.querySelector('[name="kickRedirectorUrl"]').value.trim(),
        discordRedirectorUrl: f.querySelector('[name="discordRedirectorUrl"]').value.trim(),
        botghostWebhookUrl: f.querySelector('[name="botghostWebhookUrl"]').value.trim(),
      };
      // Backend displayText fallback: title varsa displayText = title
      try{
        const r = await fetch(`/api/streamers/${slug}`, {
          method:"PUT", headers:{ "Content-Type":"application/json" }, body: JSON.stringify(data)
        });
        if(r.ok){ showToast("Güncellendi"); $("#edit-modal")?.classList?.remove("active"); }
        else { const t=await r.text(); showToast(t||"Güncellenemedi", true); }
      }catch{ showToast("Hata oluştu", true); }
    });

    // İlk açılışta routing
    handleRouting();
  });

  window.addEventListener("error", e => console.error("JS error:", e?.error||e?.message||e));
  window.addEventListener("unhandledrejection", e => console.error("Promise rejection:", e?.reason||e));
})();
