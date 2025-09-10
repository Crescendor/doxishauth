/* ==========================================================
 * Frontend Script (crash-proof)
 * - UI'ya dokunmaz; element yoksa no-op.
 * - Kick + Discord login callback query params'larını okur.
 * - ?debug=1 iken status alanına debug info basar.
 * ========================================================== */
(function () {
  "use strict";

  const $ = (sel, root = document) => root.querySelector(sel);

  /* ---------------- Safe Toast (opsiyonel) ---------------- */
  function showToast(msg, type = "info", ms = 2500) {
    try {
      const t = $("#toast"); // varsa kullan
      if (!t) return; // yoksa sessiz
      t.textContent = msg;
      t.style.borderColor =
        type === "error"
          ? "rgba(239,68,68,0.5)"
          : type === "success"
          ? "rgba(34,197,94,0.5)"
          : "rgba(255,255,255,0.2)";
      t.classList.add("show");
      setTimeout(() => t.classList.remove("show"), ms);
    } catch (_) {}
  }

  /* ---------------- API helpers ---------------- */
  const apiBase = () => location.origin;

  async function fetchJSON(url, opts) {
    const r = await fetch(url, opts);
    const txt = await r.text();
    let j = {};
    try {
      j = txt ? JSON.parse(txt) : {};
    } catch (_) {}
    if (!r.ok) throw new Error(j?.error || txt || `HTTP ${r.status}`);
    return j;
  }

  const getStreamer = (slug) =>
    fetchJSON(`${apiBase()}/api/streamers/${encodeURIComponent(slug)}`);

  /* ---------------- Auth state ---------------- */
  function defaultAuth(slug) {
    return {
      slug,
      kick: {
        linked: false,
        subscribed: false,
        method: "",
        expires_at: "",
        viewerId: "",
        username: "",
      },
      discord: { linked: false, userId: "" },
      ts: Date.now(),
    };
  }

  function readAuth(slug) {
    try {
      const raw =
        sessionStorage.getItem("auth") || localStorage.getItem("auth");
      if (!raw) return defaultAuth(slug);
      const a = JSON.parse(raw);
      if (a.slug !== slug) return defaultAuth(slug);
      a.kick ||= {
        linked: false,
        subscribed: false,
        method: "",
        expires_at: "",
        viewerId: "",
        username: "",
      };
      a.discord ||= { linked: false, userId: "" };
      return a;
    } catch (_) {
      return defaultAuth(slug);
    }
  }

  function writeAuth(a) {
    try {
      sessionStorage.setItem("auth", JSON.stringify(a));
    } catch (_) {}
  }

  function clearAuth() {
    try {
      sessionStorage.removeItem("auth");
      localStorage.removeItem("auth");
    } catch (_) {}
  }

  /* ---------------- UI helpers ---------------- */
  function badge(isSub) {
    // UI'ya dokunmadan mevcut class'ları kullan
    return isSub
      ? `<span class="status-badge status-badge-green">✓ Abone</span>`
      : `<span class="status-badge status-badge-red">X Abone Değil</span>`;
  }

  function wireButtons(slug, auth) {
    // Discord butonu (varsa)
    const discBtn = $("#discord-login");
    if (discBtn) {
      // her durumda önce eski handler'ı sıfırla
      const fresh = discBtn.cloneNode(true);
      fresh.id = "discord-login";
      discBtn.replaceWith(fresh);

      fresh.addEventListener("click", (e) => {
        e.preventDefault();
        const u = new URL(`${apiBase()}/api/auth/redirect/discord`);
        u.searchParams.set("streamer", slug);
        location.href = u.toString();
      });

      // linklenmişse gri yap (UI class'ları sende mevcut)
      if (auth.discord.linked) {
        fresh.classList.add("disabled");
        fresh.setAttribute("disabled", "disabled");
      } else {
        fresh.classList.remove("disabled");
        fresh.removeAttribute("disabled");
      }
    }

    // Kick butonu (varsa)
    const kickBtn = $("#kick-login");
    if (kickBtn) {
      const fresh = kickBtn.cloneNode(true);
      fresh.id = "kick-login";
      kickBtn.replaceWith(fresh);

      if (auth.kick.linked) {
        // Giriş yapılmışsa aynı butonu "Çıkış Yap" yap
        fresh.textContent = "Çıkış Yap";
        fresh.addEventListener("click", (e) => {
          e.preventDefault();
          clearAuth();
          location.href = `/${slug}`;
        });
      } else {
        fresh.textContent = "Kick ile Giriş Yap";
        fresh.addEventListener("click", (e) => {
          e.preventDefault();
          const u = new URL(`${apiBase()}/api/auth/redirect/kick`);
          u.searchParams.set("streamer", slug);
          location.href = u.toString();
        });
      }
    }
  }

  /* ---------------- Channel init ---------------- */
  async function initChannel(slug) {
    // Başlık/alt başlık (varsa)
    try {
      const s = await getStreamer(slug);
      const title = $("#streamer-title");
      if (title) title.textContent = s.displayText || s.title || slug;
      const sub = $("#streamer-subtitle");
      if (sub) sub.textContent = s.subtitle || "Aboneliğini doğrulamak için giriş yap.";
    } catch (_) {
      const title = $("#streamer-title");
      if (title) title.textContent = slug;
      const sub = $("#streamer-subtitle");
      if (sub) sub.textContent = "Yayıncı bulunamadı.";
      showToast("Yayıncı bulunamadı", "error");
    }

    // Callback query param'ları
    const url = new URL(location.href);
    const debugMode = url.searchParams.get("debug") === "1";
    const provider = url.searchParams.get("provider"); // "kick" | "discord"
    const subscribed = url.searchParams.get("subscribed"); // "true"/"false"
    const method = url.searchParams.get("method") || "";
    const expires_at = url.searchParams.get("expires_at") || "";
    const kick_viewer_id = url.searchParams.get("kick_viewer_id") || "";
    const kick_username = url.searchParams.get("kick_username") || "";
    const discord_user_id = url.searchParams.get("discord_user_id") || "";

    // Auth merge
    let auth = readAuth(slug);
    if (provider) {
      if (provider === "kick") {
        auth.kick.linked = true;
        auth.kick.subscribed = subscribed === "true";
        if (method) auth.kick.method = method;
        if (expires_at) auth.kick.expires_at = expires_at;
        if (kick_viewer_id) auth.kick.viewerId = kick_viewer_id;
        if (kick_username) auth.kick.username = kick_username;
      } else if (provider === "discord") {
        auth.discord.linked = true;
        if (discord_user_id) auth.discord.userId = discord_user_id;
      }
      auth.ts = Date.now();
      writeAuth(auth);

      // Debug değilse query'yi temizle
      if (!debugMode) {
        ["provider","subscribed","method","expires_at","kick_viewer_id","kick_username","discord_user_id"]
          .forEach((k) => url.searchParams.delete(k));
        try {
          history.replaceState({}, document.title, url.pathname + (url.search ? "?" + url.searchParams.toString() : "") + url.hash);
        } catch (_) {}
      }
    }

    // Kural: Kick & Discord linked && Kick.subscribed === true → ✓ Abone
    const bothLinked = auth.kick.linked && auth.discord.linked;
    const ok = bothLinked && auth.kick.subscribed === true;

    // Status badge (varsa)
    const status = $("#status-container");
    if (status) status.innerHTML = badge(ok);

    // Debug alanı (yalnızca ?debug=1 ve status alanı mevcutsa)
    if (debugMode && status) {
      try {
        const dbg = document.createElement("pre");
        dbg.style.cssText =
          "text-align:left; white-space:pre-wrap; font-size:12px; opacity:.8; margin-top:8px;";
        dbg.textContent = `DEBUG:
provider=${provider}
subscribed=${subscribed}
method=${method}
expires_at=${expires_at}
kick_viewer_id=${kick_viewer_id || auth.kick.viewerId}
kick_username=${kick_username || auth.kick.username}
discord_user_id=${discord_user_id || auth.discord.userId}
auth=${JSON.stringify(auth, null, 2)}`;
        status.appendChild(dbg);
      } catch (_) {}
    }

    // Butonları bağla (varsa)
    wireButtons(slug, auth);
  }

  /* ---------------- Routing ---------------- */
  function currentSlug() {
    try {
      const p = location.pathname.replace(/^\/+/, "");
      const s = p.split("/")[0] || "";
      return s.toLowerCase() === "admin" ? "" : s;
    } catch (_) {
      return "";
    }
  }

  function handleRouting() {
    try {
      const slug = currentSlug();
      if (slug) initChannel(slug);
      // ana sayfadaysan hiçbir şey yapma (UI mevcut kalır)
    } catch (err) {
      console.error("Routing error:", err);
      showToast("Bir şeyler ters gitti (routing).", "error");
    }
  }

  /* ---------------- Global error guard ---------------- */
  window.addEventListener("error", (e) => {
    console.error("JS error:", e?.error || e?.message || e);
    // UI'yı bozma; sadece console + opsiyonel toast
  });
  window.addEventListener("unhandledrejection", (e) => {
    console.error("Promise rejection:", e?.reason || e);
  });

  /* ---------------- Boot ---------------- */
  document.addEventListener("DOMContentLoaded", handleRouting);
})();
