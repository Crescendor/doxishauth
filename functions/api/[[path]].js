/**
 * Kick Abonelik Doğrulama (kick.bot tarzı) – v10.1+ (stabilized)
 * Cloudflare Pages Functions (KV binding: STREAMERS)
 *
 * - Yayıncıya link yok. Sadece izleyici OAuth (Kick).
 * - Kullanıcıyı Kick Public API'den alır (Bearer).
 * - Kanalı site v2 endpoint'inden çözer.
 * - Abonelik tespiti (sıra):
 *    0) /api/v2/channels/{slug}/me        (Authorization + Referer)
 *    1) /api/v2/channels/{channelId}/users/{viewerId}/identity
 *    2) /api/v2/channels/{slug}/users/{username}
 *    3) /api/v2/channels/{slug}/subscribers/{username}  (website endpoints)
 * - Kural: JSON içinde **herhangi derinlikte** string "expires_at" varsa = ABONE.
 * - KV (STREAMERS) yalnızca yayıncı kayıt/metni için; değiştirmene gerek yok.
 *
 * ENV:
 *  APP_URL
 *  ADMIN_PASSWORD
 *  KICK_CLIENT_ID, KICK_CLIENT_SECRET
 *  (opsiyonel) DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET
 */

export async function onRequest(context) {
  return handleRequest(context);
}

/* -------------------- Utilities -------------------- */
const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36";

const JSONH = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });

const TEXT = (msg, status = 400) =>
  new Response(msg, {
    status,
    headers: { "Content-Type": "text/plain; charset=utf-8" },
  });

async function safeJsonReq(request) {
  const ct = (request.headers.get("content-type") || "").toLowerCase();
  try {
    if (ct.includes("application/json")) return await request.json();
    if (ct.includes("application/x-www-form-urlencoded")) {
      const t = await request.text();
      return Object.fromEntries(new URLSearchParams(t).entries());
    }
    if (ct.includes("multipart/form-data")) {
      const fd = await request.formData();
      const o = {};
      for (const [k, v] of fd.entries()) o[k] = typeof v === "string" ? v : (v?.name || "");
      return o;
    }
    const raw = await request.text();
    try { return JSON.parse(raw || "{}"); } catch { return Object.fromEntries(new URLSearchParams(raw).entries()); }
  } catch {
    return {};
  }
}

async function safeText(res) {
  try {
    return await res.text();
  } catch {
    return "";
  }
}

async function safeJsonRes(res) {
  const raw = await res.text();
  try {
    return JSON.parse(raw);
  } catch {
    return { _raw: raw };
  }
}

/* -------------------- PKCE -------------------- */
function b64url(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+/g, "");
}
function generateCodeVerifier() {
  return b64url(crypto.getRandomValues(new Uint8Array(32)));
}
async function generateCodeChallenge(verifier) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier)
  );
  return b64url(new Uint8Array(digest));
}

/* -------------------- Headers -------------------- */
function siteHeaders(refererPathOrUrl, bearer) {
  const h = {
    Accept: "application/json",
    "User-Agent": UA,
    Origin: "https://kick.com",
    Referer: refererPathOrUrl?.startsWith("http")
      ? refererPathOrUrl
      : `https://kick.com/${refererPathOrUrl || ""}`,
  };
  if (bearer) h.Authorization = `Bearer ${bearer}`;
  return h;
}

/* -------------------- Deep expires_at finder -------------------- */
function findExpiresAtDeep(node) {
  const st = [node];
  while (st.length) {
    const cur = st.pop();
    if (!cur || typeof cur !== "object") continue;
    for (const [k, v] of Object.entries(cur)) {
      if (k === "expires_at" && typeof v === "string" && v.trim()) return v;
      if (v && typeof v === "object") st.push(v);
    }
  }
  return null;
}

/* -------------------- Kick Public API: Viewer -------------------- */
/** Robust parse: {"data":[{"user_id":..., "name": "..."}], "message":"OK"} gibi varyantları normalize eder */
async function getKickViewer(accessToken) {
  // 1) Public API (resmi)
  const r = await fetch("https://api.kick.com/public/v1/users", {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/json",
      "User-Agent": UA,
    },
  });

  const txt = await r.text();
  let payload = {};
  try {
    payload = txt ? JSON.parse(txt) : {};
  } catch {
    throw new Error(`Kick Public API 'users' JSON parse error:\n${txt}`);
  }
  if (!r.ok) throw new Error(`Kick Public API 'users' hata (${r.status}):\n${txt}`);

  const rec = Array.isArray(payload?.data)
    ? payload.data[0]
    : payload?.data || payload;

  const user_id = rec?.user_id ?? rec?.id ?? rec?.user?.id ?? null;
  const username =
    rec?.name ?? rec?.username ?? rec?.slug ?? rec?.user?.username ?? null;

  if (!user_id || !username) {
    // 2) website endpoint fallback (bazı ortamlarda buradan daha stabil geliyor)
    const rf = await fetch("https://kick.com/api/v1/user", {
      headers: siteHeaders("", accessToken),
    });
    const t2 = await rf.text();
    try {
      const j2 = t2 ? JSON.parse(t2) : {};
      const u2 = j2?.username || j2?.slug || j2?.user?.username;
      const id2 = j2?.id || j2?.user?.id || null;
      if (u2 && id2) return { id: id2, username: u2 };
    } catch { /* ignore */ }

    throw new Error(
      `Kick API'den kullanıcı kimliği alınamadı.\nPublic payload: ${JSON.stringify(payload)}`
    );
  }

  return {
    id: user_id,
    username,
    profile_picture: rec?.profile_picture ?? rec?.avatar_url ?? null,
  };
}

/* -------------------- Kick Site v2: Channel & Identity -------------------- */
async function getChannelBySlug(slug) {
  const url = `https://kick.com/api/v2/channels/${encodeURIComponent(slug)}`;
  const r = await fetch(url, { headers: siteHeaders(slug) });
  if (!r.ok) throw new Error(`Kanal bilgisi alınamadı (${r.status}): ${await r.text()}`);
  const j = await r.json();
  const channelId = j?.id ?? j?.chatroom?.channel_id ?? j?.user?.streamer_channel?.id;
  if (!channelId) throw new Error(`Kanal ID bulunamadı. Cevap: ${JSON.stringify(j)}`);
  return { channelId, raw: j };
}

async function getChannelMe(slug, bearer) {
  const url = `https://kick.com/api/v2/channels/${encodeURIComponent(slug)}/me`;
  const r = await fetch(url, { headers: siteHeaders(slug, bearer) });
  if (!r.ok) return { ok: false, status: r.status, raw: await safeText(r) };
  return { ok: true, data: await safeJsonRes(r) };
}

async function getIdentityByUserId(channelId, userId, refererSlug) {
  const url = `https://kick.com/api/v2/channels/${channelId}/users/${userId}/identity`;
  const r = await fetch(url, { headers: siteHeaders(refererSlug) });
  if (r.status === 404) return { ok: true, data: null };
  if (!r.ok) return { ok: false, status: r.status, raw: await safeText(r) };
  return { ok: true, data: await safeJsonRes(r) };
}

async function getIdentityByUsername(slug, username, refererSlug) {
  const url = `https://kick.com/api/v2/channels/${encodeURIComponent(
    slug
  )}/users/${encodeURIComponent(username)}`;
  const r = await fetch(url, { headers: siteHeaders(refererSlug) });
  if (r.status === 404) return { ok: true, data: null };
  if (!r.ok) return { ok: false, status: r.status, raw: await safeText(r) };
  return { ok: true, data: await safeJsonRes(r) };
}

/** Website endpoints repo’larına göre subscriber lookup (200/404) */
async function getSubscriberByUsername(slug, username, bearer) {
  const url = `https://kick.com/api/v2/channels/${encodeURIComponent(slug)}/subscribers/${encodeURIComponent(username)}`;
  const r = await fetch(url, { headers: siteHeaders(slug, bearer) });
  if (r.status === 404) return { ok: true, data: null };
  if (!r.ok) return { ok: false, status: r.status, raw: await safeText(r) };
  // bazı ortamlarda boş/narrow dönebilir; yine de expires_at varsa yakalayalım
  return { ok: true, data: await safeJsonRes(r) };
}

/* -------------------- Subscription Logic -------------------- */
/** payload içinde ‘expires_at’ var mı? varsa ABONE */
function evidence(payload) {
  const ex = findExpiresAtDeep(payload);
  if (ex) return { hasSubscription: true, source: "expires_at", expires_at: ex };
  return { hasSubscription: false, source: "none", expires_at: null };
}

async function checkKickSubscriptionViewer(accessToken, streamerSlug) {
  // 0) /me (en güçlü)
  const me = await getChannelMe(streamerSlug, accessToken);
  if (me.ok && me.data) {
    const ev = evidence(me.data);
    if (ev.hasSubscription) return { subscribed: true, method: "me", expires_at: ev.expires_at };
  }

  // 1) Viewer
  const viewer = await getKickViewer(accessToken); // { id, username }

  // 2) Channel
  const { channelId } = await getChannelBySlug(streamerSlug);

  // 3) PRIMARY: identity by userId
  const idRes = await getIdentityByUserId(channelId, viewer.id, streamerSlug);
  if (!idRes.ok) throw new Error(`identity HTTP ${idRes.status || "??"}\n${idRes.raw || ""}`);
  if (idRes.data) {
    const ev = evidence(idRes.data);
    if (ev.hasSubscription) return { subscribed: true, method: "identity:userId", expires_at: ev.expires_at };
  }

  // 4) SECONDARY: identity by username
  const unRes = await getIdentityByUsername(streamerSlug, viewer.username, streamerSlug);
  if (!unRes.ok) throw new Error(`identity(username) HTTP ${unRes.status || "??"}\n${unRes.raw || ""}`);
  if (unRes.data) {
    const ev = evidence(unRes.data);
    if (ev.hasSubscription) return { subscribed: true, method: "identity:username", expires_at: ev.expires_at };
  }

  // 5) Website endpoints: subscribers/{username} (bazı kanallarda expires_at burada)
  const subRes = await getSubscriberByUsername(streamerSlug, viewer.username, accessToken);
  if (!subRes.ok) throw new Error(`subscribers(username) HTTP ${subRes.status || "??"}\n${subRes.raw || ""}`);
  if (subRes.data) {
    const ev = evidence(subRes.data);
    if (ev.hasSubscription) return { subscribed: true, method: "subscribers:username", expires_at: ev.expires_at };
  }

  return { subscribed: false, method: "none" };
}

/* -------------------- Discord (opsiyonel) -------------------- */
async function checkDiscordSubscription(accessToken, streamerInfo) {
  const { discordGuildId, discordRoleId, discordBotToken } = streamerInfo || {};
  if (!discordGuildId || !discordRoleId || !discordBotToken) return false;

  const u = await fetch("https://discord.com/api/users/@me", {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!u.ok) return false;
  const me = await u.json();

  const m = await fetch(
    `https://discord.com/api/guilds/${discordGuildId}/members/${me.id}`,
    { headers: { Authorization: `Bot ${discordBotToken}` } }
  );
  if (!m.ok) return false;
  const member = await m.json();

  return Array.isArray(member.roles) && member.roles.includes(discordRoleId);
}

/* -------------------- OAuth Exchange -------------------- */
async function exchangeCodeForToken(provider, code, codeVerifier, env) {
  let tokenUrl, body;
  if (provider === "discord") {
    tokenUrl = "https://discord.com/api/oauth2/token";
    body = new URLSearchParams({
      client_id: env.DISCORD_CLIENT_ID,
      client_secret: env.DISCORD_CLIENT_SECRET,
      grant_type: "authorization_code",
      code,
      redirect_uri: `${env.APP_URL}/api/auth/callback/discord`,
    });
  } else if (provider === "kick") {
    tokenUrl = "https://id.kick.com/oauth/token";
    body = new URLSearchParams({
      client_id: env.KICK_CLIENT_ID,
      client_secret: env.KICK_CLIENT_SECRET,
      grant_type: "authorization_code",
      code,
      redirect_uri: `${env.APP_URL}/api/auth/callback/kick`,
      code_verifier: codeVerifier
    });
  } else {
    throw new Error("Unsupported provider");
  }

  const r = await fetch(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  if (!r.ok) throw new Error(await r.text());
  return r.json(); // { access_token, ... }
}

/* -------------------- Router -------------------- */
async function handleRequest(context) {
  try {
    const { request, env } = context;
    const url = new URL(request.url);
    const seg = url.pathname.replace(/^\/+/, "").split("/").filter(Boolean);
    const method = request.method;
    const STREAMERS = env.STREAMERS;

    if (seg[0] === "api") {
      // admin
      if (seg[1] === "login" && method === "POST") {
        const { password } = await safeJsonReq(request);
        if (env.ADMIN_PASSWORD && password === env.ADMIN_PASSWORD) return JSONH({ success: true });
        return JSONH({ error: "Invalid password" }, 401);
      }

      // streamers CRUD (key = slug)
      if (seg[1] === "streamers") {
        if (method === "GET" && !seg[2]) {
          const list = await STREAMERS.list();
          const streamers = await Promise.all(list.keys.map(async (key) => {
            const value = await STREAMERS.get(key.name);
            return value ? { slug: key.name, ...JSON.parse(value) } : null;
          }));
          return JSONH(streamers.filter(Boolean));
        }
        if (method === "GET" && seg[2]) {
          const value = await STREAMERS.get(seg[2]);
          if (!value) return JSONH({ error: "Streamer not found" }, 404);
          return JSONH({ slug: seg[2], ...JSON.parse(value) });
        }
        if (method === "POST") {
          const b = await safeJsonReq(request);
          const { password, broadcaster_user_id } = b;
          const slug = (b.slug || "").trim();
          const displayText = (b.displayText || "").trim();

          if (env.ADMIN_PASSWORD && password !== env.ADMIN_PASSWORD)
            return JSONH({ error: "Unauthorized" }, 401);
          if (!slug || !displayText)
            return JSONH({ error: "Slug and displayText required" }, 400);

          const rec = {
            displayText,
            discordGuildId: (b.discordGuildId || "").trim(),
            discordRoleId: (b.discordRoleId || "").trim(),
            discordBotToken: (b.discordBotToken || "").trim(),
          };
          if (broadcaster_user_id) rec.broadcaster_user_id = broadcaster_user_id;

          await STREAMERS.put(slug, JSON.stringify(rec));
          return JSONH({ success: true, slug }, 201);
        }
        if (method === "DELETE" && seg[2]) {
          const { password } = await safeJsonReq(request);
          if (env.ADMIN_PASSWORD && password !== env.ADMIN_PASSWORD)
            return JSONH({ error: "Unauthorized" }, 401);
          await STREAMERS.delete(seg[2]);
          return JSONH({ success: true });
        }
      }

      // OAuth redirect
      if (seg[1] === "auth" && seg[2] === "redirect" && seg[3]) {
        const provider = seg[3];
        const streamer = url.searchParams.get("streamer");
        if (!streamer) return TEXT("streamer query param required", 400);

        const state = { streamer, random: crypto.randomUUID() };
        let authUrl;

        if (provider === "discord") {
          authUrl = new URL("https://discord.com/api/oauth2/authorize");
          authUrl.searchParams.set("client_id", env.DISCORD_CLIENT_ID);
          authUrl.searchParams.set("redirect_uri", `${env.APP_URL}/api/auth/callback/discord`);
          authUrl.searchParams.set("scope", "identify guilds.members.read");
          authUrl.searchParams.set("response_type", "code");
          authUrl.searchParams.set("state", state.random);
        } else if (provider === "kick") {
          const verifier = generateCodeVerifier();
          const challenge = await generateCodeChallenge(verifier);
          state.codeVerifier = verifier;

          authUrl = new URL("https://id.kick.com/oauth/authorize");
          authUrl.searchParams.set("client_id", env.KICK_CLIENT_ID);
          authUrl.searchParams.set("redirect_uri", `${env.APP_URL}/api/auth/callback/kick`);
          authUrl.searchParams.set("scope", "user:read");
          authUrl.searchParams.set("response_type", "code");
          authUrl.searchParams.set("code_challenge", challenge);
          authUrl.searchParams.set("code_challenge_method", "S256");
          authUrl.searchParams.set("state", state.random);
        } else {
          return TEXT("Unsupported provider", 400);
        }

        const cookie = `oauth_state=${encodeURIComponent(JSON.stringify(state))}; HttpOnly; Path=/; Max-Age=600; Secure; SameSite=Lax`;
        return new Response(null, { status: 302, headers: { Location: authUrl.toString(), "Set-Cookie": cookie } });
      }

      // OAuth callback
      if (seg[1] === "auth" && seg[2] === "callback" && seg[3]) {
        const provider = seg[3];

        const code = url.searchParams.get("code");
        const stateFromUrl = url.searchParams.get("state");
        if (!code || !stateFromUrl) {
          return TEXT("HATA ADIM 1: code/state eksik", 400);
        }

        const cookie = request.headers.get("Cookie");
        const storedStateJSON = cookie ? decodeURIComponent(cookie.match(/oauth_state=([^;]+)/)?.[1] || "") : null;
        if (!storedStateJSON) {
          return TEXT("HATA ADIM 2: Güvenlik çerezi yok", 400);
        }

        const storedState = JSON.parse(storedStateJSON);
        if (stateFromUrl !== storedState.random) {
          return TEXT("HATA ADIM 3: CSRF state eşleşmiyor", 403);
        }

        // token
        let tokenData;
        try {
          tokenData = await exchangeCodeForToken(provider, code, storedState.codeVerifier, env);
        } catch (e) {
          return TEXT(`HATA ADIM 4: Token alınamadı\n\n${e.message}`, 500);
        }

        // subscription check
        let isSubscribed = false, subMethod = "", subExp = "";
        try {
          const streamerSlug = storedState.streamer;
          const streamerInfoJSON = await STREAMERS.get(streamerSlug);
          if (!streamerInfoJSON) throw new Error(`Yayıncı '${streamerSlug}' KV'de yok.`);
          const streamerInfo = JSON.parse(streamerInfoJSON);

          if (provider === "discord") {
            isSubscribed = await checkDiscordSubscription(tokenData.access_token, streamerInfo);
            subMethod = "discord-role";
          } else if (provider === "kick") {
            const result = await checkKickSubscriptionViewer(tokenData.access_token, streamerSlug);
            isSubscribed = !!result.subscribed;
            subMethod = result.method || "";
            subExp = result.expires_at || "";
          }
        } catch (e) {
          return TEXT(`HATA ADIM 5: Abonelik kontrolü başarısız.\n\nDetay:\n${e.message}`, 500);
        }

        const redir = new URL(`/${storedState.streamer}`, env.APP_URL);
        redir.searchParams.set("subscribed", String(isSubscribed));
        redir.searchParams.set("provider", provider);
        if (subMethod) redir.searchParams.set("method", subMethod);
        if (subExp)    redir.searchParams.set("expires_at", subExp);

        return new Response(null, {
          status: 302,
          headers: {
            Location: redir.toString(),
            "Set-Cookie": "oauth_state=; HttpOnly; Path=/; Max-Age=0",
          },
        });
      }

      // DEBUG endpoint: /api/test/kick?streamer=slug&token=BearerToken(optional)
      if (seg[1] === "test" && seg[2] === "kick" && method === "GET") {
        const streamer = url.searchParams.get("streamer");
        const token = url.searchParams.get("token"); // eğer manuel verilecekse
        if (!streamer) return JSONH({ error: "streamer query required" }, 400);
        if (!token) return JSONH({ error: "token query required (Bearer access_token)" }, 400);

        const out = {};
        try {
          out.viewer = await getKickViewer(token);
          const ch = await getChannelBySlug(streamer);
          out.channel = ch;

          const me = await getChannelMe(streamer, token);
          out.me = me;
          if (me.ok && me.data) out.me_expires_at = findExpiresAtDeep(me.data);

          const i1 = await getIdentityByUserId(ch.channelId, out.viewer.id, streamer);
          out.identity_userId = i1;
          if (i1.ok && i1.data) out.identity_userId_expires_at = findExpiresAtDeep(i1.data);

          const i2 = await getIdentityByUsername(streamer, out.viewer.username, streamer);
          out.identity_username = i2;
          if (i2.ok && i2.data) out.identity_username_expires_at = findExpiresAtDeep(i2.data);

          const s1 = await getSubscriberByUsername(streamer, out.viewer.username, token);
          out.subscribers_username = s1;
          if (s1.ok && s1.data) out.subscribers_username_expires_at = findExpiresAtDeep(s1.data);

          const verdict =
            out.me_expires_at || out.identity_userId_expires_at || out.identity_username_expires_at || out.subscribers_username_expires_at
              ? "SUBSCRIBED"
              : "NOT_SUBSCRIBED";

          return JSONH({ ok: true, verdict, out });
        } catch (e) {
          return JSONH({ ok: false, error: e.message }, 500);
        }
      }

      // unknown /api
      return TEXT("Not Found", 404);
    }

    // default
    return TEXT("Not Found", 404);
  } catch (err) {
    console.error("KRITIK HATA:", err);
    return TEXT(
      `KRITIK SUNUCU HATASI:\n\n${err.message}\n\nStack:\n${err.stack || "no-stack"}`,
      500
    );
  }
}
