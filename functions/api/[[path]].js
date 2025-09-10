// functions/[[path]].js
/**
 * Kick Abonelik Doğrulama (kick.bot tarzı) – v10.1
 * Cloudflare Pages Functions (KV binding: STREAMERS)
 *
 * - Yayıncıya link yok. Sadece izleyici OAuth.
 * - Kullanıcıyı Kick Public API'den alır (Bearer).
 * - Kanalı site v2 endpoint'inden çözer.
 * - Abonelik tespiti:
 *    1) /api/v2/channels/{channelId}/users/{viewerId}/identity
 *    2) /api/v2/channels/{slug}/users/{username}
 *    3) /api/v2/channels/{channelId}/messages (username rozet tarama)
 * - Kural: identity yanıtında "expires_at" **varsa** = ABONE (tarihe bakmadan).
 * - KV (STREAMERS) yalnızca yayıncı kayıt/metni için; değiştirmene gerek yok.
 *
 * ENV:
 *  APP_URL
 *  ADMIN_PASSWORD
 *  KICK_CLIENT_ID, KICK_CLIENT_SECRET
 *  (Discord istersen: DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET)
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
  try {
    return await request.json();
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
function siteHeaders(refererPathOrUrl) {
  return {
    Accept: "application/json",
    "User-Agent": UA,
    Referer:
      refererPathOrUrl?.startsWith("http")
        ? refererPathOrUrl
        : `https://kick.com/${refererPathOrUrl || ""}`,
    Origin: "https://kick.com",
  };
}

/* -------------------- Kick Public API: Viewer -------------------- */
/** Robust parse: {"data":[{"user_id":..., "name": "..."}], "message":"OK"} gibi varyantları normalize eder */
async function getKickViewer(accessToken) {
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
    throw new Error(
      `Kick Public API 'users' beklenmeyen cevap:\n${JSON.stringify(payload)}`
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

async function getRecentMessages(channelId, refererSlug) {
  const url = `https://kick.com/api/v2/channels/${channelId}/messages`;
  const r = await fetch(url, { headers: siteHeaders(refererSlug) });
  if (!r.ok) return { ok: false, status: r.status, raw: await safeText(r) };
  return { ok: true, data: await safeJsonRes(r) };
}

/** "expires_at" varsa ABONE kabul; aksi halde badge bazlı sinyale bakar */
function extractSubscriptionEvidence(payload, usernameForBadge) {
  // Normalize identity-like nodes
  const identity = payload?.identity || payload?.user_identity || payload;

  // 1) expires_at varsa (hangi node'da olursa olsun) -> ABONE (policy gereği tarihe bakmadan)
  const ex =
    identity?.subscription?.expires_at ??
    identity?.subscriber?.expires_at ??
    identity?.badges?.subscriber?.expires_at ??
    payload?.expires_at ??
    null;

  if (typeof ex === "string" && ex.trim().length > 0) {
    return { hasSubscription: true, source: "expires_at", expires_at: ex };
  }

  // 2) Rozet/Badge (subscriber) sinyali
  const badges =
    identity?.badges ||
    identity?.identity?.badges ||
    payload?.badges ||
    [];
  const hasSubBadge = Array.isArray(badges)
    ? badges.some((b) => `${b?.type || b?.name || b?.text || ""}`.toLowerCase().includes("sub"))
    : !!badges?.subscriber;

  if (hasSubBadge) {
    return { hasSubscription: true, source: "badge", expires_at: null };
  }

  // 3) Messages dizisi (fallback)
  if (Array.isArray(payload?.messages) || Array.isArray(payload)) {
    const arr = Array.isArray(payload?.messages) ? payload.messages : payload;
    for (const m of arr) {
      const sender = m?.sender || m?.user || m?.identity || m?.user_identity;
      const name = sender?.username || sender?.slug || sender?.name;
      if (usernameForBadge && name && name.toLowerCase() !== usernameForBadge.toLowerCase())
        continue;

      const b =
        sender?.badges ||
        sender?.identity?.badges ||
        sender?.user_identity?.badges ||
        [];
      const hadSub = Array.isArray(b)
        ? b.some((x) => `${x?.type || x?.name || x?.text || ""}`.toLowerCase().includes("sub"))
        : !!b?.subscriber;
      if (hadSub) return { hasSubscription: true, source: "messages-badge", expires_at: null };
    }
  }

  return { hasSubscription: false, source: "none", expires_at: null };
}

/* -------------------- Kick Subscription Logic -------------------- */
async function checkKickSubscriptionViewer(accessToken, streamerSlug) {
  // 1) Viewer
  const viewer = await getKickViewer(accessToken); // { id, username, ... }

  // 2) Channel
  const { channelId } = await getChannelBySlug(streamerSlug);

  // 3) PRIMARY: identity by userId
  const idRes = await getIdentityByUserId(channelId, viewer.id, streamerSlug);
  if (idRes.ok && idRes.data) {
    const ev = extractSubscriptionEvidence(idRes.data, viewer.username);
    if (ev.hasSubscription) return { subscribed: true, method: "identity:userId", details: ev };
  }

  // 4) SECONDARY: identity by username
  const unRes = await getIdentityByUsername(streamerSlug, viewer.username, streamerSlug);
  if (unRes.ok && unRes.data) {
    const ev = extractSubscriptionEvidence(unRes.data, viewer.username);
    if (ev.hasSubscription) return { subscribed: true, method: "identity:username", details: ev };
  }

  // 5) TERTIARY: recent messages badge
  const msgRes = await getRecentMessages(channelId, streamerSlug);
  if (msgRes.ok && msgRes.data) {
    const ev = extractSubscriptionEvidence(msgRes.data, viewer.username);
    if (ev.hasSubscription) return { subscribed: true, method: "messages", details: ev };
  }

  return { subscribed: false, method: "none", details: {} };
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
      code_verifier: codeVerifier,
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
          const items = await Promise.all(
            list.keys.map(async (k) => {
              const v = await STREAMERS.get(k.name);
              return v ? { slug: k.name, ...JSON.parse(v) } : null;
            })
          );
          return JSONH(items.filter(Boolean));
        }
        if (method === "GET" && seg[2]) {
          const v = await STREAMERS.get(seg[2]);
          if (!v) return JSONH({ error: "Streamer not found" }, 404);
          return JSONH({ slug: seg[2], ...JSON.parse(v) });
        }
        if (method === "POST") {
          const {
            slug,
            displayText,
            discordGuildId,
            discordRoleId,
            discordBotToken,
            broadcaster_user_id, // opsiyonel cache
            password,
          } = await safeJsonReq(request);

          if (env.ADMIN_PASSWORD && password !== env.ADMIN_PASSWORD)
            return JSONH({ error: "Unauthorized" }, 401);
          if (!slug || !displayText)
            return JSONH({ error: "Slug and displayText required" }, 400);

          const rec = {
            displayText,
            discordGuildId,
            discordRoleId,
            discordBotToken,
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
          // sadece viewer bilgisi lazım
          authUrl.searchParams.set("scope", "user:read");
          authUrl.searchParams.set("response_type", "code");
          authUrl.searchParams.set("code_challenge", challenge);
          authUrl.searchParams.set("code_challenge_method", "S256");
          authUrl.searchParams.set("state", state.random);
        } else {
          return TEXT("Unsupported provider", 400);
        }

        const cookie = `oauth_state=${encodeURIComponent(
          JSON.stringify(state)
        )}; HttpOnly; Path=/; Max-Age=600; Secure; SameSite=Lax`;

        return new Response(null, {
          status: 302,
          headers: { Location: authUrl.toString(), "Set-Cookie": cookie },
        });
      }

      // OAuth callback
      if (seg[1] === "auth" && seg[2] === "callback" && seg[3]) {
        const provider = seg[3];
        const code = url.searchParams.get("code");
        const stateParam = url.searchParams.get("state");
        if (!code || !stateParam) return TEXT("HATA ADIM 1: code/state eksik", 400);

        const cookie = request.headers.get("Cookie");
        const stored = cookie
          ? decodeURIComponent(cookie.match(/oauth_state=([^;]+)/)?.[1] || "")
          : null;
        if (!stored) return TEXT("HATA ADIM 2: Güvenlik çerezi yok", 400);

        const parsed = JSON.parse(stored);
        if (stateParam !== parsed.random) return TEXT("HATA ADIM 3: CSRF state eşleşmiyor", 403);

        // token
        let tokenData;
        try {
          tokenData = await exchangeCodeForToken(
            provider,
            code,
            parsed.codeVerifier,
            env
          );
        } catch (e) {
          return TEXT(`HATA ADIM 4: Token alınamadı\n\n${e.message}`, 500);
        }

        // subscription check
        let isSubscribed = false;
        try {
          const streamerSlug = parsed.streamer;
          const streamerJSON = await STREAMERS.get(streamerSlug);
          if (!streamerJSON) throw new Error(`Yayıncı '${streamerSlug}' KV'de yok.`);
          const streamerInfo = JSON.parse(streamerJSON);

          if (provider === "discord") {
            isSubscribed = await checkDiscordSubscription(
              tokenData.access_token,
              streamerInfo
            );
          } else if (provider === "kick") {
            const result = await checkKickSubscriptionViewer(
              tokenData.access_token,
              streamerSlug
            );
            isSubscribed = !!result.subscribed;
          }
        } catch (e) {
          return TEXT(
            `HATA ADIM 5: Abonelik kontrolü başarısız.\n\nDetay:\n${e.message}`,
            500
          );
        }

        const redir = new URL(`/${parsed.streamer}`, env.APP_URL);
        redir.searchParams.set("subscribed", String(isSubscribed));
        redir.searchParams.set("provider", provider);

        return new Response(null, {
          status: 302,
          headers: {
            Location: redir.toString(),
            "Set-Cookie": "oauth_state=; HttpOnly; Path=/; Max-Age=0",
          },
        });
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
