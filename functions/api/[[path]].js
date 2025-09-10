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
 * Çevre değişkenleri:
 * - APP_URL:             https://doxishauth.pages.dev (veya prod domain)
 * - KICK_CLIENT_ID      / KICK_CLIENT_SECRET
 * - DISCORD_CLIENT_ID   / DISCORD_CLIENT_SECRET
 * - STREAMERS (KV)
 * - ADMIN_PASSWORD (opsiyonel)
 */

const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

function TEXT(body, status = 200, headers = {}) {
  return new Response(typeof body === "string" ? body : String(body), {
    status,
    headers: { "content-type": "text/plain; charset=utf-8", ...headers },
  });
}

function JSONH(obj, status = 200, headers = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...headers },
  });
}

async function safeText(r) {
  try {
    return await r.text();
  } catch {
    return "";
  }
}
async function safeJsonReq(req) {
  try {
    return await req.json();
  } catch {
    return {};
  }
}
async function safeJsonRes(r) {
  try {
    return await r.json();
  } catch {
    const t = await safeText(r);
    try {
      return JSON.parse(t);
    } catch {
      return {};
    }
  }
}

/* -------------------- Kick Site Headers -------------------- */
function siteHeaders(refererPathOrUrl) {
  return {
    Accept: "application/json, text/plain, */*",
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

  return { id: String(user_id), username: String(username) };
}

/* -------------------- Kick Site API helpers -------------------- */
async function getChannelBySlug(slug) {
  const r = await fetch(`https://kick.com/api/v2/channels/${encodeURIComponent(slug)}`, {
    headers: siteHeaders(slug),
  });
  if (!r.ok) throw new Error(`Kick Site API 'channels' hata (${r.status})`);
  const j = await safeJsonRes(r);
  const channelId = j?.data?.id ?? j?.id ?? j?.channel_id ?? j?.user?.id;
  if (!channelId) throw new Error(`Channel bulunamadı: ${slug}`);
  return { channelId };
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
  const r = await fetch(
    `https://kick.com/api/v2/channels/${channelId}/messages?limit=50`,
    { headers: siteHeaders(refererSlug) }
  );
  if (!r.ok) return { ok: false, status: r.status, raw: await safeText(r) };
  return { ok: true, data: await safeJsonRes(r) };
}

/* -------------------- Evidence Parser -------------------- */
function extractSubscriptionEvidence(payload, username) {
  // Kick API farklı yerlerde badge/bit alanları taşıyabiliyor
  // "expires_at" varsa direkt ABONE kabul ediyoruz (tarih kontrolü yapmıyoruz)
  const identity = payload?.identity ?? payload;
  const expires = identity?.expires_at ?? identity?.subscription_expires_at ?? null;

  // messages → recent badges
  const msgs =
    Array.isArray(payload?.messages) ? payload.messages : payload?.data?.messages;
  const hasBadge =
    Array.isArray(identity?.badges)
      ? identity.badges.some((b) => String(b?.name || "").toLowerCase().includes("sub"))
      : !!identity?.subscriber;

  if (expires) return { hasSubscription: true, source: "identity:expires_at", expires_at: expires };
  if (hasBadge) return { hasSubscription: true, source: "identity:badge", expires_at: expires };

  if (Array.isArray(msgs)) {
    const u = String(username || "").toLowerCase();
    for (const m of msgs.slice(0, 20)) {
      const author = String(m?.user?.username || m?.username || "").toLowerCase();
      const b = m?.badges || m?.user?.badges || [];
      const hadSub = author === u
        ? (Array.isArray(b) && b.some((x) => String(x?.name || "").toLowerCase().includes("sub")))
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

  return { subscribed: false };
}

/* -------------------- Discord role check (optional) -------------------- */
async function discordHasRole(env, accessToken, discordGuildId, discordRoleId, discordBotToken) {
  // identify
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
      code_verifier: codeVerifier || "",
    });
  } else {
    throw new Error("Bilinmeyen provider");
  }

  const r = await fetch(tokenUrl, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!r.ok) {
    const t = await safeText(r);
    throw new Error(`Token exchange hata (${r.status})\n${t}`);
  }
  return await r.json();
}

/* -------------------- PKCE -------------------- */
function generateCodeVerifier() {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...raw))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}
async function generateCodeChallenge(verifier) {
  const data = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const base64Digest = btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
  return base64Digest;
}

/* -------------------- Router -------------------- */
export const onRequest = async ({ request, env, params }) => {
  try {
    const url = new URL(request.url);
    const path = url.pathname;
    const seg = path.split("/").filter(Boolean);
    const method = request.method.toUpperCase();

    // /api altında değilse → Not Found
    if (seg[0] !== "api") return TEXT("Not Found", 404);

    /* ---- KV helpers ---- */
    const kv = env.STREAMERS;

    // KV: get one
    async function getStreamer(slug) {
      const raw = await kv.get(`streamer:${slug}`);
      return raw ? JSON.parse(raw) : null;
    }

    // KV: list
    async function listStreamers() {
      const { keys } = await kv.list({ prefix: "streamer:" });
      const out = [];
      for (const k of keys) {
        const raw = await kv.get(k.name);
        if (raw) out.push(JSON.parse(raw));
      }
      out.sort((a, b) => (a.slug || "").localeCompare(b.slug || ""));
      return out;
    }

    // ---- ROUTES ----
    if (seg[1] === "streamers" && method === "GET" && !seg[2]) {
      const list = await listStreamers();
      return JSONH(list);
    }

    if (seg[1] === "streamers" && method === "GET" && seg[2]) {
      const slug = seg[2];
      const rec = await getStreamer(slug);
      if (!rec) return TEXT("Not Found", 404);
      return JSONH(rec);
    }

    if (seg[1] === "streamers" && method === "POST" && !seg[2]) {
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
          return JSONH({ error: "slug & displayText required" }, 400);

        const rec = {
          slug: String(slug),
          displayText: String(displayText),
          discordGuildId: discordGuildId ? String(discordGuildId) : null,
          discordRoleId: discordRoleId ? String(discordRoleId) : null,
          discordBotToken: discordBotToken ? String(discordBotToken) : null,
          broadcaster_user_id: broadcaster_user_id
            ? String(broadcaster_user_id)
            : null,
          updatedAt: new Date().toISOString(),
        };
        await kv.put(`streamer:${rec.slug}`, JSON.stringify(rec));
        return JSONH({ ok: true, streamer: rec });
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

      const cookie = `oauth_state=${encodeURIComponent(JSON.stringify(state))}; HttpOnly; SameSite=Lax; Path=/; Max-Age=900`;

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
        return TEXT(
          `HATA ADIM 4: Token alımı başarısız.\n\nDetay:\n${e.message}`,
          500
        );
      }

      // abonelik kontrolü
      let isSubscribed = false;
      try {
        const streamerSlug = parsed.streamer;

        // Discord rol kontrolü (opsiyonel, KV'de varsa)
        const rec = await getStreamer(streamerSlug);
        if (rec?.discordGuildId && rec?.discordRoleId && rec?.discordBotToken && provider === "discord") {
          isSubscribed = await discordHasRole(
            env,
            tokenData.access_token,
            rec.discordGuildId,
            rec.discordRoleId,
            rec.discordBotToken
          );
        } else {
          // Kick abonelik doğrulama
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

      // ---- username param (optional): show on UI without exposing tokens ----
      let __usernameParam = null;
      try {
        if (provider === "kick") {
          const __viewer = await getKickViewer(tokenData.access_token);
          __usernameParam = __viewer?.username || null;
        } else if (provider === "discord") {
          const __du = await fetch("https://discord.com/api/users/@me", {
            headers: { Authorization: `Bearer ${tokenData.access_token}` }
          });
          if (__du.ok) {
            const __me = await __du.json();
            __usernameParam = __me.global_name || __me.username || null;
          }
        }
      } catch (_) {
        // ignore – username is optional
      }

      const redir = new URL(`/${parsed.streamer}`, env.APP_URL);
      redir.searchParams.set("subscribed", String(isSubscribed));
      redir.searchParams.set("provider", provider);
      if (__usernameParam) redir.searchParams.set("username", __usernameParam);

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
  } catch (err) {
    console.error("KRITIK HATA:", err);
    return TEXT(
      `KRITIK SUNUCU HATASI:\n\n${err.message}\n\nStack:\n${err.stack || "no-stack"}`,
      500
    );
  }
};
