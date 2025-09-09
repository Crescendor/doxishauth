// functions/[[path]].js
/**
 * Kick Security Wall – v9.1 (Public API + Webhooks)
 * Cloudflare Pages Functions (KV binding: STREAMERS)
 *
 * - OAuth (Kick: PKCE, Discord)
 * - Streamer admin CRUD (KV: streamer:<slug>)
 * - Webhook signature verify (Kick Public Key)
 * - Subscription state via KV (sub:<broadcaster_user_id>:<subscriber_user_id>)
 * - Login callback -> KV check -> redirect /:slug?subscribed=...
 *
 * Docs:
 *  OAuth: https://docs.kick.com/getting-started/generating-tokens-oauth2-flow
 *  Scopes: https://docs.kick.com/getting-started/scopes
 *  Users:  https://docs.kick.com/apis/users
 *  Channels: https://docs.kick.com/apis/channels
 *  Webhooks: https://docs.kick.com/events/webhook-security
 *  Events:   https://docs.kick.com/events/subscribe-to-events, /events/event-types
 */

// ---------- UTIL ----------
const JSONH = (obj, status = 200, extraHeaders = {}) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...extraHeaders
    }
  });

const TEXT = (msg, status = 400) =>
  new Response(msg, {
    status,
    headers: { "Content-Type": "text/plain; charset=utf-8" }
  });

function base64UrlEncode(bytes) {
  let str = '';
  for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+/g, '');
}

function toUint8(str) {
  return new TextEncoder().encode(str);
}

function fromBase64(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ---------- PKCE ----------
function generateCodeVerifier() {
  const randomBytes = crypto.getRandomValues(new Uint8Array(32));
  return base64UrlEncode(randomBytes);
}
async function generateCodeChallenge(verifier) {
  const digest = await crypto.subtle.digest("SHA-256", toUint8(verifier));
  return base64UrlEncode(new Uint8Array(digest));
}

// ---------- KICK PUBLIC API HELPERS ----------
async function getKickUser(accessToken) {
  const res = await fetch("https://api.kick.com/public/v1/users", {
    headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" }
  });
  if (!res.ok) throw new Error(`Kick /users failed ${res.status}: ${await res.text()}`);
  const payload = await res.json();
  const me = payload?.data?.[0];
  if (!me?.user_id) throw new Error(`Unexpected /users payload: ${JSON.stringify(payload)}`);
  return me; // { user_id, name, email?, profile_picture? }
}

async function getChannelBySlug(accessToken, slug) {
  const url = new URL("https://api.kick.com/public/v1/channels");
  url.searchParams.append("slug", slug);
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" }
  });
  if (!res.ok) throw new Error(`Kick /channels failed ${res.status}: ${await res.text()}`);
  const payload = await res.json();
  const ch = payload?.data?.[0];
  if (!ch?.broadcaster_user_id) throw new Error(`Channel not found: ${slug}`);
  return ch; // includes broadcaster_user_id, slug, stream etc.
}

async function ensureEventSubs(accessToken, broadcaster_user_id) {
  // Subscribe to subscription-related events (idempotent on server side)
  const body = {
    broadcaster_user_id,
    method: "webhook",
    events: [
      { name: "channel.subscription.new", version: 1 },
      { name: "channel.subscription.renewal", version: 1 },
      { name: "channel.subscription.gifts", version: 1 }
    ]
  };
  const res = await fetch("https://api.kick.com/public/v1/events/subscriptions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
      Accept: "application/json"
    },
    body: JSON.stringify(body)
  });
  // 200 OK body lists per-event outcome; we tolerate 4xx/5xx to avoid hard failing user logins
  if (!res.ok) {
    const t = await res.text();
    console.warn("ensureEventSubs error:", res.status, t);
    return null;
  }
  return res.json();
}

// ---------- DISCORD HELPERS ----------
async function checkDiscordSubscription(accessToken, streamerInfo) {
  const { discordGuildId, discordRoleId, discordBotToken } = streamerInfo || {};
  if (!discordGuildId || !discordRoleId || !discordBotToken) return false;

  const u = await fetch("https://discord.com/api/users/@me", {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  if (!u.ok) return false;
  const user = await u.json();

  const m = await fetch(`https://discord.com/api/guilds/${discordGuildId}/members/${user.id}`, {
    headers: { Authorization: `Bot ${discordBotToken}` }
  });
  if (!m.ok) return false;
  const member = await m.json();
  return Array.isArray(member.roles) && member.roles.includes(discordRoleId);
}

// ---------- KICK SUB STATUS (KV) ----------
async function isSubscribedKV(STREAMERS, broadcaster_user_id, subscriber_user_id) {
  const key = `sub:${broadcaster_user_id}:${subscriber_user_id}`;
  const val = await STREAMERS.get(key);
  if (!val) return false;
  try {
    const { expires_at } = JSON.parse(val);
    return new Date(expires_at) > new Date();
  } catch {
    return false;
  }
}

async function saveSubKV(STREAMERS, broadcaster_user_id, subscriber_user_id, expires_at, source = "webhook") {
  const key = `sub:${broadcaster_user_id}:${subscriber_user_id}`;
  await STREAMERS.put(key, JSON.stringify({ expires_at, source }));
}

// ---------- WEBHOOK VERIFY ----------
async function importKickPublicKey(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const der = fromBase64(b64);
  return crypto.subtle.importKey(
    "spki",
    der.buffer,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
}

async function fetchKickPublicKey() {
  const r = await fetch("https://api.kick.com/public/v1/public-key");
  if (!r.ok) throw new Error(`public-key fetch failed: ${r.status}`);
  const j = await r.json();
  const pem = j?.data?.public_key;
  if (!pem) throw new Error("public key missing");
  return pem;
}

async function verifyKickSignature(headers, rawBody, pem) {
  const messageId = headers.get("Kick-Event-Message-Id");
  const ts = headers.get("Kick-Event-Message-Timestamp");
  const signatureHeader = headers.get("Kick-Event-Signature");
  if (!messageId || !ts || !signatureHeader) return false;

  const message = `${messageId}.${ts}.${rawBody}`;
  const data = toUint8(message);
  const signature = fromBase64(signatureHeader);

  const key = await importKickPublicKey(pem);
  const ok = await crypto.subtle.verify(
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    key,
    signature,
    data
  );
  return ok;
}

// ---------- MAIN ROUTER ----------
export async function onRequest(context) {
  try {
    const { request, env } = context;
    const url = new URL(request.url);
    const path = url.pathname.replace(/^\/+/, ""); // drop leading /
    const seg = path.split("/").filter(Boolean);
    const method = request.method;
    const STREAMERS = env.STREAMERS;

    // ---------------- Admin & Data ----------------
    if (seg[0] === "api") {
      // simple admin login
      if (seg[1] === "login" && method === "POST") {
        const { password } = await request.json().catch(() => ({}));
        if (env.ADMIN_PASSWORD && password === env.ADMIN_PASSWORD) {
          return JSONH({ success: true });
        }
        return JSONH({ error: "Invalid password" }, 401);
      }

      // streamers CRUD (KV: streamer:<slug>)
      if (seg[1] === "streamers") {
        if (method === "GET" && !seg[2]) {
          const list = await STREAMERS.list({ prefix: "streamer:" });
          const items = await Promise.all(
            list.keys.map(async k => {
              const v = await STREAMERS.get(k.name);
              return v ? { slug: k.name.split(":")[1], ...JSON.parse(v) } : null;
            })
          );
          return JSONH(items.filter(Boolean));
        }
        if (method === "GET" && seg[2]) {
          const v = await STREAMERS.get(`streamer:${seg[2]}`);
          if (!v) return JSONH({ error: "Streamer not found" }, 404);
          return JSONH({ slug: seg[2], ...JSON.parse(v) });
        }
        if (method === "POST") {
          const body = await request.json().catch(() => ({}));
          const { slug, displayText, discordGuildId, discordRoleId, discordBotToken, password } = body;
          if (password !== env.ADMIN_PASSWORD) return JSONH({ error: "Unauthorized" }, 401);
          if (!slug || !displayText) return JSONH({ error: "Slug and displayText required" }, 400);
          const data = {
            displayText,
            discordGuildId,
            discordRoleId,
            discordBotToken
            // broadcaster_user_id (set later)
          };
          await STREAMERS.put(`streamer:${slug}`, JSON.stringify(data));
          return JSONH({ success: true, slug }, 201);
        }
        if (method === "DELETE" && seg[2]) {
          const { password } = await request.json().catch(() => ({}));
          if (password !== env.ADMIN_PASSWORD) return JSONH({ error: "Unauthorized" }, 401);
          await STREAMERS.delete(`streamer:${seg[2]}`);
          return JSONH({ success: true });
        }
      }

      // --------------- OAuth Redirects ---------------
      if (seg[1] === "auth" && seg[2] === "redirect" && seg[3]) {
        const provider = seg[3];
        const streamer = url.searchParams.get("streamer");
        if (!streamer) return TEXT("streamer query param required", 400);

        const randomState = crypto.randomUUID();
        let stateObj = { streamer, random: randomState };
        let authUrl;

        if (provider === "discord") {
          authUrl = new URL("https://discord.com/api/oauth2/authorize");
          authUrl.searchParams.set("client_id", env.DISCORD_CLIENT_ID);
          authUrl.searchParams.set("redirect_uri", `${env.APP_URL}/api/auth/callback/discord`);
          authUrl.searchParams.set("scope", "identify guilds.members.read");
          authUrl.searchParams.set("response_type", "code");
          authUrl.searchParams.set("state", randomState);
        } else if (provider === "kick") {
          const codeVerifier = generateCodeVerifier();
          const codeChallenge = await generateCodeChallenge(codeVerifier);
          stateObj.codeVerifier = codeVerifier;

          authUrl = new URL("https://id.kick.com/oauth/authorize");
          authUrl.searchParams.set("client_id", env.KICK_CLIENT_ID);
          authUrl.searchParams.set("redirect_uri", `${env.APP_URL}/api/auth/callback/kick`);
          authUrl.searchParams.set("scope", "user:read channel:read events:subscribe"); // ✔
          authUrl.searchParams.set("code_challenge", codeChallenge);
          authUrl.searchParams.set("code_challenge_method", "S256");
          authUrl.searchParams.set("response_type", "code");
          authUrl.searchParams.set("state", randomState);
        } else {
          return TEXT("Unsupported provider", 400);
        }

        const cookie = `oauth_state=${encodeURIComponent(JSON.stringify(stateObj))}; HttpOnly; Path=/; Max-Age=600; Secure; SameSite=Lax`;
        return new Response(null, {
          status: 302,
          headers: { Location: authUrl.toString(), "Set-Cookie": cookie }
        });
      }

      // --------------- OAuth Callbacks ---------------
      if (seg[1] === "auth" && seg[2] === "callback" && seg[3]) {
        const provider = seg[3];
        const code = url.searchParams.get("code");
        const stateFromUrl = url.searchParams.get("state");
        if (!code || !stateFromUrl) return TEXT("HATA ADIM 1: code/state eksik", 400);

        const cookie = request.headers.get("Cookie");
        const storedStateJSON = cookie ? decodeURIComponent(cookie.match(/oauth_state=([^;]+)/)?.[1] || "") : null;
        if (!storedStateJSON) return TEXT("HATA ADIM 2: Güvenlik çerezi yok", 400);

        const storedState = JSON.parse(storedStateJSON);
        if (stateFromUrl !== storedState.random) return TEXT("HATA ADIM 3: CSRF state eşleşmiyor", 403);

        // Exchange code for token
        let tokenData;
        try {
          tokenData = await exchangeCodeForToken(provider, code, storedState.codeVerifier, env);
        } catch (e) {
          return TEXT(`HATA ADIM 4: Token alınamadı\n\n${e.message}`, 500);
        }

        let isSubscribed = false;
        try {
          const streamer = storedState.streamer;
          // load streamer config
          const confRaw = await STREAMERS.get(`streamer:${streamer}`);
          if (!confRaw) throw new Error(`Yayıncı '${streamer}' KV'de yok.`);
          const conf = JSON.parse(confRaw);

          if (provider === "discord") {
            isSubscribed = await checkDiscordSubscription(tokenData.access_token, conf);
          } else if (provider === "kick") {
            // resolve current user and channel id
            const me = await getKickUser(tokenData.access_token);
            let broadcaster_user_id = conf.broadcaster_user_id;
            if (!broadcaster_user_id) {
              const ch = await getChannelBySlug(tokenData.access_token, streamer);
              broadcaster_user_id = ch.broadcaster_user_id;
              conf.broadcaster_user_id = broadcaster_user_id;
              await STREAMERS.put(`streamer:${streamer}`, JSON.stringify(conf));
              // Best-effort ensure event subs (requires app webhook configured in Kick dev portal)
              await ensureEventSubs(tokenData.access_token, broadcaster_user_id).catch(() => null);
            }
            isSubscribed = await isSubscribedKV(STREAMERS, broadcaster_user_id, me.user_id);
          }
        } catch (e) {
          return TEXT(`HATA ADIM 5: Abonelik durumu kontrol edilemedi.\n\nHata detayı:\n${e.message}`, 500);
        }

        const redirectUrl = new URL(`/${storedState.streamer}`, env.APP_URL);
        redirectUrl.searchParams.set("subscribed", String(isSubscribed));
        redirectUrl.searchParams.set("provider", provider);

        return new Response(null, {
          status: 302,
          headers: { Location: redirectUrl.toString(), "Set-Cookie": "oauth_state=; HttpOnly; Path=/; Max-Age=0" }
        });
      }

      // --------------- Webhook Receiver ---------------
      if (seg[1] === "webhooks" && seg[2] === "kick" && method === "POST") {
        // Read raw body BEFORE JSON.parse (for signature)
        const rawBody = await request.text();
        let pem = env.KICK_PUBLIC_KEY_PEM;
        if (!pem) {
          try { pem = await fetchKickPublicKey(); }
          catch (e) { return TEXT(`public key alınamadı: ${e.message}`, 500); }
        }

        const ok = await verifyKickSignature(request.headers, rawBody, pem);
        if (!ok) return TEXT("Invalid signature", 401);

        const eventType = request.headers.get("Kick-Event-Type");
        const payload = JSON.parse(rawBody);

        // broadcaster user_id present on all listed subscription events
        const b = payload?.broadcaster?.user_id;
        if (!b) return TEXT("No broadcaster_user_id", 400);

        if (eventType === "channel.subscription.new" || eventType === "channel.subscription.renewal") {
          const s = payload?.subscriber?.user_id;
          const expires = payload?.expires_at;
          if (s && expires) await saveSubKV(STREAMERS, b, s, expires, eventType.endsWith("new") ? "new" : "renewal");
        } else if (eventType === "channel.subscription.gifts") {
          const expires = payload?.expires_at;
          const giftees = payload?.giftees || [];
          for (const g of giftees) {
            if (g?.user_id && expires) await saveSubKV(STREAMERS, b, g.user_id, expires, "gift");
          }
        }
        // you can also listen to chat.message.sent, followed, etc. if needed
        return new Response("OK");
      }

      // Fallback for /api/*
      return TEXT("Not Found", 404);
    }

    // ---------------- Frontend fallback ----------------
    // You can serve /:slug from Pages static assets; this exists just as a guard.
    return TEXT("Not Found", 404);
  } catch (err) {
    console.error("KRITIK HATA:", err);
    return TEXT(`KRITIK SUNUCU HATASI:\n\n${err.message}\n\nStack Trace:\n${err.stack || "no-stack"}`, 500);
  }
}

// ---------- TOKEN EXCHANGE ----------
async function exchangeCodeForToken(provider, code, codeVerifier, env) {
  let tokenUrl, body;
  if (provider === "discord") {
    tokenUrl = "https://discord.com/api/oauth2/token";
    body = new URLSearchParams({
      client_id: env.DISCORD_CLIENT_ID,
      client_secret: env.DISCORD_CLIENT_SECRET,
      grant_type: "authorization_code",
      code,
      redirect_uri: `${env.APP_URL}/api/auth/callback/discord`
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

  const res = await fetch(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}
