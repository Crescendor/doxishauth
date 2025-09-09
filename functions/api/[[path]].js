/**
 * Cloudflare Pages Functions - Kick Abonelik Doğrulama (v10)
 * - Public API ile kullanıcı (viewer) bilgisi
 * - Site v2 ile kanal & identity sorguları
 * - expires_at varsa ve gelecekteyse -> abonedir
 *
 * ENV: KICK_CLIENT_ID, KICK_CLIENT_SECRET, DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, APP_URL, ADMIN_PASSWORD
 * KV (STREAMERS): key = <slug>, value = { displayText, discordGuildId?, discordRoleId?, discordBotToken?, broadcaster_user_id? }
 */

export const onRequest = async (context) => handleRequest(context);

// ---------------- PKCE yardımcıları ----------------
function b64url(uint8) {
  return btoa(String.fromCharCode(...uint8)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
function generateCodeVerifier() {
  const random = crypto.getRandomValues(new Uint8Array(32));
  return b64url(random);
}
async function generateCodeChallenge(verifier) {
  const data = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return b64url(new Uint8Array(digest));
}

// ---------------- Ana handler ----------------
async function handleRequest(context) {
  try {
    const { request, env } = context;
    const url = new URL(request.url);
    const path = url.pathname.replace(/^\/+/, '');
    const segments = path.split('/').filter(Boolean);

    const db = env.STREAMERS;
    const adminPassword = env.ADMIN_PASSWORD;

    if (segments[0] === 'api') {
      // ---- Admin Login
      if (segments[1] === 'login' && request.method === 'POST') {
        const { password } = await safeJson(request);
        if (adminPassword && password === adminPassword) {
          return json({ success: true });
        }
        return json({ error: 'Invalid password' }, 401);
      }

      // ---- Streamers CRUD
      if (segments[1] === 'streamers') {
        if (request.method === 'GET' && !segments[2]) {
          const list = await db.list();
          const items = await Promise.all(list.keys.map(async (k) => {
            const v = await db.get(k.name);
            return v ? { slug: k.name, ...JSON.parse(v) } : null;
          }));
          return json(items.filter(Boolean));
        }
        if (request.method === 'GET' && segments[2]) {
          const v = await db.get(segments[2]);
          if (!v) return json({ error: 'Streamer not found' }, 404);
          return json({ slug: segments[2], ...JSON.parse(v) });
        }
        if (request.method === 'POST') {
          const { slug, displayText, discordGuildId, discordRoleId, discordBotToken, broadcaster_user_id, password } = await safeJson(request);
          if (password !== adminPassword) return json({ error: 'Unauthorized' }, 401);
          if (!slug || !displayText) return json({ error: 'Slug and displayText required' }, 400);
          const data = JSON.stringify({ displayText, discordGuildId, discordRoleId, discordBotToken, broadcaster_user_id });
          await db.put(slug, data);
          return json({ success: true, slug }, 201);
        }
        if (request.method === 'DELETE' && segments[2]) {
          const { password } = await safeJson(request);
          if (password !== adminPassword) return json({ error: 'Unauthorized' }, 401);
          await db.delete(segments[2]);
          return json({ success: true });
        }
      }

      // ---- OAuth2
      if (segments[1] === 'auth') {
        if (segments[2] === 'redirect' && segments[3]) {
          const provider = segments[3];
          const streamer = new URL(request.url).searchParams.get('streamer');
          if (!streamer) return text("Streamer query parameter is required", 400);

          const stateRandom = crypto.randomUUID();
          const stateObj = { streamer, random: stateRandom };
          let authUrl;

          if (provider === 'discord') {
            authUrl = new URL('https://discord.com/api/oauth2/authorize');
            authUrl.searchParams.set('client_id', env.DISCORD_CLIENT_ID);
            authUrl.searchParams.set('redirect_uri', `${env.APP_URL}/api/auth/callback/discord`);
            authUrl.searchParams.set('scope', 'identify guilds.members.read');
            authUrl.searchParams.set('response_type', 'code');
            authUrl.searchParams.set('state', stateRandom);
          } else if (provider === 'kick') {
            const codeVerifier = generateCodeVerifier();
            const codeChallenge = await generateCodeChallenge(codeVerifier);
            stateObj.codeVerifier = codeVerifier;

            // Sadece user:read gerekli; user:read:subscriptions resmi scope listesinde yok.
            authUrl = new URL('https://id.kick.com/oauth/authorize');
            authUrl.searchParams.set('client_id', env.KICK_CLIENT_ID);
            authUrl.searchParams.set('redirect_uri', `${env.APP_URL}/api/auth/callback/kick`);
            authUrl.searchParams.set('scope', 'user:read');
            authUrl.searchParams.set('response_type', 'code');
            authUrl.searchParams.set('code_challenge', codeChallenge);
            authUrl.searchParams.set('code_challenge_method', 'S256');
            authUrl.searchParams.set('state', stateRandom);
          } else {
            return text('Unsupported provider', 400);
          }

          const cookie = `oauth_state=${encodeURIComponent(JSON.stringify(stateObj))}; HttpOnly; Path=/; Max-Age=600; Secure; SameSite=Lax`;
          const headers = new Headers({ Location: authUrl.toString(), 'Set-Cookie': cookie });
          return new Response(null, { status: 302, headers });
        }

        if (segments[2] === 'callback' && segments[3]) {
          const provider = segments[3];
          const currentUrl = new URL(request.url);
          const code = currentUrl.searchParams.get('code');
          const stateFromUrl = currentUrl.searchParams.get('state');
          if (!code || !stateFromUrl) {
            return text(`HATA ADIM 1: Geri dönüş URL'sinde 'code' veya 'state' yok.`, 400);
          }

          const cookie = request.headers.get('Cookie');
          const storedStateJSON = cookie ? decodeURIComponent(cookie.match(/oauth_state=([^;]+)/)?.[1] || '') : null;
          if (!storedStateJSON) return text(`HATA ADIM 2: Güvenlik çerezi bulunamadı.`, 400);

          const storedState = JSON.parse(storedStateJSON);
          if (stateFromUrl !== storedState.random) return text(`HATA ADIM 3: CSRF state eşleşmedi.`, 403);

          let tokenData;
          try {
            tokenData = await exchangeCodeForToken(provider, code, storedState.codeVerifier, env);
          } catch (e) {
            return text(`HATA ADIM 4: Token alınamadı.\n\n${e.message}`, 500);
          }

          // ---- Abonelik doğrulama
          let isSubscribed = false;
          try {
            const streamerSlug = storedState.streamer;
            const streamerRec = await env.STREAMERS.get(streamerSlug);
            if (!streamerRec) throw new Error(`Yayıncı '${streamerSlug}' KV'de yok.`);

            if (provider === 'discord') {
              isSubscribed = await checkDiscordSubscription(tokenData.access_token, JSON.parse(streamerRec));
            } else if (provider === 'kick') {
              isSubscribed = await checkKickSubscription({
                accessToken: tokenData.access_token,
                streamerSlug,
                streamer: JSON.parse(streamerRec),
              });
            }
          } catch (e) {
            return text(`HATA ADIM 5: Abonelik kontrolü başarısız.\n\nDetay:\n${e.message}`, 500);
          }

          const redirectUrl = new URL(`/${storedState.streamer}`, env.APP_URL);
          redirectUrl.searchParams.set('subscribed', isSubscribed ? 'true' : 'false');
          redirectUrl.searchParams.set('provider', provider);

          const headers = new Headers({ Location: redirectUrl.toString(), 'Set-Cookie': 'oauth_state=; HttpOnly; Path=/; Max-Age=0' });
          return new Response(null, { status: 302, headers });
        }
      }

      // Unhandled under /api
      return text('Not Found', 404);
    }

    // Root dışı her şey 404
    return text('Not Found', 404);
  } catch (err) {
    console.error('KRITIK HATA:', err);
    return text(`KRITIK SUNUCU HATASI:\n\n${err.message}\n\nStack:\n${err.stack}`, 500);
  }
}

// ---------------- Yardımcılar ----------------
async function safeJson(request) {
  try { return await request.json(); } catch { return {}; }
}
function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });
}
function text(body, status = 200) {
  return new Response(body, { status, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
}

// ---------------- OAuth Token Exchange ----------------
async function exchangeCodeForToken(provider, code, codeVerifier, env) {
  let tokenUrl, body;
  if (provider === 'discord') {
    tokenUrl = 'https://discord.com/api/oauth2/token';
    body = new URLSearchParams({
      client_id: env.DISCORD_CLIENT_ID,
      client_secret: env.DISCORD_CLIENT_SECRET,
      grant_type: 'authorization_code',
      code,
      redirect_uri: `${env.APP_URL}/api/auth/callback/discord`,
    });
  } else if (provider === 'kick') {
    tokenUrl = 'https://id.kick.com/oauth/token';
    body = new URLSearchParams({
      client_id: env.KICK_CLIENT_ID,
      client_secret: env.KICK_CLIENT_SECRET,
      grant_type: 'authorization_code',
      code,
      redirect_uri: `${env.APP_URL}/api/auth/callback/kick`,
      code_verifier: codeVerifier,
    });
  } else {
    throw new Error('Unsupported provider');
  }

  const res = await fetch(tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });

  if (!res.ok) {
    const t = await res.text();
    throw new Error(`Token exchange failed (${res.status}): ${t}`);
  }
  return res.json();
}

// ---------------- Discord Abonelik Kontrol (opsiyonel) ----------------
async function checkDiscordSubscription(accessToken, streamer) {
  const { discordGuildId, discordRoleId, discordBotToken } = streamer || {};
  if (!discordGuildId || !discordRoleId || !discordBotToken) return false;

  const meRes = await fetch('https://discord.com/api/users/@me', {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!meRes.ok) return false;
  const me = await meRes.json();

  const memberRes = await fetch(`https://discord.com/api/guilds/${discordGuildId}/members/${me.id}`, {
    headers: { Authorization: `Bot ${discordBotToken}` },
  });
  if (!memberRes.ok) return false;
  const member = await memberRes.json();

  return Array.isArray(member.roles) && member.roles.includes(discordRoleId);
}

// ---------------- Kick Yardımcıları ----------------
function siteHeaders(ref) {
  return {
    'Accept': 'application/json',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36',
    'Referer': ref || 'https://kick.com/',
  };
}

async function getKickViewer(accessToken) {
  // Resmi Public API: Mevcut kullanıcının profili
  const res = await fetch('https://api.kick.com/public/v1/users', {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) {
    const t = await res.text();
    throw new Error(`Kick Public API 'users' hatası (${res.status}): ${t}`);
  }
  const data = await res.json();
  // Beklenen örnek şema: { id, name, email, profile_picture } — SDK/Docs referansı var.
  if (!data || (!data.id && !data.name)) {
    throw new Error(`Kick Public API 'users' beklenmeyen cevap: ${JSON.stringify(data)}`);
  }
  // Normalize
  return {
    id: data.id,
    username: data.name, // Kick Public API 'User.name' alanı kullanıcı adı olarak dönüyor (docs).
    profile_picture: data.profile_picture,
  };
}

async function getChannelBySlug(slug) {
  const url = `https://kick.com/api/v2/channels/${encodeURIComponent(slug)}`;
  const res = await fetch(url, { headers: siteHeaders(`https://kick.com/${slug}`) });
  if (!res.ok) {
    const t = await res.text();
    throw new Error(`Kanal bilgisi alınamadı (${res.status}): ${t}`);
  }
  const data = await res.json();
  // Örnek cevap: id, user_id, slug, subscription_enabled, user{ id, username, ... } vb. (public) 
  return {
    channelId: data.id,
    ownerUserId: data.user_id,
    slug: data.slug,
    ownerUsername: data?.user?.username,
    subscription_enabled: !!data.subscription_enabled,
  };
}

function parseExpiresAt(val) {
  if (!val) return null;
  const ts = Date.parse(val);
  return Number.isFinite(ts) ? ts : null;
}

function isFuture(ts) {
  return typeof ts === 'number' && ts > Date.now();
}

async function tryIdentityByIds(channelId, viewerId, referer) {
  // site v2: /api/v2/channels/{channelId}/users/{userId}/identity
  const url = `https://kick.com/api/v2/channels/${channelId}/users/${viewerId}/identity`;
  const res = await fetch(url, { headers: siteHeaders(referer) });
  if (!res.ok) return { ok: false, status: res.status, data: null, raw: await safeText(res) };
  let data = await safeJsonRes(res);
  return { ok: true, status: res.status, data };
}

async function tryUserInChannelByUsername(slug, username, referer) {
  // site v2: /api/v2/channels/{slug}/users/{username}
  const url = `https://kick.com/api/v2/channels/${encodeURIComponent(slug)}/users/${encodeURIComponent(username)}`;
  const res = await fetch(url, { headers: siteHeaders(referer) });
  if (!res.ok) return { ok: false, status: res.status, data: null, raw: await safeText(res) };
  let data = await safeJsonRes(res);
  return { ok: true, status: res.status, data };
}

async function tryRecentMessagesIdentity(channelId, viewerId, referer) {
  // site v2: /api/v2/channels/{channelId}/users/{userId}/messages  (public listelerde mevcut)
  const url = `https://kick.com/api/v2/channels/${channelId}/users/${viewerId}/messages`;
  const res = await fetch(url, { headers: siteHeaders(referer) });
  if (!res.ok) return { ok: false, status: res.status, data: null, raw: await safeText(res) };
  let data = await safeJsonRes(res);
  return { ok: true, status: res.status, data };
}

async function safeText(res) {
  try { return await res.text(); } catch { return ''; }
}
async function safeJsonRes(res) {
  const txt = await res.text();
  try { return JSON.parse(txt); } catch { return { _raw: txt }; }
}

function extractSubscriptionEvidence(payload) {
  // Bu fonksiyon identity veya user-channel cevaplarından abonelik bulgularını normalize eder.
  // Kabul edilen sinyaller:
  //  - identity.subscription.expires_at
  //  - identity.subscriber / badges içinde subscriber ve expires_at
  //  - messages[*].user_identity.subscription.expires_at
  const result = { hasSubscription: false, expires_at: null, tier: null, source: null };

  if (!payload || typeof payload !== 'object') return result;

  // direct identity style
  const identity = payload.identity || payload.user_identity || payload;
  if (identity && typeof identity === 'object') {
    const sub = identity.subscription || identity.subscriptions || identity.subscriber || identity?.badges?.subscriber;
    // Çeşitli olası yolları dene:
    const expires =
      identity?.subscription?.expires_at ||
      identity?.subscriber?.expires_at ||
      identity?.badges?.subscriber?.expires_at ||
      sub?.expires_at;

    const tier =
      identity?.subscription?.tier ||
      identity?.subscriber?.tier ||
      identity?.badges?.subscriber?.tier ||
      sub?.tier;

    const expTs = parseExpiresAt(expires);
    if (isFuture(expTs)) {
      return { hasSubscription: true, expires_at: new Date(expTs).toISOString(), tier: tier ?? null, source: 'identity' };
    }
  }

  // messages (array) -> en günceldeki identity’ye bak
  if (Array.isArray(payload.messages) || Array.isArray(payload)) {
    const arr = Array.isArray(payload.messages) ? payload.messages : payload;
    for (const m of arr) {
      const idn = m?.user_identity || m?.identity;
      const exp = idn?.subscription?.expires_at || idn?.subscriber?.expires_at || idn?.badges?.subscriber?.expires_at;
      const tier = idn?.subscription?.tier || idn?.subscriber?.tier || idn?.badges?.subscriber?.tier;
      const expTs = parseExpiresAt(exp);
      if (isFuture(expTs)) {
        return { hasSubscription: true, expires_at: new Date(expTs).toISOString(), tier: tier ?? null, source: 'messages' };
      }
    }
  }

  // user-in-channel payload’larında farklı şemalar olabilir
  if (payload?.badges && typeof payload.badges === 'object') {
    const sub = payload.badges.subscriber || payload.badges?.subscription;
    const expTs = parseExpiresAt(sub?.expires_at);
    if (isFuture(expTs)) {
      return { hasSubscription: true, expires_at: new Date(expTs).toISOString(), tier: sub?.tier ?? null, source: 'user-in-channel' };
    }
  }

  return result;
}

async function checkKickSubscription({ accessToken, streamerSlug, streamer }) {
  // 1) Viewer (current user) - resmi Public API
  const viewer = await getKickViewer(accessToken); // { id, username, ... }

  // 2) Kanal ID
  let channelId = streamer?.broadcaster_user_id;
  if (!channelId) {
    const ch = await getChannelBySlug(streamerSlug);
    channelId = ch.channelId;
  }
  if (!channelId) throw new Error(`Kanal ID alınamadı (slug=${streamerSlug}).`);

  const referer = `https://kick.com/${encodeURIComponent(streamerSlug)}`;

  // 3) PRIMARY: identity endpoint (ID bazlı, daha güvenilir)
  const idResp = await tryIdentityByIds(channelId, viewer.id, referer);
  if (idResp.ok) {
    const ev = extractSubscriptionEvidence(idResp.data);
    if (ev.hasSubscription) return true;
  } else if (idResp.status === 401 || idResp.status === 403) {
    // Devam: bazı kurulumlarda bu endpoint cookie isteyebilir; fallback'lere geçiyoruz.
  }

  // 4) SECONDARY: user-in-channel by username
  const uicResp = await tryUserInChannelByUsername(streamerSlug, viewer.username, referer);
  if (uicResp.ok) {
    const ev = extractSubscriptionEvidence(uicResp.data);
    if (ev.hasSubscription) return true;
  }

  // 5) TERTIARY: son mesajlar üzerinden identity (kullanıcı chat yazdıysa)
  const msgResp = await tryRecentMessagesIdentity(channelId, viewer.id, referer);
  if (msgResp.ok) {
    const ev = extractSubscriptionEvidence(msgResp.data);
    if (ev.hasSubscription) return true;
  }

  // 6) Son çare: explicit false
  return false;
}
