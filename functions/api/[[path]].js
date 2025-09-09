/**
 * Cloudflare Pages Functions – [[path]].js
 * Kick abonelik kontrolü (yayıncı linki olmadan, kick.bot tarzı)
 * - OAuth: Kick (PKCE)
 * - KV: STREAMERS (sadece yayıncı kaydı/metni vs.)
 * - Abonelik kontrol sırası:
 *    1) Site endpoint: /api/v2/channels/{channelId}/users/{userId}/identity  (badge/subscription/ expires_at kontrolü)
 *    2) Site endpoint: /api/v2/channels/{channelId}/users/{username}/identity  (fallback)
 *    3) Site endpoint: /api/v2/channels/{channelId}/messages  (sender badge fallback)
 * - Hepsinde UA + Referer zorunlu, mümkünse Origin da veriliyor.
 */

/// --- PKCE HELPERS ---
function generateCodeVerifier() {
  const randomBytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...randomBytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
async function generateCodeChallenge(verifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(digest))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// --- CONSTANTS ---
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';
const SITE_ORIGIN = 'https://kick.com';
const PUBLIC_API = 'https://api.kick.com'; // Public API (OAuth Bearer) – kullanıcı bilgisi burada

// --- COMMON HEADERS (Kick site endpoints için) ---
function siteHeaders(refererPath) {
  return {
    'Accept': 'application/json',
    'User-Agent': UA,
    'Referer': `${SITE_ORIGIN}/${refererPath || ''}`,
    'Origin': SITE_ORIGIN
  };
}

// --- UTILS ---
async function readJSONOrThrow(res, urlLabel) {
  const text = await res.text();
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} @ ${urlLabel}\n${text}`);
  }
  try {
    return text ? JSON.parse(text) : {};
  } catch (e) {
    throw new Error(`JSON parse error @ ${urlLabel}\nRaw:\n${text}`);
  }
}

// Kick Public API: token -> user info
async function getMeViaPublicAPI(accessToken) {
  // Public doc örneklerinde /public/v1/users kullanılıyor (Arctic docs). 
  // Payload bazen {data:[user]} formunda dönebiliyor.  :contentReference[oaicite:2]{index=2}
  const url = `${PUBLIC_API}/public/v1/users`;
  const res = await fetch(url, {
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Accept': 'application/json',
      'User-Agent': UA
    }
  });
  const json = await readJSONOrThrow(res, 'PublicAPI /public/v1/users');
  // Esnek çekim: farklı yanıt biçimlerini tolere et
  const me = json?.data?.[0] || json?.user || json;
  if (!me || !(me.id || me.user_id || me.username)) {
    throw new Error(`Public API 'me' bilgisi alınamadı. Gelen:\n${JSON.stringify(json)}`);
  }
  return {
    id: me.id || me.user_id,
    username: me.username || me.slug || me.user?.username
  };
}

// Site API: kanal detayından channelId al
async function getChannelBySlug(slug) {
  const url = `${SITE_ORIGIN}/api/v2/channels/${encodeURIComponent(slug)}`;
  const res = await fetch(url, { headers: siteHeaders(slug) });
  const json = await readJSONOrThrow(res, `/api/v2/channels/${slug}`);
  const channelId = json?.id || json?.chatroom?.channel_id || json?.user?.streamer_channel?.id;
  if (!channelId) {
    throw new Error(`Kanal ID bulunamadı. Response:\n${JSON.stringify(json)}`);
  }
  return { channelId, channel: json };
}

// identity endpoint – userId ile
async function getIdentityByUserId(channelId, userId, refererSlug) {
  const url = `${SITE_ORIGIN}/api/v2/channels/${channelId}/users/${userId}/identity`;
  const res = await fetch(url, { headers: siteHeaders(refererSlug) });
  if (res.status === 404) return null;
  if (!res.ok) {
    const t = await res.text();
    throw new Error(`Identity(userId) beklenmedik yanıt: ${res.status}\n${t}`);
  }
  return await res.json();
}

// identity endpoint – username ile (fallback)
async function getIdentityByUsername(channelId, username, refererSlug) {
  const url = `${SITE_ORIGIN}/api/v2/channels/${channelId}/users/${encodeURIComponent(username)}/identity`;
  const res = await fetch(url, { headers: siteHeaders(refererSlug) });
  if (res.status === 404) return null;
  if (!res.ok) {
    const t = await res.text();
    throw new Error(`Identity(username) beklenmedik yanıt: ${res.status}\n${t}`);
  }
  return await res.json();
}

// messages fallback – son mesajlardan badge bak
async function findSubscriberBadgeFromMessages(channelId, username, refererSlug) {
  const url = `${SITE_ORIGIN}/api/v2/channels/${channelId}/messages`;
  const res = await fetch(url, { headers: siteHeaders(refererSlug) });
  if (!res.ok) return { ok: false, reason: `messages HTTP ${res.status}` };
  const json = await res.json();
  const items = Array.isArray(json?.data) ? json.data : (Array.isArray(json) ? json : []);
  for (const msg of items) {
    const sender = msg?.sender || msg?.user || msg?.identity;
    const name = sender?.username || sender?.slug;
    if (name && name.toLowerCase() === username.toLowerCase()) {
      const badges = sender?.badges || sender?.identity?.badges || [];
      const hasSub = badges.some(b => (b?.type || b?.name || '').toLowerCase().includes('sub'));
      return { ok: true, isSub: hasSub, detail: { badges } };
    }
  }
  return { ok: true, isSub: false, detail: { seen: false } };
}

// Genel abonelik çıkarımı: identity json => {isSub, expiresAt}
function deriveSubFromIdentity(identityJson) {
  if (!identityJson) return { isSub: false };
  const badges = identityJson?.badges || identityJson?.identity?.badges || [];
  const hasSubBadge = badges.some(b => (b?.type || b?.name || '').toLowerCase().includes('sub'));
  // Bazı varyantlarda subscription alanı/ expires_at gelebiliyor; varsa öncelik o. (endpoint listeleri bu identity/me çağrılarını doğruluyor) :contentReference[oaicite:3]{index=3}
  const subObj = identityJson?.subscription || identityJson?.subscriber || null;
  const expires_at = subObj?.expires_at || subObj?.expiresAt || identityJson?.expires_at || null;
  if (expires_at) {
    const expires = new Date(expires_at).getTime();
    const now = Date.now();
    if (!Number.isNaN(expires) && expires > now) {
      return { isSub: true, expiresAt: new Date(expires).toISOString(), source: 'expires_at' };
    }
  }
  return { isSub: !!hasSubBadge, expiresAt: null, source: hasSubBadge ? 'badge' : 'none' };
}

// --- MAIN SUB CHECK (no broadcaster link) ---
async function checkKickSubscription(accessToken, streamerSlug) {
  // 1) Me + Channel
  const me = await getMeViaPublicAPI(accessToken); // {id, username}
  const { channelId } = await getChannelBySlug(streamerSlug);

  // 2) identity by userId
  try {
    const identById = await getIdentityByUserId(channelId, me.id, streamerSlug);
    const d1 = deriveSubFromIdentity(identById);
    if (d1.isSub) return { subscribed: true, meta: { method: 'identity:userId', ...d1, user: me } };
  } catch (e) {
    // Sessiz geç; username fallback'e düş
  }

  // 3) identity by username (fallback)
  try {
    const identByU = await getIdentityByUsername(channelId, me.username, streamerSlug);
    const d2 = deriveSubFromIdentity(identByU);
    if (d2.isSub) return { subscribed: true, meta: { method: 'identity:username', ...d2, user: me } };
  } catch (e) {
    // Sessiz geç; messages fallback
  }

  // 4) messages fallback (son mesajlarda sub rozeti var mı)
  try {
    const r = await findSubscriberBadgeFromMessages(channelId, me.username, streamerSlug);
    if (r.ok) {
      if (r.isSub) return { subscribed: true, meta: { method: 'messages', source: 'badge', user: me } };
      return { subscribed: false, meta: { method: 'messages', user: me } };
    }
  } catch (e) {
    // yut
  }

  // 5) Son çare: kanala özgü /me (bazı setuplarda çalışır)
  try {
    const url = `${SITE_ORIGIN}/api/v2/channels/${encodeURIComponent(streamerSlug)}/me`;
    const res = await fetch(url, { headers: siteHeaders(streamerSlug) });
    if (res.ok) {
      const meChannel = await res.json();
      const d3 = deriveSubFromIdentity(meChannel);
      if (d3.isSub) return { subscribed: true, meta: { method: 'channel:me', ...d3, user: me } };
      return { subscribed: false, meta: { method: 'channel:me', user: me } };
    }
  } catch (e) {
    // ignore
  }

  return { subscribed: false, meta: { method: 'all-fallbacks-failed', user: me } };
}

// --- DISCORD CHECK (opsiyonel; KV'ye hala koyabiliyorsun) ---
async function checkDiscordSubscription(accessToken, streamerInfo) {
  const { discordGuildId, discordRoleId, discordBotToken } = streamerInfo || {};
  if (!discordGuildId || !discordRoleId || !discordBotToken) return false;
  const userRes = await fetch('https://discord.com/api/users/@me', {
    headers: { 'Authorization': `Bearer ${accessToken}` }
  });
  if (!userRes.ok) return false;
  const u = await userRes.json();
  const mRes = await fetch(`https://discord.com/api/guilds/${discordGuildId}/members/${u.id}`, {
    headers: { 'Authorization': `Bot ${discordBotToken}` }
  });
  if (!mRes.ok) return false;
  const member = await mRes.json();
  return Array.isArray(member?.roles) && member.roles.includes(discordRoleId);
}

// --- OAUTH EXCHANGE ---
async function exchangeCodeForToken(provider, code, codeVerifier, env) {
  let tokenUrl, body;
  if (provider === 'discord') {
    tokenUrl = 'https://discord.com/api/oauth2/token';
    body = new URLSearchParams({
      client_id: env.DISCORD_CLIENT_ID, client_secret: env.DISCORD_CLIENT_SECRET,
      grant_type: 'authorization_code', code,
      redirect_uri: `${env.APP_URL}/api/auth/callback/discord`,
    });
  } else if (provider === 'kick') {
    tokenUrl = 'https://id.kick.com/oauth/token';
    body = new URLSearchParams({
      client_id: env.KICK_CLIENT_ID, client_secret: env.KICK_CLIENT_SECRET,
      grant_type: 'authorization_code', code,
      redirect_uri: `${env.APP_URL}/api/auth/callback/kick`,
      code_verifier: codeVerifier
    });
  } else {
    throw new Error('Unsupported provider');
  }

  const res = await fetch(tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': UA },
    body
  });
  if (!res.ok) {
    const t = await res.text();
    throw new Error(`Token exchange failed (${res.status})\n${t}`);
  }
  return res.json();
}

// --- ROUTER ---
export async function onRequest(context) {
  try {
    const { request, env } = context;
    const url = new URL(request.url);
    const path = url.pathname.replace(/^\/+/, '');
    const seg = path.split('/').filter(Boolean);
    const db = env.STREAMERS;
    const adminPassword = env.ADMIN_PASSWORD;

    // API TREE
    if (seg[0] === 'api') {
      // Basic admin login (opsiyonel)
      if (seg[1] === 'login' && request.method === 'POST') {
        const { password } = await request.json();
        return new Response(JSON.stringify({ success: !!(adminPassword && password === adminPassword) }), {
          status: (adminPassword && password === adminPassword) ? 200 : 401,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      // Streamers CRUD (KV – yayıncı metni/ids vs.)
      if (seg[1] === 'streamers') {
        if (request.method === 'GET' && !seg[2]) {
          const list = await db.list();
          const streamers = await Promise.all(list.keys.map(async (k) => {
            const v = await db.get(k.name);
            return v ? { slug: k.name, ...JSON.parse(v) } : null;
          }));
          return new Response(JSON.stringify(streamers.filter(Boolean)), { headers: { 'Content-Type': 'application/json' } });
        }
        if (request.method === 'GET' && seg[2]) {
          const v = await db.get(seg[2]);
          if (!v) return new Response(JSON.stringify({ error: 'Streamer not found' }), { status: 404 });
          return new Response(JSON.stringify({ slug: seg[2], ...JSON.parse(v) }), { headers: { 'Content-Type': 'application/json' } });
        }
        if (request.method === 'POST') {
          const { slug, displayText, discordGuildId, discordRoleId, discordBotToken, broadcaster_user_id, password } = await request.json();
          if (adminPassword && password !== adminPassword) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
          if (!slug || !displayText) return new Response(JSON.stringify({ error: 'Slug and display text are required' }), { status: 400 });
          const data = JSON.stringify({ displayText, discordGuildId, discordRoleId, discordBotToken, broadcaster_user_id });
          await db.put(slug, data);
          return new Response(JSON.stringify({ success: true, slug }), { status: 201, headers: { 'Content-Type': 'application/json' } });
        }
        if (request.method === 'DELETE' && seg[2]) {
          const { password } = await request.json();
          if (adminPassword && password !== adminPassword) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
          await db.delete(seg[2]);
          return new Response(JSON.stringify({ success: true }), { status: 200, headers: { 'Content-Type': 'application/json' } });
        }
      }

      // OAuth flows
      if (seg[1] === 'auth') {
        // /api/auth/redirect/:provider?streamer=slug
        if (seg[2] === 'redirect' && seg[3]) {
          const provider = seg[3];
          const streamer = url.searchParams.get('streamer');
          if (!streamer) return new Response('Streamer query parameter is required', { status: 400 });

          const state = crypto.randomUUID();
          let cookieState = { streamer, random: state };
          let authUrl;

          if (provider === 'discord') {
            authUrl = new URL('https://discord.com/api/oauth2/authorize');
            authUrl.searchParams.set('client_id', env.DISCORD_CLIENT_ID);
            authUrl.searchParams.set('redirect_uri', `${env.APP_URL}/api/auth/callback/discord`);
            authUrl.searchParams.set('scope', 'identify guilds.members.read');
          } else if (provider === 'kick') {
            const verifier = generateCodeVerifier();
            const challenge = await generateCodeChallenge(verifier);
            cookieState.codeVerifier = verifier;

            authUrl = new URL('https://id.kick.com/oauth/authorize');
            authUrl.searchParams.set('client_id', env.KICK_CLIENT_ID);
            authUrl.searchParams.set('redirect_uri', `${env.APP_URL}/api/auth/callback/kick`);
            // önemlisi: kullanıcı profili okumak için 'user:read' (bazı sdk'lar 'users:read' der, ikisini de güvene almak için ekleyelim)
            authUrl.searchParams.set('scope', 'user:read users:read');
            authUrl.searchParams.set('code_challenge', challenge);
            authUrl.searchParams.set('code_challenge_method', 'S256');
          } else {
            return new Response('Unsupported provider', { status: 400 });
          }

          authUrl.searchParams.set('response_type', 'code');
          authUrl.searchParams.set('state', state);

          const stateCookie = `oauth_state=${encodeURIComponent(JSON.stringify(cookieState))}; HttpOnly; Path=/; Max-Age=600; Secure; SameSite=Lax`;
          const headers = new Headers({ 'Location': authUrl.toString(), 'Set-Cookie': stateCookie });
          return new Response(null, { status: 302, headers });
        }

        // /api/auth/callback/:provider
        if (seg[2] === 'callback' && seg[3]) {
          const provider = seg[3];
          const code = url.searchParams.get('code');
          const stateParam = url.searchParams.get('state');
          if (!code || !stateParam) return new Response("HATA ADIM 1: 'code' veya 'state' eksik.", { status: 400, headers: { 'Content-Type': 'text/plain' } });

          const cookie = request.headers.get('Cookie');
          const stored = cookie ? decodeURIComponent(cookie.match(/oauth_state=([^;]+)/)?.[1] || '') : null;
          if (!stored) return new Response('HATA ADIM 2: Güvenlik çerezi bulunamadı.', { status: 400, headers: { 'Content-Type': 'text/plain' } });

          const parsed = JSON.parse(stored);
          if (stateParam !== parsed.random) return new Response('HATA ADIM 3: CSRF.', { status: 403, headers: { 'Content-Type': 'text/plain' } });

          let tokens;
          try {
            tokens = await exchangeCodeForToken(provider, code, parsed.codeVerifier, env);
          } catch (e) {
            return new Response(`HATA ADIM 4: Token alınamadı.\n${e.message}`, { status: 500, headers: { 'Content-Type': 'text/plain' } });
          }

          // ABONELİK KONTROLÜ (kick veya discord – discord opsiyonel)
          let isSubscribed = false;
          let debugMeta = {};
          try {
            const streamer = parsed.streamer;
            const streamerInfoJSON = await db.get(streamer);
            const streamerInfo = streamerInfoJSON ? JSON.parse(streamerInfoJSON) : {};

            if (provider === 'discord') {
              isSubscribed = await checkDiscordSubscription(tokens.access_token, streamerInfo);
            } else if (provider === 'kick') {
              // Burada yayıncıdan link istemiyoruz; direkt kimlik/rozete göre karar.
              const r = await checkKickSubscription(tokens.access_token, streamer);
              isSubscribed = !!r.subscribed;
              debugMeta = r.meta || {};
            }
          } catch (e) {
            return new Response(`HATA ADIM 5: Abonelik durumu kontrol edilemedi.\n\nHata detayı:\n${e.message}`, {
              status: 500, headers: { 'Content-Type': 'text/plain' }
            });
          }

          const redirectUrl = new URL(`/${parsed.streamer}`, env.APP_URL);
          redirectUrl.searchParams.set('subscribed', String(isSubscribed));
          redirectUrl.searchParams.set('provider', provider);
          if (debugMeta.method) redirectUrl.searchParams.set('method', debugMeta.method);
          if (debugMeta.expiresAt) redirectUrl.searchParams.set('expires_at', debugMeta.expiresAt);

          const headers = new Headers({ 'Location': redirectUrl.toString(), 'Set-Cookie': 'oauth_state=; HttpOnly; Path=/; Max-Age=0' });
          return new Response(null, { status: 302, headers });
        }
      }

      return new Response('Not Found', { status: 404 });
    }

    // default
    return new Response('Not Found', { status: 404 });
  } catch (err) {
    console.error('KRITIK HATA:', err);
    return new Response(`KRITIK SUNUCU HATASI:\n\n${err.message}\n\nStack Trace:\n${err.stack}`, {
      status: 500,
      headers: { 'Content-Type': 'text/plain' }
    });
  }
}
