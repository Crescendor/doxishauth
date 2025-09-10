// functions/[[path]].js
/**
 * Kick Abonelik Doğrulama – Strict v17.1
 * Cloudflare Pages Functions (KV: STREAMERS)
 *
 * 🔒 KURAL: expires_at VARSA = ABONE, YOKSA = DEĞİL (badge/fallback yok)
 * 🔁 OAuth: Kick (PKCE) + (opsiyonel) Discord
 * 🔎 Identity: /api/v2/channels/{channelId}/users/{viewerId}/identity
 * 🧰 Viewer:  https://api.kick.com/public/v1/users (Bearer)
 */

export async function onRequest(context) { return handleRequest(context); }

/* ---------------- Utils ---------------- */
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36";
const JSONH = (obj, status=200)=>new Response(JSON.stringify(obj),{status,headers:{"Content-Type":"application/json; charset=utf-8"}});
const TEXT  = (msg, status=400)=>new Response(msg,{status,headers:{"Content-Type":"text/plain; charset=utf-8"}});

async function safeJsonReq(req){ try{ return await req.json(); } catch{ return {}; } }
async function safeText(res){ try{ return await res.text(); } catch{ return ""; } }
async function safeJsonRes(res){ const raw=await res.text(); try{ return JSON.parse(raw); } catch{ return { _raw: raw }; } }

/* ---------------- PKCE ---------------- */
function b64url(bytes){ return btoa(String.fromCharCode(...bytes)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+/g,""); }
function generateCodeVerifier(){ return b64url(crypto.getRandomValues(new Uint8Array(32))); }
async function generateCodeChallenge(verifier){
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return b64url(new Uint8Array(digest));
}

/* ---------------- Headers ---------------- */
function siteHeaders(refererPathOrUrl){
  return {
    Accept:"application/json",
    "User-Agent":UA,
    Referer: refererPathOrUrl?.startsWith("http") ? refererPathOrUrl : `https://kick.com/${refererPathOrUrl||""}`,
    Origin:"https://kick.com",
  };
}

/* ---------------- Kick Viewer (Public API) ---------------- */
async function getKickViewer(accessToken){
  const r = await fetch("https://api.kick.com/public/v1/users", {
    headers:{ Authorization:`Bearer ${accessToken}`, Accept:"application/json", "User-Agent":UA }
  });
  const txt = await r.text();
  let payload={}; try{ payload = txt?JSON.parse(txt):{}; } catch{ throw new Error(`Kick Public API 'users' JSON parse error:\n${txt}`); }
  if(!r.ok) throw new Error(`Kick Public API 'users' hatası (${r.status}):\n${txt}`);

  const rec = Array.isArray(payload?.data) ? payload.data[0] : (payload?.data || payload);
  const user_id = rec?.user_id ?? rec?.id ?? rec?.user?.id ?? null;
  const username = rec?.name ?? rec?.username ?? rec?.slug ?? rec?.user?.username ?? null;
  if(!user_id || !username) throw new Error(`Kick Public API 'users' beklenmeyen cevap:\n${JSON.stringify(payload)}`);

  return { id:user_id, username };
}

/* ---------------- Kick Channel / Identity (Site v2) ---------------- */
async function getChannelBySlug(slug){
  const r = await fetch(`https://kick.com/api/v2/channels/${encodeURIComponent(slug)}`, { headers: siteHeaders(slug) });
  if(!r.ok) throw new Error(`Kanal bilgisi alınamadı (${r.status}): ${await r.text()}`);
  const j = await r.json();
  const channelId = j?.id ?? j?.chatroom?.channel_id ?? j?.user?.streamer_channel?.id;
  if(!channelId) throw new Error(`Kanal ID bulunamadı. Cevap: ${JSON.stringify(j)}`);
  return { channelId };
}
async function getIdentityByUserId(channelId, userId, refererSlug){
  const r = await fetch(`https://kick.com/api/v2/channels/${channelId}/users/${userId}/identity`, { headers: siteHeaders(refererSlug) });
  if (r.status === 404) return { ok:true, data:null };
  if (!r.ok) return { ok:false, status:r.status, raw: await safeText(r) };
  return { ok:true, data: await safeJsonRes(r) };
}

/* ---------------- Strict expires_at rule ---------------- */
/** JSON içinde herhangi derinlikte string bir `expires_at` var mı? */
function hasExpiresAtDeep(node){
  const stack = [node];
  while(stack.length){
    const cur = stack.pop();
    if(!cur || typeof cur !== "object") continue;
    for (const [k,v] of Object.entries(cur)){
      if (k === "expires_at" && typeof v === "string" && v.trim().length>0) return true;
      if (v && typeof v === "object") stack.push(v);
    }
  }
  return false;
}

async function checkKickSubscriptionStrict(accessToken, streamerSlug){
  const viewer = await getKickViewer(accessToken);
  const { channelId } = await getChannelBySlug(streamerSlug);
  const idRes = await getIdentityByUserId(channelId, viewer.id, streamerSlug);
  if (!idRes.ok)   throw new Error(`identity HTTP ${idRes.status || "??"}\n${idRes.raw || ""}`);
  if (!idRes.data) return { subscribed:false, viewer };
  const isSub = hasExpiresAtDeep(idRes.data); // 🔒 tek kural
  return { subscribed:isSub, viewer };
}

/* ---------------- Discord (opsiyonel) ---------------- */
async function checkDiscordSubscription(accessToken, streamerInfo){
  const { discordGuildId, discordRoleId, discordBotToken } = streamerInfo || {};
  if (!discordGuildId || !discordRoleId || !discordBotToken) return false;
  const u = await fetch("https://discord.com/api/users/@me", { headers:{ Authorization:`Bearer ${accessToken}` }});
  if (!u.ok) return false;
  const me = await u.json();
  const m = await fetch(`https://discord.com/api/guilds/${discordGuildId}/members/${me.id}`, { headers:{ Authorization:`Bot ${discordBotToken}` }});
  if (!m.ok) return false;
  const member = await m.json();
  return Array.isArray(member.roles) && member.roles.includes(discordRoleId);
}

/* ---------------- Token Exchange ---------------- */
async function exchangeCodeForToken(provider, code, codeVerifier, env){
  let tokenUrl, body;
  if (provider === "discord"){
    tokenUrl = "https://discord.com/api/oauth2/token";
    body = new URLSearchParams({
      client_id: env.DISCORD_CLIENT_ID, client_secret: env.DISCORD_CLIENT_SECRET,
      grant_type: "authorization_code", code,
      redirect_uri: `${env.APP_URL}/api/auth/callback/discord`,
    });
  } else if (provider === "kick"){
    tokenUrl = "https://id.kick.com/oauth/token";
    body = new URLSearchParams({
      client_id: env.KICK_CLIENT_ID, client_secret: env.KICK_CLIENT_SECRET,
      grant_type: "authorization_code", code,
      redirect_uri: `${env.APP_URL}/api/auth/callback/kick`,
      code_verifier: codeVerifier,
    });
  } else { throw new Error("Unsupported provider"); }

  const r = await fetch(tokenUrl, { method:"POST", headers:{ "Content-Type":"application/x-www-form-urlencoded" }, body });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

/* ---------------- Router ---------------- */
async function handleRequest(context){
  try{
    const { request, env } = context;
    const url = new URL(request.url);
    const seg = url.pathname.replace(/^\/+/, "").split("/").filter(Boolean);
    const method = request.method;
    const STREAMERS = env.STREAMERS;

    if (seg[0] === "api") {

      // Admin login
      if (seg[1] === "login" && method === "POST"){
        const { password } = await safeJsonReq(request);
        if (env.ADMIN_PASSWORD && password === env.ADMIN_PASSWORD) return JSONH({ success:true });
        return JSONH({ error:"Invalid password" }, 401);
      }

      // Streamers CRUD (mevcutta displayText şemasını koruyoruz)
      if (seg[1] === "streamers"){
        if (method === "GET" && !seg[2]){
          const list = await STREAMERS.list();
          const items = await Promise.all(list.keys.map(async (k)=>{
            const v = await STREAMERS.get(k.name);
            return v ? { slug:k.name, ...JSON.parse(v) } : null;
          }));
          return JSONH(items.filter(Boolean));
        }
        if (method === "GET" && seg[2]){
          const v = await STREAMERS.get(seg[2]);
          if (!v) return JSONH({ error:"Streamer not found" }, 404);
          return JSONH({ slug:seg[2], ...JSON.parse(v) });
        }
        if (method === "POST"){
          const { slug, displayText, discordGuildId, discordRoleId, discordBotToken, broadcaster_user_id, password } = await safeJsonReq(request);
          if (env.ADMIN_PASSWORD && password !== env.ADMIN_PASSWORD) return JSONH({ error:"Unauthorized" }, 401);
          if (!slug || !displayText) return JSONH({ error:"Slug and displayText required" }, 400);
          const data = { displayText, discordGuildId, discordRoleId, discordBotToken };
          if (broadcaster_user_id) data.broadcaster_user_id = broadcaster_user_id;
          await STREAMERS.put(slug, JSON.stringify(data));
          return JSONH({ success:true, slug }, 201);
        }
        if (method === "DELETE" && seg[2]){
          const { password } = await safeJsonReq(request);
          if (env.ADMIN_PASSWORD && password !== env.ADMIN_PASSWORD) return JSONH({ error:"Unauthorized" }, 401);
          await STREAMERS.delete(seg[2]);
          return JSONH({ success:true });
        }
      }

      // OAuth redirect
      if (seg[1] === "auth" && seg[2] === "redirect" && seg[3]){
        const provider = seg[3];
        const streamer = url.searchParams.get("streamer");
        if (!streamer) return TEXT("streamer query param required", 400);

        const state = { streamer, random: crypto.randomUUID() };
        let authUrl;

        if (provider === "discord"){
          authUrl = new URL("https://discord.com/api/oauth2/authorize");
          authUrl.searchParams.set("client_id", env.DISCORD_CLIENT_ID);
          authUrl.searchParams.set("redirect_uri", `${env.APP_URL}/api/auth/callback/discord`);
          authUrl.searchParams.set("scope", "identify");
          authUrl.searchParams.set("response_type", "code");
          authUrl.searchParams.set("state", state.random);
        } else if (provider === "kick"){
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
        } else { return TEXT("Unsupported provider", 400); }

        const cookie = `oauth_state=${encodeURIComponent(JSON.stringify(state))}; HttpOnly; Path=/; Max-Age=600; Secure; SameSite=Lax`;
        return new Response(null, { status:302, headers:{ Location: authUrl.toString(), "Set-Cookie": cookie } });
      }

      // OAuth callback
      if (seg[1] === "auth" && seg[2] === "callback" && seg[3]){
        const provider = seg[3];
        const code = url.searchParams.get("code");
        const stateParam = url.searchParams.get("state");
        if (!code || !stateParam) return TEXT("HATA ADIM 1: code/state eksik", 400);

        const cookie = request.headers.get("Cookie");
        const stored = cookie ? decodeURIComponent(cookie.match(/oauth_state=([^;]+)/)?.[1] || "") : null;
        if (!stored) return TEXT("HATA ADIM 2: Güvenlik çerezi yok", 400);

        const parsed = JSON.parse(stored);
        if (stateParam !== parsed.random) return TEXT("HATA ADIM 3: CSRF state eşleşmiyor", 403);

        // token
        let tokenData; try{
          tokenData = await exchangeCodeForToken(provider, code, parsed.codeVerifier, env);
        } catch(e){ return TEXT(`HATA ADIM 4: Token alınamadı\n\n${e.message}`, 500); }

        // strict subscription
        let isSubscribed = false;
        try{
          const streamerSlug = parsed.streamer;
          const sJSON = await STREAMERS.get(streamerSlug);
          if (!sJSON) throw new Error(`Yayıncı '${streamerSlug}' KV'de yok.`);
          if (provider === "discord"){
            // Discord abonelik doğrulaması kullanmıyorsan false kalsın
            isSubscribed = false;
          } else if (provider === "kick"){
            const r = await checkKickSubscriptionStrict(tokenData.access_token, streamerSlug);
            isSubscribed = !!r.subscribed;
          }
        } catch(e){
          return TEXT(`HATA ADIM 5: Abonelik kontrolü başarısız.\n\nDetay:\n${e.message}`, 500);
        }

        const redir = new URL(`/${parsed.streamer}`, env.APP_URL);
        redir.searchParams.set("subscribed", String(isSubscribed));
        redir.searchParams.set("provider", provider);

        return new Response(null, {
          status:302,
          headers:{ Location: redir.toString(), "Set-Cookie":"oauth_state=; HttpOnly; Path=/; Max-Age=0" }
        });
      }

      return TEXT("Not Found", 404);
    }

    return TEXT("Not Found", 404);
  } catch(err){
    console.error("KRITIK HATA:", err);
    return TEXT(`KRITIK SUNUCU HATASI:\n\n${err.message}\n\nStack:\n${err.stack||"no-stack"}`, 500);
  }
}
