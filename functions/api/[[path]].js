// functions/api/[[path]].js
/**
 * Kick Abonelik Doğrulama – v18.2
 * Cloudflare Pages Functions (KV: STREAMERS)
 *
 * - Admin POST/PUT: JSON + x-www-form-urlencoded + multipart body parse
 * - slug/displayText trim & normalize
 * - Abonelik kuralı: JSON içinde herhangi derinlikte string `expires_at` VARSA = ABONE
 * - Sıra:
 *    1) /api/v2/channels/{slug}/me  (Bearer + Referer)
 *    2) /api/v2/channels/{channelId}/users/{viewerId}/identity
 *    3) /api/v2/channels/{slug}/users/{username}
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

/* ---------------- Utils ---------------- */
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36";
const JSONH = (obj, status=200)=>new Response(JSON.stringify(obj),{status,headers:{"Content-Type":"application/json; charset=utf-8"}});
const TEXT  = (msg, status=400)=>new Response(msg,{status,headers:{"Content-Type":"text/plain; charset=utf-8"}});

async function readSmartBody(request){
  const ct = (request.headers.get("content-type") || "").toLowerCase();

  if (ct.includes("application/json")){
    try { return await request.json(); } catch {}
  }
  if (ct.includes("application/x-www-form-urlencoded")){
    const text = await request.text();
    const params = new URLSearchParams(text);
    return Object.fromEntries(params.entries());
  }
  if (ct.includes("multipart/form-data")){
    const fd = await request.formData();
    const obj = {};
    for (const [k,v] of fd.entries()){
      obj[k] = (typeof v === "string") ? v : (v?.name || "");
    }
    return obj;
  }
  try { return await request.json(); } catch { return {}; }
}

const normString = (x)=> (x==null ? "" : String(x).trim());
function sanitizeSlug(s){
  s = normString(s).toLowerCase();
  s = s.replace(/[^a-z0-9._-]/g, "-").replace(/-+/g, "-");
  return s;
}

/* ---------------- Headers ---------------- */
function siteHeaders(refererPathOrUrl, bearer){
  const h = {
    Accept:"application/json",
    "User-Agent":UA,
    Referer: refererPathOrUrl?.startsWith("http") ? refererPathOrUrl : `https://kick.com/${refererPathOrUrl||""}`,
    Origin:"https://kick.com",
  };
  if (bearer) h.Authorization = `Bearer ${bearer}`;
  return h;
}

/* ---------------- Kick Viewer (Public API) ---------------- */
async function getKickViewer(accessToken){
  const r = await fetch("https://api.kick.com/public/v1/users", {
    headers:{ Authorization:`Bearer ${accessToken}`, Accept:"application/json", "User-Agent":UA }
  });
  const txt = await r.text();
  let payload={}; try{ payload = txt?JSON.parse(txt):{}; }catch{ throw new Error(`Kick Public API 'users' JSON parse error:\n${txt}`); }
  if(!r.ok) throw new Error(`Kick Public API 'users' hatası (${r.status}):\n${txt}`);

  const rec = Array.isArray(payload?.data) ? payload.data[0] : (payload?.data || payload);
  const user_id = rec?.user_id ?? rec?.id ?? rec?.user?.id ?? null;
  const username = rec?.name ?? rec?.username ?? rec?.slug ?? rec?.user?.username ?? null;
  if(!user_id || !username) throw new Error(`Kick Public API 'users' beklenmeyen cevap:\n${JSON.stringify(payload)}`);

  return { id:user_id, username };
}

/* ---------------- Kick Channel/Identity ---------------- */
async function getChannelBySlug(slug){
  const r = await fetch(`https://kick.com/api/v2/channels/${encodeURIComponent(slug)}`, { headers: siteHeaders(slug) });
  if(!r.ok) throw new Error(`Kanal bilgisi alınamadı (${r.status}): ${await r.text()}`);
  const j = await r.json();
  const channelId = j?.id ?? j?.chatroom?.channel_id ?? j?.user?.streamer_channel?.id;
  if(!channelId) throw new Error(`Kanal ID bulunamadı. Cevap: ${JSON.stringify(j)}`);
  return { channelId };
}

async function getChannelMe(slug, accessToken){
  const url = `https://kick.com/api/v2/channels/${encodeURIComponent(slug)}/me`;
  const r = await fetch(url, { headers: siteHeaders(slug, accessToken) });
  if (r.status === 401 || r.status === 403) return { ok:false, auth:false, raw: await r.text() };
  if (!r.ok) return { ok:false, auth:true, raw: await r.text() };
  return { ok:true, data: await r.json() };
}

async function getIdentityByUserId(channelId, userId, refererSlug){
  const r = await fetch(`https://kick.com/api/v2/channels/${channelId}/users/${userId}/identity`, { headers: siteHeaders(refererSlug) });
  if (r.status === 404) return { ok:true, data:null };
  if (!r.ok) return { ok:false, status:r.status, raw: await r.text() };
  return { ok:true, data: await r.json() };
}

async function getIdentityByUsername(slug, username, refererSlug){
  const r = await fetch(`https://kick.com/api/v2/channels/${encodeURIComponent(slug)}/users/${encodeURIComponent(username)}`, { headers: siteHeaders(refererSlug) });
  if (r.status === 404) return { ok:true, data:null };
  if (!r.ok) return { ok:false, status:r.status, raw: await r.text() };
  return { ok:true, data: await r.json() };
}

/* ---------------- expires_at derin arayıcı ---------------- */
function findExpiresAtDeep(node){
  const stack=[node];
  while(stack.length){
    const cur=stack.pop();
    if(!cur || typeof cur!=="object") continue;
    for(const [k,v] of Object.entries(cur)){
      if(k==="expires_at" && typeof v==="string" && v.trim()) return v;
      if(v && typeof v==="object") stack.push(v);
    }
  }
  return null;
}

/* ---------------- Abonelik Logic ---------------- */
async function checkKickSubscription(accessToken, streamerSlug){
  const viewer = await getKickViewer(accessToken);

  // 1) /me
  const meRes = await getChannelMe(streamerSlug, accessToken);
  if (meRes.ok && meRes.data){
    const ex = findExpiresAtDeep(meRes.data);
    if (ex) return { subscribed:true, method:"me", expires_at:ex };
  }

  const { channelId } = await getChannelBySlug(streamerSlug);

  // 2) identity by userId
  const idRes = await getIdentityByUserId(channelId, viewer.id, streamerSlug);
  if (!idRes.ok) throw new Error(`identity HTTP ${idRes.status||"??"}\n${idRes.raw||""}`);
  if (idRes.data){
    const ex = findExpiresAtDeep(idRes.data);
    if (ex) return { subscribed:true, method:"identity:userId", expires_at:ex };
  }

  // 3) identity by username
  const unRes = await getIdentityByUsername(streamerSlug, viewer.username, streamerSlug);
  if (!unRes.ok) throw new Error(`identity(username) HTTP ${unRes.status||"??"}\n${unRes.raw||""}`);
  if (unRes.data){
    const ex = findExpiresAtDeep(unRes.data);
    if (ex) return { subscribed:true, method:"identity:username", expires_at:ex };
  }

  return { subscribed:false, method:"none" };
}

/* ---------------- OAuth Exchange ---------------- */
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

    // functions/api/[[path]].js altında bazı ortamlarda seg[0] === 'api' olabilir.
    const base = (seg[0] === "api") ? 1 : 0;

    /* --- Admin Login --- */
    if (seg[base] === "login" && method === "POST"){
      const { password } = await readSmartBody(request);
      if (env.ADMIN_PASSWORD && password === env.ADMIN_PASSWORD) return JSONH({ success:true });
      return JSONH({ error:"Invalid password" }, 401);
    }

    /* --- Streamers CRUD --- */
    if (seg[base] === "streamers"){
      // LIST
      if (method === "GET" && !seg[base+1]){
        const list = await STREAMERS.list();
        const items = await Promise.all(list.keys.map(async (k)=>{
          const v = await STREAMERS.get(k.name);
          return v ? { slug:k.name, ...JSON.parse(v) } : null;
        }));
        return JSONH(items.filter(Boolean));
      }

      // GET ONE
      if (method === "GET" && seg[base+1]){
        const key = seg[base+1];
        const v = await STREAMERS.get(key);
        if (!v) return JSONH({ error:"Streamer not found" }, 404);
        return JSONH({ slug:key, ...JSON.parse(v) });
      }

      // CREATE
      if (method === "POST"){
        const b = await readSmartBody(request);

        let slug = sanitizeSlug(b.slug ?? b.Slug ?? b.slugName ?? "");
        let displayText = normString(b.displayText ?? b.DisplayText ?? b.title ?? "");
        const {
          discordGuildId = "", discordRoleId = "", discordBotToken = "", broadcaster_user_id = "", password = ""
        } = b;

        if (env.ADMIN_PASSWORD && password !== env.ADMIN_PASSWORD)
          return JSONH({ error:"Unauthorized" }, 401);

        if (!slug || !displayText)
          return JSONH({ error:"Slug and displayText required" }, 400);

        const rec = { displayText, discordGuildId, discordRoleId, discordBotToken };
        if (broadcaster_user_id) rec.broadcaster_user_id = String(broadcaster_user_id).trim();

        await STREAMERS.put(slug, JSON.stringify(rec));
        return JSONH({ success:true, slug }, 201);
      }

      // UPDATE
      if (method === "PUT" && seg[base+1]){
        const slug = sanitizeSlug(seg[base+1]);
        const exists = await STREAMERS.get(slug);
        if (!exists) return JSONH({ error:"Streamer not found" }, 404);

        const b = await readSmartBody(request);
        const password = b.password ?? "";
        if (env.ADMIN_PASSWORD && password !== env.ADMIN_PASSWORD)
          return JSONH({ error:"Unauthorized" }, 401);

        const cur = JSON.parse(exists);
        const next = {
          displayText: normString(b.displayText ?? cur.displayText),
          discordGuildId: normString(b.discordGuildId ?? cur.discordGuildId),
          discordRoleId: normString(b.discordRoleId ?? cur.discordRoleId),
          discordBotToken: normString(b.discordBotToken ?? cur.discordBotToken),
          broadcaster_user_id: normString(b.broadcaster_user_id ?? cur.broadcaster_user_id)
        };

        if (!next.displayText) return JSONH({ error:"displayText required" }, 400);

        await STREAMERS.put(slug, JSON.stringify(next));
        return JSONH({ success:true, slug });
      }

      // DELETE
      if (method === "DELETE" && seg[base+1]){
        const slug = sanitizeSlug(seg[base+1]);
        const b = await readSmartBody(request);
        if (env.ADMIN_PASSWORD && (b.password ?? "") !== env.ADMIN_PASSWORD)
          return JSONH({ error:"Unauthorized" }, 401);
        await STREAMERS.delete(slug);
        return JSONH({ success:true });
      }
    }

    /* --- OAuth redirect --- */
    if (seg[base] === "auth" && seg[base+1] === "redirect" && seg[base+2]){
      const provider = seg[base+2];
      const streamer = url.searchParams.get("streamer");
      if (!streamer) return TEXT("streamer query param required", 400);

      // PKCE
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
        const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)));
        const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
        const challenge = b64url(new Uint8Array(digest));
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

    /* --- OAuth callback --- */
    if (seg[base] === "auth" && seg[base+1] === "callback" && seg[base+2]){
      const provider = seg[base+2];
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

      // subscription
      let isSubscribed = false;
      try{
        const streamerSlug = parsed.streamer;
        const exists = await env.STREAMERS.get(streamerSlug);
        if (!exists) throw new Error(`Yayıncı '${streamerSlug}' KV'de yok.`);
        if (provider === "kick"){
          const r = await checkKickSubscription(tokenData.access_token, streamerSlug);
          isSubscribed = !!r.subscribed;
        } else {
          isSubscribed = false; // Discord ile abonelik bakmıyoruz
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
  }catch(err){
    console.error("KRITIK HATA:", err);
    return TEXT(`KRITIK SUNUCU HATASI:\n\n${err.message}\n\nStack:\n${err.stack||"no-stack"}`, 500);
  }
}

/* --- tiny PKCE helper --- */
function b64url(bytes){
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+/g,"");
}
