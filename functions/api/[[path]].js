/**
 * Kick Abonelik Doğrulama – v10.2 (expires_at-only)
 * Cloudflare Pages Functions (KV: STREAMERS)
 *
 * Sıra:
 *  0a) /api/v2/user/subscriptions         (Authorization, Referer)
 *  0b) /api/v2/channels/{slug}/me         (Authorization, Referer)
 *  1)  /api/v2/channels/{channelId}/users/{viewerId}/identity
 *  2)  /api/v2/channels/{slug}/users/{username}
 *  3)  /api/v2/channels/{slug}/subscribers/{username} (varsa)
 *
 * KURAL: JSON içinde herhangi derinlikte string `expires_at` bulunursa ABONE.
 *
 * ENV: APP_URL, ADMIN_PASSWORD, KICK_CLIENT_ID, KICK_CLIENT_SECRET
 * (opsiyonel Discord: DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET)
 */

export async function onRequest(ctx) { return handleRequest(ctx); }

/* ---------- utils ---------- */
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36";

const JSONH = (obj, status=200) => new Response(JSON.stringify(obj), { status, headers: { "Content-Type":"application/json; charset=utf-8" }});
const TEXT  = (msg, status=400) => new Response(msg, { status, headers: { "Content-Type":"text/plain; charset=utf-8" }});

async function safeJsonReq(req){
  const ct=(req.headers.get("content-type")||"").toLowerCase();
  try{
    if(ct.includes("application/json")) return await req.json();
    const raw=await req.text();
    try{ return JSON.parse(raw||"{}"); }catch{ return Object.fromEntries(new URLSearchParams(raw).entries()); }
  }catch{ return {}; }
}
async function safeText(res){ try{ return await res.text(); }catch{ return ""; } }
async function safeJsonRes(res){ const raw=await res.text(); try{ return JSON.parse(raw); }catch{ return { _raw: raw }; }}

/* ---------- pkce ---------- */
function b64url(bytes){ let s=""; for(let i=0;i<bytes.length;i++) s+=String.fromCharCode(bytes[i]); return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+/g,""); }
function generateCodeVerifier(){ return b64url(crypto.getRandomValues(new Uint8Array(32))); }
async function generateCodeChallenge(verifier){ const d=await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)); return b64url(new Uint8Array(d)); }

/* ---------- headers ---------- */
function siteHeaders(refererPathOrUrl, bearer){
  const h={ Accept:"application/json", "User-Agent":UA, Origin:"https://kick.com",
    Referer: refererPathOrUrl?.startsWith("http") ? refererPathOrUrl : `https://kick.com/${refererPathOrUrl||""}` };
  if(bearer) h.Authorization = `Bearer ${bearer}`;
  return h;
}

/* ---------- deep expires_at ---------- */
function findExpiresAtDeep(node){
  const st=[node];
  while(st.length){
    const cur=st.pop();
    if(!cur || typeof cur!=="object") continue;
    for(const [k,v] of Object.entries(cur)){
      if(k==="expires_at" && typeof v==="string" && v.trim()) return v;
      if(v && typeof v==="object") st.push(v);
    }
  }
  return null;
}

/* ---------- Kick viewer ---------- */
async function getKickViewer(accessToken){
  const r = await fetch("https://api.kick.com/public/v1/users", {
    headers:{ Authorization:`Bearer ${accessToken}`, Accept:"application/json", "User-Agent":UA }
  });
  const txt = await r.text();
  let payload={}; try{ payload=txt?JSON.parse(txt):{}; }catch{ throw new Error(`Kick Public API 'users' JSON parse error:\n${txt}`); }
  if(!r.ok) throw new Error(`Kick Public API 'users' hata (${r.status}):\n${txt}`);

  const rec = Array.isArray(payload?.data) ? payload.data[0] : (payload?.data || payload);
  const user_id = rec?.user_id ?? rec?.id ?? rec?.user?.id ?? null;
  const username = rec?.name ?? rec?.username ?? rec?.slug ?? rec?.user?.username ?? null;

  if(!user_id || !username){
    // website fallback
    const w = await fetch("https://kick.com/api/v1/user", { headers: siteHeaders("", accessToken) });
    const wtxt = await w.text();
    try{
      const j = wtxt?JSON.parse(wtxt):{};
      const u = j?.username || j?.slug || j?.user?.username;
      const id = j?.id || j?.user?.id || null;
      if(u && id) return { id, username:u, profile_picture: j?.profilepic||null };
    }catch{}
    throw new Error(`Kick API'den kullanıcı kimliği alınamadı.\nPublic payload: ${JSON.stringify(payload)}`);
  }
  return { id:user_id, username, profile_picture: rec?.profile_picture ?? rec?.avatar_url ?? null };
}

/* ---------- Channels & Identities ---------- */
async function getChannelBySlug(slug){
  const r=await fetch(`https://kick.com/api/v2/channels/${encodeURIComponent(slug)}`, { headers: siteHeaders(slug) });
  if(!r.ok) throw new Error(`Kanal bilgisi alınamadı (${r.status}): ${await r.text()}`);
  const j=await r.json();
  const channelId = j?.id ?? j?.chatroom?.channel_id ?? j?.user?.streamer_channel?.id;
  if(!channelId) throw new Error(`Kanal ID bulunamadı. Cevap: ${JSON.stringify(j)}`);
  return { channelId, raw:j };
}

async function getChannelMe(slug, bearer){
  const r=await fetch(`https://kick.com/api/v2/channels/${encodeURIComponent(slug)}/me`, { headers: siteHeaders(slug, bearer) });
  if(!r.ok) return { ok:false, status:r.status, raw:await safeText(r) };
  return { ok:true, data:await safeJsonRes(r) };
}

async function getIdentityByUserId(channelId, userId, refererSlug){
  const r=await fetch(`https://kick.com/api/v2/channels/${channelId}/users/${userId}/identity`, { headers: siteHeaders(refererSlug) });
  if(r.status===404) return { ok:true, data:null };
  if(!r.ok) return { ok:false, status:r.status, raw:await safeText(r) };
  return { ok:true, data:await safeJsonRes(r) };
}

async function getIdentityByUsername(slug, username, refererSlug){
  const r=await fetch(`https://kick.com/api/v2/channels/${encodeURIComponent(slug)}/users/${encodeURIComponent(username)}`, { headers: siteHeaders(refererSlug) });
  if(r.status===404) return { ok:true, data:null };
  if(!r.ok) return { ok:false, status:r.status, raw:await safeText(r) };
  return { ok:true, data:await safeJsonRes(r) };
}

async function getSubscriberByUsername(slug, username, bearer){
  const r=await fetch(`https://kick.com/api/v2/channels/${encodeURIComponent(slug)}/subscribers/${encodeURIComponent(username)}`, { headers: siteHeaders(slug, bearer) });
  if(r.status===404) return { ok:true, data:null };
  if(!r.ok) return { ok:false, status:r.status, raw:await safeText(r) };
  return { ok:true, data:await safeJsonRes(r) };
}

/* NEW: kullanıcının tüm abonelikleri */
async function getUserSubscriptions(bearer, refererSlug){
  const r=await fetch(`https://kick.com/api/v2/user/subscriptions`, { headers: siteHeaders(refererSlug, bearer) });
  if(!r.ok) return { ok:false, status:r.status, raw:await safeText(r) };
  return { ok:true, data:await safeJsonRes(r) };
}

/* ---------- evidence ---------- */
function evidence(payload){ const ex=findExpiresAtDeep(payload); return ex ? { hasSubscription:true, source:"expires_at", expires_at:ex } : { hasSubscription:false, source:"none", expires_at:null }; }

/* ---------- main check ---------- */
async function checkKickSubscriptionViewer(accessToken, streamerSlug){
  // 0a) user/subscriptions
  const subs = await getUserSubscriptions(accessToken, streamerSlug);
  if (subs.ok && subs.data){
    const arr = Array.isArray(subs.data) ? subs.data : (Array.isArray(subs.data?.data) ? subs.data.data : []);
    for (const item of arr){
      // slug veya channel eşle
      const slug = item?.channel?.slug || item?.streamer_channel?.slug || item?.user?.streamer_channel?.slug;
      if (slug && String(slug).toLowerCase() === String(streamerSlug).toLowerCase()){
        const ev = evidence(item);
        if (ev.hasSubscription) return { subscribed:true, method:"user/subscriptions", expires_at:ev.expires_at };
      }
    }
  }

  // 0b) /me
  const me = await getChannelMe(streamerSlug, accessToken);
  if (me.ok && me.data){
    const ev = evidence(me.data);
    if (ev.hasSubscription) return { subscribed:true, method:"me", expires_at:ev.expires_at };
  }

  // 1) viewer + channel
  const viewer = await getKickViewer(accessToken);
  const { channelId } = await getChannelBySlug(streamerSlug);

  // 1) identity by userId
  const idRes = await getIdentityByUserId(channelId, viewer.id, streamerSlug);
  if(!idRes.ok) throw new Error(`identity HTTP ${idRes.status||"??"}\n${idRes.raw||""}`);
  if(idRes.data){
    const ev = evidence(idRes.data);
    if(ev.hasSubscription) return { subscribed:true, method:"identity:userId", expires_at:ev.expires_at };
  }

  // 2) identity by username
  const unRes = await getIdentityByUsername(streamerSlug, viewer.username, streamerSlug);
  if(!unRes.ok) throw new Error(`identity(username) HTTP ${unRes.status||"??"}\n${unRes.raw||""}`);
  if(unRes.data){
    const ev = evidence(unRes.data);
    if(ev.hasSubscription) return { subscribed:true, method:"identity:username", expires_at:ev.expires_at };
  }

  // 3) subscribers/{username}
  const sRes = await getSubscriberByUsername(streamerSlug, viewer.username, accessToken);
  if(!sRes.ok) throw new Error(`subscribers(username) HTTP ${sRes.status||"??"}\n${sRes.raw||""}`);
  if(sRes.data){
    const ev = evidence(sRes.data);
    if(ev.hasSubscription) return { subscribed:true, method:"subscribers:username", expires_at:ev.expires_at };
  }

  return { subscribed:false, method:"none" };
}

/* ---------- Discord (opsiyonel) ---------- */
async function checkDiscordSubscription(accessToken, streamerInfo){
  const { discordGuildId, discordRoleId, discordBotToken } = streamerInfo||{};
  if(!discordGuildId || !discordRoleId || !discordBotToken) return false;
  const u=await fetch("https://discord.com/api/users/@me",{ headers:{ Authorization:`Bearer ${accessToken}` }});
  if(!u.ok) return false;
  const me=await u.json();
  const m=await fetch(`https://discord.com/api/guilds/${discordGuildId}/members/${me.id}`, { headers:{ Authorization:`Bot ${discordBotToken}` }});
  if(!m.ok) return false;
  const member=await m.json();
  return Array.isArray(member.roles) && member.roles.includes(discordRoleId);
}

/* ---------- token exchange ---------- */
async function exchangeCodeForToken(provider, code, codeVerifier, env){
  let tokenUrl, body;
  if(provider==="discord"){
    tokenUrl="https://discord.com/api/oauth2/token";
    body=new URLSearchParams({ client_id:env.DISCORD_CLIENT_ID, client_secret:env.DISCORD_CLIENT_SECRET, grant_type:"authorization_code", code, redirect_uri:`${env.APP_URL}/api/auth/callback/discord`});
  } else if(provider==="kick"){
    tokenUrl="https://id.kick.com/oauth/token";
    body=new URLSearchParams({ client_id:env.KICK_CLIENT_ID, client_secret:env.KICK_CLIENT_SECRET, grant_type:"authorization_code", code, redirect_uri:`${env.APP_URL}/api/auth/callback/kick`, code_verifier:codeVerifier });
  } else { throw new Error("Unsupported provider"); }

  const r=await fetch(tokenUrl,{ method:"POST", headers:{ "Content-Type":"application/x-www-form-urlencoded" }, body });
  if(!r.ok) throw new Error(await r.text());
  return r.json();
}

/* ---------- router ---------- */
async function handleRequest(context){
  try{
    const { request, env } = context;
    const url = new URL(request.url);
    const seg = url.pathname.replace(/^\/+/, "").split("/").filter(Boolean);
    const method = request.method;
    const STREAMERS = env.STREAMERS;

    if(seg[0]==="api"){

      /* admin login */
      if(seg[1]==="login" && method==="POST"){
        const { password } = await safeJsonReq(request);
        if(env.ADMIN_PASSWORD && password===env.ADMIN_PASSWORD) return JSONH({ success:true });
        return JSONH({ error:"Invalid password" }, 401);
      }

      /* streamers CRUD */
      if(seg[1]==="streamers"){
        if(method==="GET" && !seg[2]){
          const list=await STREAMERS.list();
          const items=await Promise.all(list.keys.map(async k=>{ const v=await STREAMERS.get(k.name); return v?{ slug:k.name, ...JSON.parse(v)}:null; }));
          return JSONH(items.filter(Boolean));
        }
        if(method==="GET" && seg[2]){
          const v=await STREAMERS.get(seg[2]);
          if(!v) return JSONH({ error:"Streamer not found" },404);
          return JSONH({ slug:seg[2], ...JSON.parse(v) });
        }
        if(method==="POST"){
          const b=await safeJsonReq(request);
          const { password }=b;
          const slug=(b.slug||"").trim();
          const displayText=(b.displayText||"").trim();
          if(env.ADMIN_PASSWORD && password!==env.ADMIN_PASSWORD) return JSONH({ error:"Unauthorized" },401);
          if(!slug || !displayText) return JSONH({ error:"Slug and displayText required" },400);
          const rec={ displayText, discordGuildId:(b.discordGuildId||"").trim(), discordRoleId:(b.discordRoleId||"").trim(), discordBotToken:(b.discordBotToken||"").trim() };
          if(b.broadcaster_user_id) rec.broadcaster_user_id=b.broadcaster_user_id;
          await STREAMERS.put(slug, JSON.stringify(rec));
          return JSONH({ success:true, slug },201);
        }
        if(method==="DELETE" && seg[2]){
          const { password } = await safeJsonReq(request);
          if(env.ADMIN_PASSWORD && password!==env.ADMIN_PASSWORD) return JSONH({ error:"Unauthorized" },401);
          await STREAMERS.delete(seg[2]);
          return JSONH({ success:true });
        }
      }

      /* OAuth redirect */
      if(seg[1]==="auth" && seg[2]==="redirect" && seg[3]){
        const provider=seg[3];
        const streamer=url.searchParams.get("streamer");
        if(!streamer) return TEXT("streamer query param required",400);

        const state={ streamer, random:crypto.randomUUID() };
        let authUrl;

        if(provider==="discord"){
          authUrl=new URL("https://discord.com/api/oauth2/authorize");
          authUrl.searchParams.set("client_id", env.DISCORD_CLIENT_ID);
          authUrl.searchParams.set("redirect_uri", `${env.APP_URL}/api/auth/callback/discord`);
          authUrl.searchParams.set("scope", "identify guilds.members.read");
          authUrl.searchParams.set("response_type","code");
          authUrl.searchParams.set("state", state.random);
        } else if(provider==="kick"){
          const verifier=generateCodeVerifier();
          const challenge=await generateCodeChallenge(verifier);
          state.codeVerifier=verifier;
          authUrl=new URL("https://id.kick.com/oauth/authorize");
          authUrl.searchParams.set("client_id", env.KICK_CLIENT_ID);
          authUrl.searchParams.set("redirect_uri", `${env.APP_URL}/api/auth/callback/kick`);
          authUrl.searchParams.set("scope","user:read"); // viewer bilgisi yeter
          authUrl.searchParams.set("response_type","code");
          authUrl.searchParams.set("code_challenge", challenge);
          authUrl.searchParams.set("code_challenge_method","S256");
          authUrl.searchParams.set("state", state.random);
        } else {
          return TEXT("Unsupported provider",400);
        }

        const cookie=`oauth_state=${encodeURIComponent(JSON.stringify(state))}; HttpOnly; Path=/; Max-Age=600; Secure; SameSite=Lax`;
        return new Response(null,{ status:302, headers:{ Location:authUrl.toString(), "Set-Cookie":cookie }});
      }

      /* OAuth callback */
      if(seg[1]==="auth" && seg[2]==="callback" && seg[3]){
        const provider=seg[3];
        const code=url.searchParams.get("code");
        const stateFromUrl=url.searchParams.get("state");
        if(!code || !stateFromUrl) return TEXT("HATA ADIM 1: code/state eksik",400);

        const cookie=request.headers.get("Cookie");
        const storedJSON=cookie ? decodeURIComponent(cookie.match(/oauth_state=([^;]+)/)?.[1]||"") : null;
        if(!storedJSON) return TEXT("HATA ADIM 2: Güvenlik çerezi yok",400);

        const stored=JSON.parse(storedJSON);
        if(stateFromUrl!==stored.random) return TEXT("HATA ADIM 3: CSRF state eşleşmiyor",403);

        // token
        let token;
        try{ token=await exchangeCodeForToken(provider, code, stored.codeVerifier, env); }
        catch(e){ return TEXT(`HATA ADIM 4: Token alınamadı\n\n${e.message}`,500); }

        // subscription
        let isSub=false, methodUsed="", exp="";
        try{
          const slug=stored.streamer;
          const recJSON=await STREAMERS.get(slug);
          if(!recJSON) throw new Error(`Yayıncı '${slug}' KV'de yok.`);
          const info=JSON.parse(recJSON);

          if(provider==="discord"){
            isSub = await checkDiscordSubscription(token.access_token, info);
            methodUsed="discord-role";
          }else if(provider==="kick"){
            const r=await checkKickSubscriptionViewer(token.access_token, slug);
            isSub=!!r.subscribed; methodUsed=r.method||""; exp=r.expires_at||"";
          }
        }catch(e){
          return TEXT(`HATA ADIM 5: Abonelik kontrolü başarısız.\n\nDetay:\n${e.message}`,500);
        }

        const redir=new URL(`/${stored.streamer}`, env.APP_URL);
        redir.searchParams.set("subscribed", String(isSub));
        redir.searchParams.set("provider", provider);
        if(methodUsed) redir.searchParams.set("method", methodUsed);
        if(exp) redir.searchParams.set("expires_at", exp);

        return new Response(null,{ status:302, headers:{ Location:redir.toString(), "Set-Cookie":"oauth_state=; HttpOnly; Path=/; Max-Age=0" }});
      }

      /* optional debug: /api/test/kick?streamer=slug&token=ACCESS */
      if(seg[1]==="test" && seg[2]==="kick" && method==="GET"){
        const streamer=url.searchParams.get("streamer");
        const token=url.searchParams.get("token");
        if(!streamer) return JSONH({ error:"streamer query required" },400);
        if(!token)    return JSONH({ error:"token query required (Bearer access_token)" },400);
        try{
          const out={};
          const subs=await getUserSubscriptions(token, streamer); out.user_subscriptions=subs;
          if(subs.ok && subs.data) out.user_subscriptions_expires_at = findExpiresAtDeep(subs.data);

          const me=await getChannelMe(streamer, token); out.me=me;
          if(me.ok && me.data) out.me_expires_at=findExpiresAtDeep(me.data);

          const viewer=await getKickViewer(token); out.viewer=viewer;
          const ch=await getChannelBySlug(streamer); out.channel=ch;

          const id1=await getIdentityByUserId(ch.channelId, viewer.id, streamer); out.identity_userId=id1;
          if(id1.ok && id1.data) out.identity_userId_expires_at=findExpiresAtDeep(id1.data);

          const id2=await getIdentityByUsername(streamer, viewer.username, streamer); out.identity_username=id2;
          if(id2.ok && id2.data) out.identity_username_expires_at=findExpiresAtDeep(id2.data);

          const s1=await getSubscriberByUsername(streamer, viewer.username, token); out.subscribers_username=s1;
          if(s1.ok && s1.data) out.subscribers_username_expires_at=findExpiresAtDeep(s1.data);

          const verdict = out.user_subscriptions_expires_at || out.me_expires_at || out.identity_userId_expires_at || out.identity_username_expires_at || out.subscribers_username_expires_at ? "SUBSCRIBED" : "NOT_SUBSCRIBED";
          return JSONH({ ok:true, verdict, out });
        }catch(e){ return JSONH({ ok:false, error:e.message },500); }
      }

      return TEXT("Not Found",404);
    }

    return TEXT("Not Found",404);
  }catch(err){
    console.error("KRITIK HATA:", err);
    return TEXT(`KRITIK SUNUCU HATASI:\n\n${err.message}\n\nStack:\n${err.stack||"no-stack"}`,500);
  }
}
