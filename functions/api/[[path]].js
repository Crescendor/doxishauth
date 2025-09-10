/**
 * Kick Abonelik Doğrulama – v10.7
 * Cloudflare Pages Functions (KV: STREAMERS)
 *
 * ✅ Admin login fix:
 *   - password ve ENV normalize (trim + NFKC)
 *   - güvenli karşılaştırma (süre bazlı kısa devre yok)
 *   - Aynı kontrol /api/login ve /api/streamers POST/PUT/DELETE için ortak
 *   - /api/admin/diag teşhis ucu: { hasAdminPassword, adminLength } (değer göstermez)
 *
 * 🟢 Abonelik kuralı (değişmedi):
 *   - JSON içinde herhangi derinlikte "expires_at" string → ABONE
 *   - Veya /api/v2/channels/{slug}/users/{username} badges[*].type === "subscriber" → ABONE
 *   - Fallback: /user/subscriptions, /channels/{slug}/me, identity (userId/username), subscribers/{username}
 *
 * ENV: APP_URL, ADMIN_PASSWORD, KICK_CLIENT_ID, KICK_CLIENT_SECRET
 *      (opsiyonel) DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET
 */

export async function onRequest(ctx){ return handleRequest(ctx); }

/* -------------------- Utilities -------------------- */
const UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36";

const JSONH=(obj,status=200)=>new Response(JSON.stringify(obj),{status,headers:{"Content-Type":"application/json; charset=utf-8"}});
const TEXT =(msg,status=400)=>new Response(msg,{status,headers:{"Content-Type":"text/plain; charset=utf-8"}});

const norm = (s) => (s==null ? "" : String(s)).normalize("NFKC").trim();
function eqSecure(a,b){
  // Süre temelli kısa devreyi azaltmak için sabit süreli karşılaştırma
  if(a.length !== b.length) return false;
  let r=0; for(let i=0;i<a.length;i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r===0;
}
function isAdminAuthorized(provided, env){
  const need = norm(env.ADMIN_PASSWORD);
  const got  = norm(provided);
  if(need.length===0){ // ENV yoksa dev mod: izin ver
    return { ok:true, mode:"dev" };
  }
  const ok = eqSecure(got, need);
  return { ok, mode:"strict" };
}

async function safeJsonReq(req){
  const ct=(req.headers.get("content-type")||"").toLowerCase();
  try{
    if(ct.includes("application/json")) return await req.json();
    if(ct.includes("application/x-www-form-urlencoded")){
      const t=await req.text(); return Object.fromEntries(new URLSearchParams(t).entries());
    }
    if(ct.includes("multipart/form-data")){
      const fd=await req.formData(); const o={}; for(const [k,v] of fd.entries()) o[k]=typeof v==="string"?v:(v?.name||""); return o;
    }
    const raw=await req.text(); try{ return JSON.parse(raw||"{}"); }catch{ return Object.fromEntries(new URLSearchParams(raw).entries()); }
  }catch{ return {}; }
}
async function safeText(res){ try{ return await res.text(); }catch{ return ""; } }
async function safeJsonRes(res){ const raw=await res.text(); try{ return JSON.parse(raw); }catch{ return { _raw: raw }; }}

/* -------------------- PKCE -------------------- */
function b64url(bytes){ let s=""; for(let i=0;i<bytes.length;i++) s+=String.fromCharCode(bytes[i]); return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+/g,""); }
function generateCodeVerifier(){ return b64url(crypto.getRandomValues(new Uint8Array(32))); }
async function generateCodeChallenge(v){ const d=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(v)); return b64url(new Uint8Array(d)); }

/* -------------------- Headers -------------------- */
function siteHeaders(refererPathOrUrl, bearer){
  const h={ Accept:"application/json", "User-Agent":UA, Origin:"https://kick.com",
    Referer: refererPathOrUrl?.startsWith("http")? refererPathOrUrl : `https://kick.com/${refererPathOrUrl||""}` };
  if(bearer) h.Authorization=`Bearer ${bearer}`;
  return h;
}

/* -------------------- Deep expires_at -------------------- */
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

/* -------------------- Kick Viewer -------------------- */
async function getKickViewer(accessToken){
  const r=await fetch("https://api.kick.com/public/v1/users",{
    headers:{ Authorization:`Bearer ${accessToken}`, Accept:"application/json", "User-Agent":UA }
  });
  const txt=await r.text();
  let payload={}; try{ payload=txt?JSON.parse(txt):{}; }catch{ throw new Error(`Kick Public API 'users' JSON parse error:\n${txt}`); }
  if(!r.ok) throw new Error(`Kick Public API 'users' hata (${r.status}):\n${txt}`);

  const rec=Array.isArray(payload?.data)?payload.data[0]:(payload?.data||payload);
  let user_id = rec?.user_id ?? rec?.id ?? rec?.user?.id ?? null;
  let username= rec?.name ?? rec?.username ?? rec?.slug ?? rec?.user?.username ?? null;

  if(!user_id || !username){
    const w=await fetch("https://kick.com/api/v1/user",{ headers: siteHeaders("", accessToken) });
    const wtxt=await w.text();
    try{
      const j=wtxt?JSON.parse(wtxt):{};
      const u=j?.username||j?.slug||j?.user?.username;
      const id=j?.id||j?.user?.id||null;
      if(u && id){ user_id=id; username=u; }
    }catch{}
  }

  if(!user_id || !username) throw new Error(`Kick API'den kullanıcı kimliği alınamadı. Payload: ${JSON.stringify(payload)}`);
  return { id:user_id, username };
}

/* -------------------- Channel & Identity -------------------- */
async function getChannelBySlug(slug){
  const r=await fetch(`https://kick.com/api/v2/channels/${encodeURIComponent(slug)}`,{ headers: siteHeaders(slug) });
  if(!r.ok) throw new Error(`Kanal bilgisi alınamadı (${r.status}): ${await r.text()}`);
  const j=await r.json();
  const channelId=j?.id ?? j?.chatroom?.channel_id ?? j?.user?.streamer_channel?.id;
  if(!channelId) throw new Error(`Kanal ID bulunamadı. Cevap: ${JSON.stringify(j)}`);
  return { channelId, raw:j };
}

async function getUserSubscriptions(bearer, refererSlug){
  const r=await fetch(`https://kick.com/api/v2/user/subscriptions`,{ headers: siteHeaders(refererSlug, bearer) });
  if(!r.ok) return { ok:false, status:r.status, raw:await safeText(r) };
  return { ok:true, data:await safeJsonRes(r) };
}
async function getChannelMe(slug, bearer){
  const r=await fetch(`https://kick.com/api/v2/channels/${encodeURIComponent(slug)}/me`,{ headers: siteHeaders(slug, bearer) });
  if(!r.ok) return { ok:false, status:r.status, raw:await safeText(r) };
  return { ok:true, data:await safeJsonRes(r) };
}
async function getIdentityByUserId(channelId, userId, refererSlug){
  const r=await fetch(`https://kick.com/api/v2/channels/${channelId}/users/${userId}/identity`,{ headers: siteHeaders(refererSlug) });
  if(r.status===404) return { ok:true, data:null };
  if(!r.ok) return { ok:false, status:r.status, raw:await safeText(r) };
  return { ok:true, data:await safeJsonRes(r) };
}
async function getIdentityByUsername(slug, username, refererSlug){
  const r=await fetch(`https://kick.com/api/v2/channels/${encodeURIComponent(slug)}/users/${encodeURIComponent(username)}`,{ headers: siteHeaders(refererSlug) });
  if(r.status===404) return { ok:true, data:null };
  if(!r.ok) return { ok:false, status:r.status, raw:await safeText(r) };
  return { ok:true, data:await safeJsonRes(r) };
}
async function getSubscriberByUsername(slug, username, bearer){
  const r=await fetch(`https://kick.com/api/v2/channels/${encodeURIComponent(slug)}/subscribers/${encodeURIComponent(username)}`,{ headers: siteHeaders(slug, bearer) });
  if(r.status===404) return { ok:true, data:null };
  if(!r.ok) return { ok:false, status:r.status, raw:await safeText(r) };
  return { ok:true, data:await safeJsonRes(r) };
}

/* -------------------- Evidence helpers -------------------- */
function isSubBadge(b){
  const vals=[b?.type,b?.name,b?.text,b?.title,b?.label].filter(Boolean).map(x=>String(x).toLowerCase());
  if(vals.includes("subscriber")) return true;
  return vals.some(x=>x.includes("sub"));
}
function evidence(obj){
  const ex=findExpiresAtDeep(obj);
  if(ex) return { hasSubscription:true, source:"expires_at", expires_at:ex };

  const badges = Array.isArray(obj?.badges) ? obj.badges
                : Array.isArray(obj?.identity?.badges) ? obj.identity.badges
                : Array.isArray(obj?.user_identity?.badges) ? obj.user_identity.badges
                : Array.isArray(obj?.data?.badges) ? obj.data.badges
                : null;
  if(Array.isArray(badges) && badges.some(isSubBadge))
    return { hasSubscription:true, source:"badge:subscriber", expires_at:null };

  return { hasSubscription:false, source:"none", expires_at:null };
}

/* -------------------- Main Kick Check -------------------- */
async function checkKickSubscriptionViewer(accessToken, streamerSlug){
  const subs=await getUserSubscriptions(accessToken, streamerSlug);
  if(subs.ok && subs.data){
    const arr=Array.isArray(subs.data)?subs.data:(Array.isArray(subs.data?.data)?subs.data.data:[]);
    for(const item of arr){
      const slug=item?.channel?.slug || item?.streamer_channel?.slug || item?.user?.streamer_channel?.slug;
      if(slug && String(slug).toLowerCase()===String(streamerSlug).toLowerCase()){
        const ev=evidence(item); if(ev.hasSubscription) return { subscribed:true, method:"user/subscriptions", expires_at:ev.expires_at, viewerId:null, viewerUsername:null, channelId:null };
      }
    }
  }
  const me=await getChannelMe(streamerSlug, accessToken);
  if(me.ok && me.data){
    const ev=evidence(me.data); if(ev.hasSubscription) return { subscribed:true, method:"channels/me", expires_at:ev.expires_at, viewerId:null, viewerUsername:null, channelId:null };
  }

  const viewer=await getKickViewer(accessToken);
  const { channelId }=await getChannelBySlug(streamerSlug);

  const idRes=await getIdentityByUserId(channelId, viewer.id, streamerSlug);
  if(!idRes.ok) throw new Error(`identity HTTP ${idRes.status||"??"}\n${idRes.raw||""}`);
  if(idRes.data){
    const ev=evidence(idRes.data);
    if(ev.hasSubscription) return { subscribed:true, method:"identity:userId", expires_at:ev.expires_at, viewerId:viewer.id, viewerUsername:viewer.username, channelId };
  }

  const unRes=await getIdentityByUsername(streamerSlug, viewer.username, streamerSlug);
  if(!unRes.ok) throw new Error(`identity(username) HTTP ${unRes.status||"??"}\n${unRes.raw||""}`);
  if(unRes.data){
    const ev=evidence(unRes.data);
    if(ev.hasSubscription) return { subscribed:true, method:"users:badge", expires_at:ev.expires_at, viewerId:viewer.id, viewerUsername:viewer.username, channelId };
  }

  const sRes=await getSubscriberByUsername(streamerSlug, viewer.username, accessToken);
  if(!sRes.ok) throw new Error(`subscribers(username) HTTP ${sRes.status||"??"}\n${sRes.raw||""}`);
  if(sRes.data){
    const ev=evidence(sRes.data);
    if(ev.hasSubscription) return { subscribed:true, method:"subscribers:username", expires_at:ev.expires_at, viewerId:viewer.id, viewerUsername:viewer.username, channelId };
  }

  return { subscribed:false, method:"none", viewerId:viewer.id, viewerUsername:viewer.username, channelId };
}

/* -------------------- Discord -------------------- */
async function getDiscordMe(accessToken){
  const r=await fetch("https://discord.com/api/users/@me",{ headers:{ Authorization:`Bearer ${accessToken}` }});
  if(!r.ok) throw new Error(`Discord /@me HTTP ${r.status}: ${await r.text()}`);
  return r.json();
}
async function checkDiscordSubscription(accessToken, streamerInfo){
  const { discordGuildId, discordRoleId, discordBotToken } = streamerInfo || {};
  if(!discordGuildId || !discordRoleId || !discordBotToken) return { hasRole:false, userId:null };
  const me=await getDiscordMe(accessToken);
  const m=await fetch(`https://discord.com/api/guilds/${discordGuildId}/members/${me.id}`,{ headers:{ Authorization:`Bot ${discordBotToken}` }});
  if(!m.ok) return { hasRole:false, userId:me.id };
  const member=await m.json();
  return { hasRole: Array.isArray(member.roles) && member.roles.includes(discordRoleId), userId:me.id };
}

/* -------------------- Token Exchange -------------------- */
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

/* -------------------- Router -------------------- */
async function handleRequest(context){
  try{
    const { request, env } = context;
    const url=new URL(request.url);
    const seg=url.pathname.replace(/^\/+/, "").split("/").filter(Boolean);
    const method=request.method;
    const STREAMERS=env.STREAMERS;

    if(seg[0]==="api"){
      // Health & Diag
      if(seg[1]==="health" && method==="GET"){ return JSONH({ ok:true, now:Date.now() }); }
      if(seg[1]==="admin" && seg[2]==="diag" && method==="GET"){
        const val = norm(env.ADMIN_PASSWORD);
        return JSONH({ hasAdminPassword: val.length>0, adminLength: val.length });
      }

      // Admin login
      if(seg[1]==="login" && method==="POST"){
        const body = await safeJsonReq(request);
        const provided = body.password ?? body.pass ?? body.p ?? "";
        const auth = isAdminAuthorized(provided, env);
        if(auth.ok) return JSONH({ success:true, mode:auth.mode });
        return JSONH({ error:"Invalid password" }, 401);
      }

      // Streamers CRUD
      if(seg[1]==="streamers"){
        if(method==="GET" && !seg[2]){
          const list=await STREAMERS.list();
          const items=await Promise.all(list.keys.map(async k=>{ const v=await STREAMERS.get(k.name); return v?{ slug:k.name, ...JSON.parse(v) }:null; }));
          return JSONH(items.filter(Boolean));
        }
        if(method==="GET" && seg[2]){
          const v=await STREAMERS.get(seg[2]); if(!v) return JSONH({ error:"Streamer not found" },404);
          return JSONH({ slug:seg[2], ...JSON.parse(v) });
        }
        if(method==="POST"){
          const b=await safeJsonReq(request);
          const provided = b.password ?? b.pass ?? b.p ?? "";
          const auth = isAdminAuthorized(provided, env);
          if(!auth.ok) return JSONH({ error:"Unauthorized" },401);

          const slug=norm(b.slug);
          const displayTextRaw=norm(b.displayText||b.title);
          if(!slug || !displayTextRaw) return JSONH({ error:"Slug and displayText required" },400);

          const rec={
            displayText: displayTextRaw,
            title: norm(b.title) || displayTextRaw,
            subtitle: norm(b.subtitle),
            customBackgroundUrl: norm(b.customBackgroundUrl),
            kickRedirectorUrl: norm(b.kickRedirectorUrl),
            discordRedirectorUrl: norm(b.discordRedirectorUrl),
            botghostWebhookUrl: norm(b.botghostWebhookUrl),
            discordGuildId: norm(b.discordGuildId),
            discordRoleId: norm(b.discordRoleId),
            discordBotToken: norm(b.discordBotToken),
            broadcaster_user_id: b.broadcaster_user_id || null
          };
          await STREAMERS.put(slug, JSON.stringify(rec));
          return JSONH({ success:true, slug },201);
        }
        if(method==="PUT" && seg[2]){
          const b=await safeJsonReq(request);
          const provided = b.password ?? b.pass ?? b.p ?? "";
          const auth = isAdminAuthorized(provided, env);
          if(!auth.ok) return JSONH({ error:"Unauthorized" },401);

          const v=await STREAMERS.get(seg[2]); if(!v) return JSONH({ error:"Streamer not found" },404);
          const cur=JSON.parse(v);
          const patch={ ...cur, ...b };

          // Normalize editable fields
          if("title" in patch) patch.title = norm(patch.title);
          if("displayText" in patch) patch.displayText = norm(patch.displayText);
          if(!patch.displayText && patch.title) patch.displayText = patch.title;

          const fields = ["subtitle","customBackgroundUrl","kickRedirectorUrl","discordRedirectorUrl","botghostWebhookUrl","discordGuildId","discordRoleId","discordBotToken"];
          for(const f of fields) if(f in patch) patch[f] = norm(patch[f]);

          await STREAMERS.put(seg[2], JSON.stringify(patch));
          return JSONH({ success:true, slug:seg[2] });
        }
        if(method==="DELETE" && seg[2]){
          const b=await safeJsonReq(request);
          const provided = b.password ?? b.pass ?? b.p ?? "";
          const auth = isAdminAuthorized(provided, env);
          if(!auth.ok) return JSONH({ error:"Unauthorized" },401);

          await STREAMERS.delete(seg[2]);
          return JSONH({ success:true });
        }
      }

      // OAuth redirect
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
          authUrl.searchParams.set("scope","identify guilds.members.read");
          authUrl.searchParams.set("response_type","code");
          authUrl.searchParams.set("state", state.random);
        } else if(provider==="kick"){
          const verifier=generateCodeVerifier(); const challenge=await generateCodeChallenge(verifier); state.codeVerifier=verifier;
          authUrl=new URL("https://id.kick.com/oauth/authorize");
          authUrl.searchParams.set("client_id", env.KICK_CLIENT_ID);
          authUrl.searchParams.set("redirect_uri", `${env.APP_URL}/api/auth/callback/kick`);
          authUrl.searchParams.set("scope","user:read");
          authUrl.searchParams.set("response_type","code");
          authUrl.searchParams.set("code_challenge",challenge);
          authUrl.searchParams.set("code_challenge_method","S256");
          authUrl.searchParams.set("state", state.random);
        } else { return TEXT("Unsupported provider",400); }

        const cookie=`oauth_state=${encodeURIComponent(JSON.stringify(state))}; HttpOnly; Path=/; Max-Age=600; Secure; SameSite=Lax`;
        return new Response(null,{ status:302, headers:{ Location:authUrl.toString(), "Set-Cookie":cookie }});
      }

      // OAuth callback
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

        let token; try{ token=await exchangeCodeForToken(provider, code, stored.codeVerifier, env); }
        catch(e){ return TEXT(`HATA ADIM 4: Token alınamadı\n\n${e.message}`,500); }

        let isSub=false, methodUsed="", exp="", kickViewerId="", kickUsername="", discordUserId="";
        try{
          const slug=stored.streamer;
          const recJSON=await STREAMERS.get(slug);
          if(!recJSON) throw new Error(`Yayıncı '${slug}' KV'de yok.`);
          const info=JSON.parse(recJSON);

          if(provider==="discord"){
            const me=await getDiscordMe(token.access_token);
            discordUserId=String(me.id||"");
            await checkDiscordSubscription(token.access_token, info);
          } else if(provider==="kick"){
            const r=await checkKickSubscriptionViewer(token.access_token, slug);
            isSub=!!r.subscribed; methodUsed=r.method||""; exp=r.expires_at||"";
            kickViewerId=r.viewerId?String(r.viewerId):""; kickUsername=r.viewerUsername||"";
          }
        }catch(e){
          return TEXT(`HATA ADIM 5: Abonelik kontrolü başarısız.\n\nDetay:\n${e.message}`,500);
        }

        const redir=new URL(`/${stored.streamer}`, env.APP_URL);
        redir.searchParams.set("subscribed", String(isSub));
        redir.searchParams.set("provider", provider);
        if(methodUsed) redir.searchParams.set("method", methodUsed);
        if(exp) redir.searchParams.set("expires_at", exp);
        if(kickViewerId) redir.searchParams.set("kick_viewer_id", kickViewerId);
        if(kickUsername) redir.searchParams.set("kick_username", kickUsername);
        if(discordUserId) redir.searchParams.set("discord_user_id", discordUserId);

        return new Response(null,{ status:302, headers:{ Location:redir.toString(), "Set-Cookie":"oauth_state=; HttpOnly; Path=/; Max-Age=0" }});
      }

      return TEXT("Not Found",404);
    }

    // statik dosyaları Pages servis ediyor
    return TEXT("Not Found",404);
  }catch(err){
    console.error("KRITIK HATA:", err);
    return TEXT(`KRITIK SUNUCU HATASI:\n\n${err.message}\n\nStack:\n${err.stack||"no-stack"}`,500);
  }
}
