// functions/api/[[path]].js
/**
 * Kick Abonelik Doğrulama – v19.0 (stabil)
 * Cloudflare Pages Functions (KV: STREAMERS)
 *
 * - OAuth (Kick): PKCE
 * - Abonelik tespiti (sıra):
 *   1) /api/v2/channels/{slug}/me  (Bearer + Referer)
 *   2) /api/v2/channels/{channelId}/users/{viewerId}/identity
 *   3) /api/v2/channels/{slug}/users/{username}
 * - Kural: JSON içinde herhangi derinlikte string "expires_at" VARSA => ABONE
 * - Admin CRUD: çok formatlı body parse (json/form/multipart)
 *
 * ENV: APP_URL, ADMIN_PASSWORD, KICK_CLIENT_ID, KICK_CLIENT_SECRET
 */

export async function onRequest(ctx){ return handleRequest(ctx); }

/* ---------------- Utils ---------------- */
const UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36";
const JSONH=(o,s=200)=>new Response(JSON.stringify(o),{status:s,headers:{"Content-Type":"application/json; charset=utf-8"}});
const TEXT=(m,s=400)=>new Response(m,{status:s,headers:{"Content-Type":"text/plain; charset=utf-8"}});

async function readSmartBody(req){
  const ct=(req.headers.get("content-type")||"").toLowerCase();
  try{
    if (ct.includes("application/json")) return await req.json();
    if (ct.includes("application/x-www-form-urlencoded")){
      const t=await req.text(); return Object.fromEntries(new URLSearchParams(t).entries());
    }
    if (ct.includes("multipart/form-data")){
      const fd=await req.formData(); const o={}; for(const [k,v] of fd.entries()) o[k]=typeof v==="string"?v:(v?.name||""); return o;
    }
    return await req.json();
  }catch{ return {}; }
}
const norm = v => (v==null?"":String(v).trim());
const sanitizeSlug = s => norm(s).toLowerCase().replace(/[^a-z0-9._-]/g,"-").replace(/-+/g,"-");

/* --------------- Headers --------------- */
function siteHeaders(referer, bearer){
  const h={ Accept:"application/json", "User-Agent":UA, Origin:"https://kick.com",
            Referer: referer?.startsWith("http")?referer:`https://kick.com/${referer||""}` };
  if (bearer) h.Authorization=`Bearer ${bearer}`;
  return h;
}

/* --------------- PKCE ------------------ */
function b64url(bytes){ return btoa(String.fromCharCode(...bytes)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+/g,""); }
function genVerifier(){ return b64url(crypto.getRandomValues(new Uint8Array(32))); }
async function codeChallenge(v){ const d=await crypto.subtle.digest("SHA-256", new TextEncoder().encode(v)); return b64url(new Uint8Array(d)); }

/* --------------- Kick APIs ------------- */
async function getKickViewer(accessToken){
  const r=await fetch("https://api.kick.com/public/v1/users",{ headers:{Authorization:`Bearer ${accessToken}`,Accept:"application/json","User-Agent":UA}});
  const raw=await r.text(); let j={}; try{ j=raw?JSON.parse(raw):{} }catch{ throw new Error(`Kick Public API 'users' JSON parse error:\n${raw}`); }
  if(!r.ok) throw new Error(`Kick Public API 'users' hata (${r.status}):\n${raw}`);

  const rec = Array.isArray(j?.data) ? j.data[0] : (j?.data || j);
  const id  = rec?.user_id ?? rec?.id ?? rec?.user?.id;
  const uname = rec?.name ?? rec?.username ?? rec?.slug ?? rec?.user?.username;
  if(!id || !uname) throw new Error(`Kick Public API 'users' beklenmeyen cevap:\n${JSON.stringify(j)}`);
  return { id, username: uname };
}

async function getChannelBySlug(slug){
  const r=await fetch(`https://kick.com/api/v2/channels/${encodeURIComponent(slug)}`, { headers: siteHeaders(slug) });
  if(!r.ok) throw new Error(`Kanal bilgisi alınamadı (${r.status}): ${await r.text()}`);
  const j=await r.json();
  const channelId=j?.id ?? j?.chatroom?.channel_id ?? j?.user?.streamer_channel?.id;
  if(!channelId) throw new Error(`Kanal ID bulunamadı. Cevap: ${JSON.stringify(j)}`);
  return { channelId };
}

async function getChannelMe(slug, bearer){
  const r=await fetch(`https://kick.com/api/v2/channels/${encodeURIComponent(slug)}/me`, { headers: siteHeaders(slug, bearer) });
  if (r.status===401 || r.status===403) return {ok:false,auth:false,raw:await r.text()};
  if (!r.ok) return {ok:false,auth:true,raw:await r.text()};
  return {ok:true,data:await r.json()};
}

async function getIdentityByUserId(channelId, userId, referer){
  const r=await fetch(`https://kick.com/api/v2/channels/${channelId}/users/${userId}/identity`, { headers: siteHeaders(referer) });
  if (r.status===404) return {ok:true,data:null};
  if (!r.ok) return {ok:false,status:r.status,raw:await r.text()};
  return {ok:true,data:await r.json()};
}
async function getIdentityByUsername(slug, username, referer){
  const r=await fetch(`https://kick.com/api/v2/channels/${encodeURIComponent(slug)}/users/${encodeURIComponent(username)}`, { headers: siteHeaders(referer) });
  if (r.status===404) return {ok:true,data:null};
  if (!r.ok) return {ok:false,status:r.status,raw:await r.text()};
  return {ok:true,data:await r.json()};
}

/* --------------- Deep expires_at ------- */
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

/* --------------- Subscription ---------- */
async function checkKickSubscription(accessToken, slug){
  // 0) /me şansı en yüksek
  const me = await getChannelMe(slug, accessToken);
  if (me.ok && me.data){
    const ex = findExpiresAtDeep(me.data);
    if (ex) return {subscribed:true, method:"me", expires_at:ex};
  }

  // 1) viewer + channel
  const viewer = await getKickViewer(accessToken);
  const { channelId } = await getChannelBySlug(slug);

  // 2) identity by userId
  const idRes = await getIdentityByUserId(channelId, viewer.id, slug);
  if (!idRes.ok) throw new Error(`identity HTTP ${idRes.status||"??"}\n${idRes.raw||""}`);
  if (idRes.data){
    const ex = findExpiresAtDeep(idRes.data);
    if (ex) return {subscribed:true, method:"identity:userId", expires_at:ex};
  }

  // 3) identity by username
  const unRes = await getIdentityByUsername(slug, viewer.username, slug);
  if (!unRes.ok) throw new Error(`identity(username) HTTP ${unRes.status||"??"}\n${unRes.raw||""}`);
  if (unRes.data){
    const ex = findExpiresAtDeep(unRes.data);
    if (ex) return {subscribed:true, method:"identity:username", expires_at:ex};
  }

  return {subscribed:false, method:"none"};
}

/* --------------- OAuth exchange -------- */
async function exchangeCodeForToken(provider, code, verifier, env){
  let url, body;
  if (provider==="kick"){
    url="https://id.kick.com/oauth/token";
    body=new URLSearchParams({
      client_id: env.KICK_CLIENT_ID, client_secret: env.KICK_CLIENT_SECRET,
      grant_type: "authorization_code", code,
      redirect_uri: `${env.APP_URL}/api/auth/callback/kick`,
      code_verifier: verifier
    });
  } else if (provider==="discord"){
    url="https://discord.com/api/oauth2/token";
    body=new URLSearchParams({
      client_id: env.DISCORD_CLIENT_ID, client_secret: env.DISCORD_CLIENT_SECRET,
      grant_type: "authorization_code", code,
      redirect_uri: `${env.APP_URL}/api/auth/callback/discord`,
    });
  } else { throw new Error("Unsupported provider"); }

  const r=await fetch(url,{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body});
  if(!r.ok) throw new Error(await r.text());
  return r.json();
}

/* --------------- Router ---------------- */
async function handleRequest({request, env}){
  try{
    const url=new URL(request.url);
    const seg=url.pathname.replace(/^\/+/, "").split("/").filter(Boolean);
    const method=request.method;
    const KV=env.STREAMERS;

    if (seg[0]==="api"){
      // admin login
      if (seg[1]==="login" && method==="POST"){
        const { password } = await readSmartBody(request);
        if (env.ADMIN_PASSWORD && password===env.ADMIN_PASSWORD) return JSONH({success:true});
        return JSONH({error:"Invalid password"},401);
      }

      // streamers
      if (seg[1]==="streamers"){
        if (method==="GET" && !seg[2]){
          const list=await KV.list();
          const items=await Promise.all(list.keys.map(async k=>{
            const v=await KV.get(k.name); return v?{slug:k.name, ...JSON.parse(v)}:null;
          }));
          return JSONH(items.filter(Boolean));
        }
        if (method==="GET" && seg[2]){
          const v=await KV.get(seg[2]); if(!v) return JSONH({error:"Streamer not found"},404);
          return JSONH({slug:seg[2], ...JSON.parse(v)});
        }
        if (method==="POST"){
          const b=await readSmartBody(request);
          const slug=sanitizeSlug(b.slug||"");
          const displayText=norm(b.displayText);
          if (env.ADMIN_PASSWORD && (b.password||"")!==env.ADMIN_PASSWORD) return JSONH({error:"Unauthorized"},401);
          if (!slug || !displayText) return JSONH({error:"Slug and displayText required"},400);
          const rec={
            displayText,
            discordGuildId: norm(b.discordGuildId),
            discordRoleId: norm(b.discordRoleId),
            discordBotToken: norm(b.discordBotToken),
            broadcaster_user_id: norm(b.broadcaster_user_id)
          };
          await KV.put(slug, JSON.stringify(rec));
          return JSONH({success:true, slug},201);
        }
        if (method==="PUT" && seg[2]){
          const key=sanitizeSlug(seg[2]); const cur=await KV.get(key); if(!cur) return JSONH({error:"Streamer not found"},404);
          const b=await readSmartBody(request);
          if (env.ADMIN_PASSWORD && (b.password||"")!==env.ADMIN_PASSWORD) return JSONH({error:"Unauthorized"},401);
          const prev=JSON.parse(cur);
          const next={
            displayText: norm(b.displayText||prev.displayText),
            discordGuildId: norm(b.discordGuildId||prev.discordGuildId),
            discordRoleId: norm(b.discordRoleId||prev.discordRoleId),
            discordBotToken: norm(b.discordBotToken||prev.discordBotToken),
            broadcaster_user_id: norm(b.broadcaster_user_id||prev.broadcaster_user_id),
          };
          if (!next.displayText) return JSONH({error:"displayText required"},400);
          await KV.put(key, JSON.stringify(next));
          return JSONH({success:true, slug:key});
        }
        if (method==="DELETE" && seg[2]){
          const b=await readSmartBody(request);
          if (env.ADMIN_PASSWORD && (b.password||"")!==env.ADMIN_PASSWORD) return JSONH({error:"Unauthorized"},401);
          await KV.delete(seg[2]); return JSONH({success:true});
        }
      }

      // oauth redirect
      if (seg[1]==="auth" && seg[2]==="redirect" && seg[3]){
        const provider=seg[3]; const streamer=url.searchParams.get("streamer");
        if (!streamer) return TEXT("streamer query param required",400);
        const state={streamer, random:crypto.randomUUID()};
        let authUrl;

        if (provider==="kick"){
          const verifier=genVerifier(); state.codeVerifier=verifier;
          const challenge=await codeChallenge(verifier);
          authUrl=new URL("https://id.kick.com/oauth/authorize");
          authUrl.searchParams.set("client_id", env.KICK_CLIENT_ID);
          authUrl.searchParams.set("redirect_uri", `${env.APP_URL}/api/auth/callback/kick`);
          authUrl.searchParams.set("scope", "user:read");
          authUrl.searchParams.set("response_type","code");
          authUrl.searchParams.set("code_challenge", challenge);
          authUrl.searchParams.set("code_challenge_method","S256");
          authUrl.searchParams.set("state", state.random);
        } else if (provider==="discord"){
          authUrl=new URL("https://discord.com/api/oauth2/authorize");
          authUrl.searchParams.set("client_id", env.DISCORD_CLIENT_ID);
          authUrl.searchParams.set("redirect_uri", `${env.APP_URL}/api/auth/callback/discord`);
          authUrl.searchParams.set("scope", "identify");
          authUrl.searchParams.set("response_type","code");
          authUrl.searchParams.set("state", state.random);
        } else return TEXT("Unsupported provider",400);

        const cookie=`oauth_state=${encodeURIComponent(JSON.stringify(state))}; HttpOnly; Path=/; Max-Age=600; Secure; SameSite=Lax`;
        return new Response(null,{status:302,headers:{Location:authUrl.toString(),"Set-Cookie":cookie}});
      }

      // oauth callback
      if (seg[1]==="auth" && seg[2]==="callback" && seg[3]){
        const provider=seg[3];
        const code=url.searchParams.get("code");
        const st=url.searchParams.get("state");
        if(!code || !st) return TEXT("HATA ADIM 1: code/state eksik",400);

        const ck=request.headers.get("Cookie");
        const stored= ck ? decodeURIComponent(ck.match(/oauth_state=([^;]+)/)?.[1]||"") : null;
        if(!stored) return TEXT("HATA ADIM 2: Güvenlik çerezi yok",400);
        const parsed=JSON.parse(stored);
        if(st!==parsed.random) return TEXT("HATA ADIM 3: CSRF state eşleşmiyor",403);

        let token; try{ token=await exchangeCodeForToken(provider, code, parsed.codeVerifier, env); }
        catch(e){ return TEXT(`HATA ADIM 4: Token alınamadı\n\n${e.message}`,500); }

        let isSub=false;
        try{
          const streamerSlug=parsed.streamer;
          const exists=await env.STREAMERS.get(streamerSlug);
          if(!exists) throw new Error(`Yayıncı '${streamerSlug}' KV'de yok.`);
          if (provider==="kick"){
            const r=await checkKickSubscription(token.access_token, streamerSlug);
            isSub=!!r.subscribed;
          } else {
            isSub=false; // discord ile abonelik bakmıyoruz
          }
        }catch(e){ return TEXT(`HATA ADIM 5: Abonelik kontrolü başarısız.\n\nDetay:\n${e.message}`,500); }

        const redir=new URL(`/${parsed.streamer}`, env.APP_URL);
        redir.searchParams.set("subscribed", String(isSub));
        redir.searchParams.set("provider", provider);
        return new Response(null,{status:302,headers:{Location:redir.toString(),"Set-Cookie":"oauth_state=; HttpOnly; Path=/; Max-Age=0"}});
      }

      return TEXT("Not Found",404);
    }

    return TEXT("Not Found",404);
  }catch(err){
    console.error("KRITIK HATA:", err);
    return TEXT(`KRITIK SUNUCU HATASI:\n\n${err.message}\n\nStack:\n${err.stack||"no-stack"}`,500);
  }
}
