/**
 * Gelişmiş Sunucu Kodu (Backend) v8.0 - Nihai Kick API Versiyonlama Çözümü
 * Bu kod, Kick API'sinin v1 ve v2 versiyonları arasındaki belirsizliği çözmek için
 * her iki kullanıcı bilgisi uç noktasını da dener. Bu, "boş cevap" sorununu
 * kesin olarak çözmek için tasarlanmıştır.
 */

// --- PKCE YARDIMCI FONKSİYONLARI ---
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

// --- ANA İSTEK YÖNETİCİSİ ---
async function handleRequest(context) {
    try {
        const { request, env } = context;
        const url = new URL(request.url);
        const pathSegments = url.pathname.split('/').filter(Boolean);

        const db = env.STREAMERS;
        const adminPassword = env.ADMIN_PASSWORD;

        // --- YÖNETİCİ VE VERİ ROTALARI ---
        if (pathSegments[0] === 'api') {
            if (pathSegments[1] === 'login' && request.method === 'POST') {
                const { password } = await request.json();
                if (adminPassword && password === adminPassword) return new Response(JSON.stringify({ success: true }), { status: 200 });
                return new Response(JSON.stringify({ error: 'Invalid password' }), { status: 401 });
            }

            if (pathSegments[1] === 'streamers') {
                if (request.method === 'GET' && !pathSegments[2]) {
                    const list = await db.list();
                    const streamers = await Promise.all(list.keys.map(async (key) => {
                        const value = await db.get(key.name);
                        return value ? { slug: key.name, ...JSON.parse(value) } : null;
                    }));
                    return new Response(JSON.stringify(streamers.filter(s => s)), { headers: { 'Content-Type': 'application/json' }});
                }
                if (request.method === 'GET' && pathSegments[2]) {
                    const value = await db.get(pathSegments[2]);
                    if (!value) return new Response(JSON.stringify({ error: 'Streamer not found' }), { status: 404 });
                    return new Response(JSON.stringify({ slug: pathSegments[2], ...JSON.parse(value) }), { headers: { 'Content-Type': 'application/json' }});
                }
                if (request.method === 'POST') {
                     const { slug, displayText, discordGuildId, discordRoleId, discordBotToken, password } = await request.json();
                    if (password !== adminPassword) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
                    if (!slug || !displayText) return new Response(JSON.stringify({ error: 'Slug and display text are required' }), { status: 400 });
                    const data = JSON.stringify({ displayText, discordGuildId, discordRoleId, discordBotToken });
                    await db.put(slug, data);
                    return new Response(JSON.stringify({ success: true, slug }), { status: 201 });
                }
                if (request.method === 'DELETE' && pathSegments[2]) {
                    const { password } = await request.json();
                    if (password !== adminPassword) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
                    await db.delete(pathSegments[2]);
                    return new Response(JSON.stringify({ success: true }), { status: 200 });
                }
            }

            // --- OAUTH2 GİRİŞ ROTALARI ---
            if (pathSegments[1] === 'auth') {
                if (pathSegments[2] === 'redirect' && pathSegments[3]) {
                    const provider = pathSegments[3];
                    const streamer = url.searchParams.get('streamer');
                    if (!streamer) return new Response('Streamer query parameter is required', { status: 400 });
                    
                    const randomState = crypto.randomUUID();
                    let stateToStoreInCookie = { streamer, random: randomState };
                    let authUrl;

                    if (provider === 'discord') {
                        authUrl = new URL('https://discord.com/api/oauth2/authorize');
                        authUrl.searchParams.set('client_id', env.DISCORD_CLIENT_ID);
                        authUrl.searchParams.set('redirect_uri', `${env.APP_URL}/api/auth/callback/discord`);
                        authUrl.searchParams.set('scope', 'identify guilds.members.read');
                    } else if (provider === 'kick') {
                        const codeVerifier = generateCodeVerifier();
                        const codeChallenge = await generateCodeChallenge(codeVerifier);
                        stateToStoreInCookie.codeVerifier = codeVerifier;
                        
                        authUrl = new URL('https://id.kick.com/oauth/authorize');
                        authUrl.searchParams.set('client_id', env.KICK_CLIENT_ID);
                        authUrl.searchParams.set('redirect_uri', `${env.APP_URL}/api/auth/callback/kick`);
                        authUrl.searchParams.set('scope', 'user:read user:read:subscriptions');
                        authUrl.searchParams.set('code_challenge', codeChallenge);
                        authUrl.searchParams.set('code_challenge_method', 'S256');
                    } else {
                        return new Response('Unsupported provider', { status: 400 });
                    }
                    
                    authUrl.searchParams.set('response_type', 'code');
                    authUrl.searchParams.set('state', randomState);

                    const stateCookie = `oauth_state=${encodeURIComponent(JSON.stringify(stateToStoreInCookie))}; HttpOnly; Path=/; Max-Age=600; Secure; SameSite=Lax`;
                    const headers = new Headers({ 'Location': authUrl.toString(), 'Set-Cookie': stateCookie });
                    return new Response(null, { status: 302, headers });
                }

                if (pathSegments[2] === 'callback' && pathSegments[3]) {
                    const provider = pathSegments[3];

                    const code = url.searchParams.get('code');
                    const stateFromUrl = url.searchParams.get('state');
                    if (!code || !stateFromUrl) {
                        return new Response("HATA ADIM 1: Geri dönüş URL'sinde 'code' veya 'state' parametresi eksik.", { status: 400, headers: { 'Content-Type': 'text/plain' } });
                    }

                    const cookie = request.headers.get('Cookie');
                    const storedStateJSON = cookie ? decodeURIComponent(cookie.match(/oauth_state=([^;]+)/)?.[1] || '') : null;
                    if (!storedStateJSON) {
                        return new Response("HATA ADIM 2: Güvenlik çerezi bulunamadı. Lütfen tekrar giriş yapmayı deneyin.", { status: 400, headers: { 'Content-Type': 'text/plain' } });
                    }

                    const storedState = JSON.parse(storedStateJSON);
                    if (stateFromUrl !== storedState.random) {
                        return new Response("HATA ADIM 3: Güvenlik anahtarları eşleşmiyor. (CSRF Koruması)", { status: 403, headers: { 'Content-Type': 'text/plain' } });
                    }

                    let tokenData;
                    try {
                        tokenData = await exchangeCodeForToken(provider, code, storedState.codeVerifier, env);
                    } catch (error) {
                        return new Response(`HATA ADIM 4: API anahtarı (token) alınamadı.\n\nAPI'den gelen hata:\n${error.message}`, { status: 500, headers: { 'Content-Type': 'text/plain' } });
                    }

                    let isSubscribed = false;
                    try {
                        const { streamer } = storedState;
                        const streamerInfoJSON = await db.get(streamer);
                        if (!streamerInfoJSON) throw new Error(`Yayıncı '${streamer}' veritabanında bulunamadı.`);
                        
                        if (provider === 'discord') {
                            isSubscribed = await checkDiscordSubscription(tokenData.access_token, JSON.parse(streamerInfoJSON));
                        } else if (provider === 'kick') {
                            isSubscribed = await checkKickSubscription(tokenData.access_token, streamer);
                        }
                    } catch (error) {
                        return new Response(`HATA ADIM 5: Abonelik durumu kontrol edilemedi.\n\nHata detayı:\n${error.message}`, { status: 500, headers: { 'Content-Type': 'text/plain' } });
                    }

                    const { streamer } = storedState;
                    const redirectUrl = new URL(`/${streamer}`, env.APP_URL);
                    redirectUrl.searchParams.set('subscribed', isSubscribed);
                    redirectUrl.searchParams.set('provider', provider);
                    
                    const headers = new Headers({ 'Location': redirectUrl.toString(), 'Set-Cookie': 'oauth_state=; HttpOnly; Path=/; Max-Age=0' });
                    return new Response(null, { status: 302, headers });
                }
            }
        }
        return new Response('Not Found', { status: 404 });
    } catch (error) {
        console.error("KRİTİK HATA:", error);
        return new Response(`KRİTİK SUNUCU HATASI:\n\n${error.message}\n\nStack Trace:\n${error.stack}`, {
            status: 500,
            headers: { 'Content-Type': 'text/plain' }
        });
    }
}

// --- YARDIMCI FONKSİYONLARI ---
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
    }

    const response = await fetch(tokenUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
    });
    
    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(errorText);
    }
    return response.json();
}

async function checkDiscordSubscription(accessToken, streamerInfo) {
    const { discordGuildId, discordRoleId, discordBotToken } = streamerInfo;
    if (!discordGuildId || !discordRoleId || !discordBotToken) return false;
    
    const userResponse = await fetch('https://discord.com/api/users/@me', { headers: { 'Authorization': `Bearer ${accessToken}` } });
    if (!userResponse.ok) return false;
    const user = await userResponse.json();

    const memberResponse = await fetch(`https://discord.com/api/guilds/${discordGuildId}/members/${user.id}`, { headers: { 'Authorization': `Bot ${discordBotToken}` } });
    if (!memberResponse.ok) return false;
    const member = await memberResponse.json();
    
    return member.roles.includes(discordRoleId);
}

// NİHAİ DÜZELTME v8.0: API versiyon belirsizliğini gidermek için hem v2 hem de v1 deneniyor.
async function getKickUser(accessToken) {
    const kickApiHeaders = {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36'
    };

    // Önce en güncel olduğu varsayılan v2'yi dene
    const v2ApiUrl = `https://kick.com/api/v2/user`;
    let response = await fetch(v2ApiUrl, { headers: kickApiHeaders });
    
    if (response.ok) {
        const text = await response.text();
        try {
            const user = JSON.parse(text);
            if (user && (user.slug || user.username)) {
                return user; // v2 çalıştı!
            }
        } catch (e) {
            // JSON değilse, bu bir HTML hata sayfası olabilir.
            throw new Error(`Kick API (v2) JSON yerine HTML döndürdü. Sayfanın başı: ${text.substring(0, 500)}`);
        }
    }
    
    // v2 başarısız olursa veya boş cevap verirse, v1'i dene
    const v1ApiUrl = `https://kick.com/api/v1/user`;
    response = await fetch(v1ApiUrl, { headers: kickApiHeaders });

    if (response.ok) {
        const user = await response.json();
        if (user && (user.slug || user.username)) {
            return user; // v1 çalıştı!
        } else {
             throw new Error(`Kick API (v1) kullanıcı verisi yerine boş bir cevap döndürdü. Gelen Cevap: ${JSON.stringify(user)}`);
        }
    }

    // Her ikisi de başarısız olursa
    const errorText = await response.text();
    throw new Error(`Kick API'sinden kullanıcı bilgisi alınamadı (v1 & v2 denendi).\nSon Hata (v1): Durum Kodu: ${response.status}. Cevap: ${errorText}`);
}


async function checkKickSubscription(accessToken, streamerSlug) {
    if (!streamerSlug) return false;
    
    const user = await getKickUser(accessToken);
    const userIdentifier = user.username || user.slug;

    if (!userIdentifier) {
        throw new Error(`Kullanıcı kimliği (username/slug) alınamadı.`);
    }

    const kickApiHeaders = {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36'
    };

    const subApiUrl = `https://kick.com/api/v2/channels/${streamerSlug}/subscribers/${userIdentifier}`;
    const subResponse = await fetch(subApiUrl, { headers: kickApiHeaders });

    if (subResponse.status !== 200 && subResponse.status !== 404) {
        const errorText = await subResponse.text();
        throw new Error(`Kick abonelik API'si beklenmedik bir durum kodu döndürdü (URL: ${subApiUrl}).\nDurum Kodu: ${subResponse.status}.\nGelen Cevap: ${errorText}`);
    }

    return subResponse.status === 200;
}

export const onRequest = handleRequest;

