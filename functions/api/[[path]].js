/**
 * Gelişmiş Sunucu Kodu (Backend) v4.0 - Nihai Kick Çözümü (Kullanıcı Dokümanına Göre)
 * Bu kod, kullanıcının sağladığı teknik dokümandaki tüm kurallara uyarak,
 * Kick'in gerektirdiği PKCE (Proof Key for Code Exchange) güvenlik akışını tam olarak uygular.
 * Tüm Kick OAuth2 işlemleri artık dokümanda belirtildiği gibi `id.kick.com` üzerinden yapılmaktadır.
 */

// --- PKCE YARDIMCI FONKSİYONLARI ---

// Güvenli, rastgele bir dize oluşturur (code_verifier).
function generateCodeVerifier() {
    const randomBytes = crypto.getRandomValues(new Uint8Array(32));
    // Base64URL formatına uygun hale getir
    return btoa(String.fromCharCode(...randomBytes))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

// Verifier'dan SHA-256 hash'i oluşturur (code_challenge).
async function generateCodeChallenge(verifier) {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const digest = await crypto.subtle.digest('SHA-256', data);
    // Base64URL formatına uygun hale getir
    return btoa(String.fromCharCode(...new Uint8Array(digest)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
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
                        
                        // DOKÜMANDAN ALINAN DOĞRU BİLGİLER
                        authUrl = new URL('https://id.kick.com/oauth/authorize');
                        authUrl.searchParams.set('client_id', env.KICK_CLIENT_ID);
                        authUrl.searchParams.set('redirect_uri', `${env.APP_URL}/api/auth/callback/kick`);
                        authUrl.searchParams.set('scope', 'user:read:subscriptions');
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

                    // ADIM 1: Gerekli parametreler URL'de var mı?
                    const code = url.searchParams.get('code');
                    const stateFromUrl = url.searchParams.get('state');
                    if (!code || !stateFromUrl) {
                        return new Response("HATA ADIM 1: Geri dönüş URL'sinde 'code' veya 'state' parametresi eksik.", { status: 400, headers: { 'Content-Type': 'text/plain' } });
                    }

                    // ADIM 2: Güvenlik çerezi (cookie) mevcut mu?
                    const cookie = request.headers.get('Cookie');
                    const storedStateJSON = cookie ? decodeURIComponent(cookie.match(/oauth_state=([^;]+)/)?.[1] || '') : null;
                    if (!storedStateJSON) {
                        return new Response("HATA ADIM 2: Güvenlik çerezi bulunamadı. Lütfen tekrar giriş yapmayı deneyin.", { status: 400, headers: { 'Content-Type': 'text/plain' } });
                    }

                    // ADIM 3: Güvenlik anahtarları eşleşiyor mu?
                    const storedState = JSON.parse(storedStateJSON);
                    if (stateFromUrl !== storedState.random) {
                        return new Response("HATA ADIM 3: Güvenlik anahtarları eşleşmiyor. (CSRF Koruması)", { status: 403, headers: { 'Content-Type': 'text/plain' } });
                    }

                    let tokenData;
                    try {
                        // ADIM 4: Geçici kod, kalıcı anahtar (token) ile takas ediliyor mu?
                        tokenData = await exchangeCodeForToken(provider, code, storedState.codeVerifier, env);
                    } catch (error) {
                        return new Response(`HATA ADIM 4: API anahtarı (token) alınamadı.\n\nAPI'den gelen hata:\n${error.message}`, { status: 500, headers: { 'Content-Type': 'text/plain' } });
                    }

                    let isSubscribed = false;
                    try {
                        // ADIM 5: Abonelik durumu kontrol ediliyor mu?
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

                    // BAŞARILI!
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
        // En dış katmanda hata yakalama
        console.error("KRİTİK HATA:", error);
        return new Response(`KRİTİK SUNUCU HATASI:\n\n${error.message}\n\nStack Trace:\n${error.stack}`, {
            status: 500,
            headers: { 'Content-Type': 'text/plain' }
        });
    }
}

// --- YARDIMCI FONKSİYONLAR ---
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
        // DOKÜMANDAN ALINAN DOĞRU BİLGİLER
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

async function checkKickSubscription(accessToken, streamerSlug) {
    if (!streamerSlug) return false;
    const userResponse = await fetch('https://kick.com/api/v1/user', { headers: { 'Authorization': `Bearer ${accessToken}`, 'Accept': 'application/json' } });
    if (!userResponse.ok) throw new Error("Kick API'sinden kullanıcı bilgisi alınamadı.");
    const user = await userResponse.json();
    if (!user.slug) throw new Error("Kick API'sinden gelen yanıtta kullanıcı adı (slug) bulunamadı.");
    const subResponse = await fetch(`https://kick.com/api/v2/channels/${streamerSlug}/subscribers/${user.slug}`);
    if (subResponse.status !== 200 && subResponse.status !== 404) {
        throw new Error(`Kick abonelik API'si beklenmedik bir durum kodu döndürdü: ${subResponse.status}`);
    }
    return subResponse.status === 200;
}

export const onRequest = handleRequest;

