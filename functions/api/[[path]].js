/**
 * Gelişmiş Sunucu Kodu (Backend) v3.3 - Daha Sağlam Güvenlik ve Hata Raporlama
 * Bu kod, Kick'in gerektirdiği PKCE güvenlik akışını tam olarak uygular.
 * "Internal Server Error" durumunda, sorunun kaynağını göstermek için basit metin tabanlı hata raporu sunar.
 * State yönetimi daha güvenli ve standartlara uygun hale getirildi.
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
    const { request, env } = context;
    const url = new URL(request.url);
    const pathSegments = url.pathname.split('/').filter(Boolean);

    const db = env.STREAMERS;
    const adminPassword = env.ADMIN_PASSWORD;

    // --- YÖNETİCİ VE VERİ ROTALARI ---
    if (pathSegments[0] === 'api') {
        if (pathSegments[1] === 'login' && request.method === 'POST') {
            try {
                const { password } = await request.json();
                if (adminPassword && password === adminPassword) return new Response(JSON.stringify({ success: true }), { status: 200 });
                return new Response(JSON.stringify({ error: 'Invalid password' }), { status: 401 });
            } catch (e) { return new Response(JSON.stringify({ error: 'Bad request' }), { status: 400 }); }
        }

        if (pathSegments[1] === 'streamers') {
            if (request.method === 'GET' && !pathSegments[2]) {
                try {
                    const list = await db.list();
                    const streamers = await Promise.all(list.keys.map(async (key) => {
                        const value = await db.get(key.name);
                        return value ? { slug: key.name, ...JSON.parse(value) } : null;
                    }));
                    return new Response(JSON.stringify(streamers.filter(s => s)), { headers: { 'Content-Type': 'application/json' }});
                } catch (e) { return new Response(JSON.stringify({ error: 'Could not fetch streamers' }), { status: 500 }); }
            }
            if (request.method === 'GET' && pathSegments[2]) {
                const value = await db.get(pathSegments[2]);
                if (!value) return new Response(JSON.stringify({ error: 'Streamer not found' }), { status: 404 });
                return new Response(JSON.stringify({ slug: pathSegments[2], ...JSON.parse(value) }), { headers: { 'Content-Type': 'application/json' }});
            }
            if (request.method === 'POST') {
                 try {
                    const { slug, displayText, discordGuildId, discordRoleId, discordBotToken, password } = await request.json();
                    if (password !== adminPassword) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
                    if (!slug || !displayText) return new Response(JSON.stringify({ error: 'Slug and display text are required' }), { status: 400 });
                    const data = JSON.stringify({ displayText, discordGuildId, discordRoleId, discordBotToken });
                    await db.put(slug, data);
                    return new Response(JSON.stringify({ success: true, slug }), { status: 201 });
                } catch (e) { return new Response(JSON.stringify({ error: 'Bad request' }), { status: 400 }); }
            }
            if (request.method === 'DELETE' && pathSegments[2]) {
                try {
                    const { password } = await request.json();
                    if (password !== adminPassword) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
                    await db.delete(pathSegments[2]);
                    return new Response(JSON.stringify({ success: true }), { status: 200 });
                } catch (e) { return new Response(JSON.stringify({ error: 'Bad request' }), { status: 400 }); }
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
                    authUrl.searchParams.set('scope', 'user:read:subscriptions');
                    authUrl.searchParams.set('code_challenge', codeChallenge);
                    authUrl.searchParams.set('code_challenge_method', 'S256');
                } else {
                    return new Response('Unsupported provider', { status: 400 });
                }
                
                authUrl.searchParams.set('response_type', 'code');
                authUrl.searchParams.set('state', randomState); // URL'e sadece rastgele dizeyi gönder

                const stateCookie = `oauth_state=${encodeURIComponent(JSON.stringify(stateToStoreInCookie))}; HttpOnly; Path=/; Max-Age=600; Secure; SameSite=Lax`;
                const headers = new Headers({ 'Location': authUrl.toString(), 'Set-Cookie': stateCookie });
                return new Response(null, { status: 302, headers });
            }

            if (pathSegments[2] === 'callback' && pathSegments[3]) {
                try {
                    const provider = pathSegments[3];
                    const code = url.searchParams.get('code');
                    const stateFromUrl = url.searchParams.get('state');

                    const cookie = request.headers.get('Cookie');
                    const storedStateJSON = cookie ? decodeURIComponent(cookie.match(/oauth_state=([^;]+)/)?.[1] || '') : null;
                    if (!storedStateJSON) throw new Error("State cookie not found. Please try logging in again.");
                    
                    const storedState = JSON.parse(storedStateJSON);
                    if (!stateFromUrl || stateFromUrl !== storedState.random) throw new Error("State mismatch. CSRF attack detected or old cookie.");

                    const { streamer, codeVerifier } = storedState;
                    const tokenData = await exchangeCodeForToken(provider, code, codeVerifier, env);
                    const streamerInfoJSON = await db.get(streamer);
                    if (!streamerInfoJSON) throw new Error(`Streamer '${streamer}' not found in database.`);
                    
                    const streamerInfo = JSON.parse(streamerInfoJSON);
                    let isSubscribed = false;

                    if (provider === 'discord') {
                        isSubscribed = await checkDiscordSubscription(tokenData.access_token, streamerInfo);
                    } else if (provider === 'kick') {
                        isSubscribed = await checkKickSubscription(tokenData.access_token, streamer);
                    }

                    const redirectUrl = new URL(`/${streamer}`, env.APP_URL);
                    redirectUrl.searchParams.set('subscribed', isSubscribed);
                    redirectUrl.searchParams.set('provider', provider);
                    
                    const headers = new Headers({ 'Location': redirectUrl.toString(), 'Set-Cookie': 'oauth_state=; HttpOnly; Path=/; Max-Age=0' });
                    return new Response(null, { status: 302, headers });

                } catch (error) {
                    console.error(`OAuth callback error:`, error);
                    // YENİLİK: Hata mesajını düz metin olarak tarayıcıda göster
                    return new Response(`Authentication Error:\n\n${error.message}\n\nStack Trace:\n${error.stack}`, {
                        status: 500,
                        headers: { 'Content-Type': 'text/plain' }
                    });
                }
            }
        }
    }
    return new Response('Not Found', { status: 404 });
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
        throw new Error(`${provider} token exchange failed with status ${response.status}: ${errorText}`);
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
    try {
        const userResponse = await fetch('https://kick.com/api/v1/user', { headers: { 'Authorization': `Bearer ${accessToken}`, 'Accept': 'application/json' } });
        if (!userResponse.ok) return false;
        const user = await userResponse.json();
        if (!user.slug) return false;
        const subResponse = await fetch(`https://kick.com/api/v2/channels/${streamerSlug}/subscribers/${user.slug}`);
        return subResponse.status === 200;
    } catch (error) {
        console.error('checkKickSubscription error:', error);
        return false;
    }
}

export const onRequest = handleRequest;

