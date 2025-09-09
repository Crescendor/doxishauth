/**
 * Gelişmiş Sunucu Kodu (Backend) v3.0 - Nihai Kick Çözümü (PKCE Destekli)
 * Bu kod, Kick'in gerektirdiği PKCE (Proof Key for Code Exchange) güvenlik akışını tam olarak uygular.
 * Tüm Kick OAuth2 işlemleri artık dokümanda belirtildiği gibi `id.kick.com` üzerinden yapılmaktadır.
 */

// --- PKCE YARDIMCI FONKSİYONLARI ---

// Güvenli, rastgele bir dize oluşturur.
function generateCodeVerifier() {
    const randomBytes = crypto.getRandomValues(new Uint8Array(32));
    return btoa(String.fromCharCode(...randomBytes))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

// Verifier'dan SHA-256 hash'i oluşturur.
async function generateCodeChallenge(verifier) {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const digest = await crypto.subtle.digest('SHA-256', data);
    return btoa(String.fromCharCode(...new Uint8Array(digest)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
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
        // Rota: /api/login
        if (pathSegments[1] === 'login' && request.method === 'POST') {
            try {
                const { password } = await request.json();
                if (adminPassword && password === adminPassword) {
                    return new Response(JSON.stringify({ success: true }), { status: 200 });
                }
                return new Response(JSON.stringify({ error: 'Invalid password' }), { status: 401 });
            } catch (e) {
                return new Response(JSON.stringify({ error: 'Bad request' }), { status: 400 });
            }
        }

        // Rota: /api/streamers
        if (pathSegments[1] === 'streamers') {
            // GET /api/streamers (Tümünü listele)
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
            // GET /api/streamers/:slug (Tekil getirme)
            if (request.method === 'GET' && pathSegments[2]) {
                const slug = pathSegments[2];
                const value = await db.get(slug);
                if (!value) return new Response(JSON.stringify({ error: 'Streamer not found' }), { status: 404 });
                return new Response(JSON.stringify({ slug, ...JSON.parse(value) }), { headers: { 'Content-Type': 'application/json' }});
            }
            // POST /api/streamers (Yeni ekleme)
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
            // DELETE /api/streamers/:slug (Silme)
            if (request.method === 'DELETE' && pathSegments[2]) {
                try {
                    const slug = pathSegments[2];
                    const { password } = await request.json();
                    if (password !== adminPassword) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
                    await db.delete(slug);
                    return new Response(JSON.stringify({ success: true }), { status: 200 });
                } catch (e) { return new Response(JSON.stringify({ error: 'Bad request' }), { status: 400 }); }
            }
        }

        // --- OAUTH2 GİRİŞ ROTALARI ---
        if (pathSegments[1] === 'auth') {
            // Rota: /api/auth/redirect/:provider
            if (pathSegments[2] === 'redirect' && pathSegments[3]) {
                const provider = pathSegments[3];
                const streamer = url.searchParams.get('streamer');
                if (!streamer) return new Response('Streamer query parameter is required', { status: 400 });
                
                let state = { streamer, random: crypto.randomUUID() };
                let authUrl;

                if (provider === 'discord') {
                    authUrl = new URL('https://discord.com/api/oauth2/authorize');
                    authUrl.searchParams.set('client_id', env.DISCORD_CLIENT_ID);
                    authUrl.searchParams.set('redirect_uri', `${env.APP_URL}/api/auth/callback/discord`);
                    authUrl.searchParams.set('scope', 'identify guilds.members.read');
                } else if (provider === 'kick') {
                    // YENİLİK: Kick için PKCE akışı eklendi.
                    const codeVerifier = generateCodeVerifier();
                    const codeChallenge = await generateCodeChallenge(codeVerifier);
                    
                    state.codeVerifier = codeVerifier; // Verifier'ı state'e ekleyip cookie'de sakla

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
                authUrl.searchParams.set('state', JSON.stringify(state));

                const stateCookie = `oauth_state=${encodeURIComponent(JSON.stringify(state))}; HttpOnly; Path=/; Max-Age=600; Secure; SameSite=Lax`;
                const headers = new Headers({ 'Location': authUrl.toString(), 'Set-Cookie': stateCookie });
                return new Response(null, { status: 302, headers });
            }

            // Rota: /api/auth/callback/:provider
            if (pathSegments[2] === 'callback' && pathSegments[3]) {
                const provider = pathSegments[3];
                const code = url.searchParams.get('code');
                const state = JSON.parse(url.searchParams.get('state') || '{}');

                const cookie = request.headers.get('Cookie');
                const storedStateJSON = cookie ? decodeURIComponent(cookie.match(/oauth_state=([^;]+)/)?.[1] || '') : null;
                const storedState = JSON.parse(storedStateJSON || '{}');

                if (!state.random || state.random !== storedState.random) {
                    return new Response('Invalid state parameter.', { status: 403 });
                }
                
                const { streamer } = storedState;
                let isSubscribed = false;

                try {
                    const tokenData = await exchangeCodeForToken(provider, code, storedState.codeVerifier, env);
                    const streamerInfo = JSON.parse(await db.get(streamer));

                    if (provider === 'discord') {
                        isSubscribed = await checkDiscordSubscription(tokenData.access_token, streamerInfo);
                    } else if (provider === 'kick') {
                        isSubscribed = await checkKickSubscription(tokenData.access_token, streamer);
                    }
                } catch(error) {
                    console.error(`OAuth callback error for ${provider}:`, error);
                    const redirectUrl = new URL(`/${streamer}`, env.APP_URL);
                    redirectUrl.searchParams.set('error', 'authentication_failed');
                    return Response.redirect(redirectUrl.toString(), 302);
                }

                const redirectUrl = new URL(`/${streamer}`, env.APP_URL);
                redirectUrl.searchParams.set('subscribed', isSubscribed);
                redirectUrl.searchParams.set('provider', provider);
                
                const headers = new Headers({ 'Location': redirectUrl.toString(), 'Set-Cookie': 'oauth_state=; HttpOnly; Path=/; Max-Age=0' });
                return new Response(null, { status: 302, headers });
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
        // YENİLİK: Token URL'si id.kick.com olarak güncellendi ve body'ye code_verifier eklendi.
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
        const error = await response.json();
        throw new Error(`${provider} token exchange failed: ${JSON.stringify(error)}`);
    }
    return response.json();
}

async function checkDiscordSubscription(accessToken, streamerInfo) {
    const { discordGuildId, discordRoleId, discordBotToken } = streamerInfo;
    if (!discordGuildId || !discordRoleId || !discordBotToken) return false;
    
    const userResponse = await fetch('https://discord.com/api/users/@me', {
        headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    if (!userResponse.ok) return false;
    const user = await userResponse.json();

    const memberResponse = await fetch(`https://discord.com/api/guilds/${discordGuildId}/members/${user.id}`, {
        headers: { 'Authorization': `Bot ${discordBotToken}` }
    });
    if (!memberResponse.ok) return false;
    const member = await memberResponse.json();
    
    return member.roles.includes(discordRoleId);
}

async function checkKickSubscription(accessToken, streamerSlug) {
    if (!streamerSlug) return false;
    try {
        const userResponse = await fetch('https://kick.com/api/v1/user', {
            headers: { 'Authorization': `Bearer ${accessToken}`, 'Accept': 'application/json' }
        });
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

