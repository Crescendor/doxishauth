/**
 * Gelişmiş Sunucu Kodu (Backend) v2.2 - Dinamik Discord Bot Token
 * Bu kod Cloudflare sunucularında çalışır.
 * GEREKLİ YENİ ORTAM DEĞİŞKENLERİ:
 * - DISCORD_CLIENT_ID: Discord Geliştirici Portalından
 * - DISCORD_CLIENT_SECRET: Discord Geliştirici Portalından
 * - KICK_CLIENT_ID: Kick Geliştirici Portalından (varsayımsal)
 * - KICK_CLIENT_SECRET: Kick Geliştirici Portalından (varsayımsal)
 * - APP_URL: Sitenizin tam adresi (örn: https://doxishauth.pages.dev)
 * NOT: Discord Bot Token artık her yayıncı için admin panelinden ayrı ayrı girilmektedir.
 */
async function handleRequest(context) {
    const { request, env } = context;
    const url = new URL(request.url);
    const pathSegments = url.pathname.split('/').filter(Boolean);

    const db = env.STREAMERS;
    const adminPassword = env.ADMIN_PASSWORD;

    // --- YÖNETİCİ VE VERİ ROTALARI (Mevcut) ---
    
    // Rota: /api/login (Admin girişi)
    if (pathSegments.join('/') === 'api/login' && request.method === 'POST') {
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

    // Rota: /api/streamers (Tüm yayıncıları listeleme)
    if (pathSegments.join('/') === 'api/streamers' && request.method === 'GET') {
        try {
            const list = await db.list();
            const streamers = [];
            for (const key of list.keys) {
                const value = await db.get(key.name);
                if (value) {
                    streamers.push({ slug: key.name, ...JSON.parse(value) });
                }
            }
            return new Response(JSON.stringify(streamers), { headers: { 'Content-Type': 'application/json' }});
        } catch (e) {
            return new Response(JSON.stringify({ error: 'Could not fetch streamers' }), { status: 500 });
        }
    }

    // Rota: /api/streamers/:slug (Tek bir yayıncıyı getirme)
    if (pathSegments[0] === 'api' && pathSegments[1] === 'streamers' && pathSegments[2] && request.method === 'GET') {
        const slug = pathSegments[2];
        const value = await db.get(slug);
        if (value === null) {
            return new Response(JSON.stringify({ error: 'Streamer not found' }), { status: 404 });
        }
        return new Response(JSON.stringify({ slug, ...JSON.parse(value) }), { headers: { 'Content-Type': 'application/json' }});
    }

    // Rota: /api/streamers (Yeni yayıncı ekleme - GÜNCELLENDİ)
    if (pathSegments.join('/') === 'api/streamers' && request.method === 'POST') {
        try {
            const { slug, displayText, discordGuildId, discordRoleId, discordBotToken, password } = await request.json();
            if (password !== adminPassword) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
            if (!slug || !displayText) return new Response(JSON.stringify({ error: 'Slug and display text are required' }), { status: 400 });

            const data = JSON.stringify({ displayText, discordGuildId, discordRoleId, discordBotToken });
            await db.put(slug, data);
            return new Response(JSON.stringify({ success: true }), { status: 201 });
        } catch (e) {
            return new Response(JSON.stringify({ error: 'Bad request' }), { status: 400 });
        }
    }
    
    // Rota: /api/streamers/:slug (Yayıncı silme)
    if (pathSegments[0] === 'api' && pathSegments[1] === 'streamers' && pathSegments[2] && request.method === 'DELETE') {
        try {
            const slug = pathSegments[2];
            const { password } = await request.json();
            if (password !== adminPassword) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
            await db.delete(slug);
            return new Response(JSON.stringify({ success: true }), { status: 200 });
        } catch (e) {
            return new Response(JSON.stringify({ error: 'Bad request' }), { status: 400 });
        }
    }

    // --- YENİ OAUTH2 GİRİŞ ROTALARI ---

    // Rota: /api/auth/redirect/:provider?streamer=...
    // Kullanıcıyı Discord/Kick giriş sayfasına yönlendirir.
    if (pathSegments[0] === 'api' && pathSegments[1] === 'auth' && pathSegments[2] === 'redirect' && pathSegments[3]) {
        const provider = pathSegments[3];
        const streamer = url.searchParams.get('streamer');
        if (!streamer) return new Response('Streamer query parameter is required', { status: 400 });
        
        const state = JSON.stringify({ streamer, random: crypto.randomUUID() });
        const stateCookie = `oauth_state=${encodeURIComponent(state)}; HttpOnly; Path=/; Max-Age=600; Secure; SameSite=Lax`;
        let authUrl = '';

        if (provider === 'discord') {
            const discordAuthUrl = new URL('https://discord.com/api/oauth2/authorize');
            discordAuthUrl.searchParams.set('client_id', env.DISCORD_CLIENT_ID);
            discordAuthUrl.searchParams.set('redirect_uri', `${env.APP_URL}/api/auth/callback/discord`);
            discordAuthUrl.searchParams.set('response_type', 'code');
            discordAuthUrl.searchParams.set('scope', 'identify guilds.members.read');
            discordAuthUrl.searchParams.set('state', state);
            authUrl = discordAuthUrl.toString();
        } else if (provider === 'kick') {
            const kickAuthUrl = new URL('https://kick.com/oauth2/authorize');
            kickAuthUrl.searchParams.set('client_id', env.KICK_CLIENT_ID);
            kickAuthUrl.searchParams.set('redirect_uri', `${env.APP_URL}/api/auth/callback/kick`);
            kickAuthUrl.searchParams.set('response_type', 'code');
            kickAuthUrl.searchParams.set('scope', 'user:read:subscriptions'); // API'ye göre scope değişebilir
            kickAuthUrl.searchParams.set('state', state);
            authUrl = kickAuthUrl.toString();
        } else {
            return new Response('Unsupported provider', { status: 400 });
        }
        
        const headers = new Headers({ 'Location': authUrl, 'Set-Cookie': stateCookie });
        return new Response(null, { status: 302, headers });
    }

    // Rota: /api/auth/callback/:provider
    // Discord/Kick'ten geri dönüşü yakalar, kodu token ile takas eder ve sonucu yönlendirir.
    if (pathSegments[0] === 'api' && pathSegments[1] === 'auth' && pathSegments[2] === 'callback' && pathSegments[3]) {
        const provider = pathSegments[3];
        const code = url.searchParams.get('code');
        const state = url.searchParams.get('state');

        const cookie = request.headers.get('Cookie');
        const storedStateJSON = cookie ? decodeURIComponent(cookie.match(/oauth_state=([^;]+)/)?.[1] || '') : null;
        if (!state || !storedStateJSON || state !== storedStateJSON) {
            return new Response('Invalid state parameter.', { status: 403 });
        }

        const { streamer } = JSON.parse(storedStateJSON);
        let isSubscribed = false;

        try {
            if (provider === 'discord') {
                const tokenData = await exchangeCodeForToken(provider, code, env);
                const streamerInfo = JSON.parse(await db.get(streamer));
                isSubscribed = await checkDiscordSubscription(tokenData.access_token, streamerInfo.discordGuildId, streamerInfo.discordRoleId, streamerInfo.discordBotToken);
            } else if (provider === 'kick') {
                const tokenData = await exchangeCodeForToken(provider, code, env);
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

    return new Response('Not Found', { status: 404 });
}

// --- YARDIMCI FONKSİYONLAR ---

async function exchangeCodeForToken(provider, code, env) {
    let tokenUrl, body;
    if (provider === 'discord') {
        tokenUrl = 'https://discord.com/api/oauth2/token';
        body = new URLSearchParams({
            client_id: env.DISCORD_CLIENT_ID, client_secret: env.DISCORD_CLIENT_SECRET,
            grant_type: 'authorization_code', code: code,
            redirect_uri: `${env.APP_URL}/api/auth/callback/discord`,
        });
    } else if (provider === 'kick') {
        tokenUrl = 'https://kick.com/api/v2/oauth/token'; // Bu URL Kick API'sine göre doğrulanmalıdır
        body = new URLSearchParams({
            client_id: env.KICK_CLIENT_ID, client_secret: env.KICK_CLIENT_SECRET,
            grant_type: 'authorization_code', code: code,
            redirect_uri: `${env.APP_URL}/api/auth/callback/kick`,
        });
    }

    const response = await fetch(tokenUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body,
    });

    if (!response.ok) {
        const error = await response.json();
        throw new Error(`${provider} token exchange failed: ${JSON.stringify(error)}`);
    }
    return response.json();
}

async function checkDiscordSubscription(accessToken, guildId, roleId, botToken) {
    if (!guildId || !roleId || !botToken) return false;
    
    const userResponse = await fetch('https://discord.com/api/users/@me', {
        headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    if (!userResponse.ok) return false;
    const user = await userResponse.json();

    const memberResponse = await fetch(`https://discord.com/api/guilds/${guildId}/members/${user.id}`, {
        headers: { 'Authorization': `Bot ${botToken}` }
    });
    if (!memberResponse.ok) return false;
    const member = await memberResponse.json();
    
    return member.roles.includes(roleId);
}

// YENİ: Kick API'sini kullanarak kullanıcının aboneliğini kontrol eder.
async function checkKickSubscription(accessToken, streamerSlug) {
    if (!streamerSlug) return false;

    try {
        // 1. Access token ile giriş yapmış kullanıcının bilgilerini al (API endpoint: /api/v1/user)
        const userResponse = await fetch('https://kick.com/api/v1/user', {
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Accept': 'application/json',
            }
        });

        if (!userResponse.ok) {
            console.error('Kick user info fetch failed:', await userResponse.text());
            return false;
        }
        const user = await userResponse.json();
        const userSlug = user.slug; // veya user.username, API cevabına göre

        if (!userSlug) {
            console.error('Kullanıcı adı Kick API yanıtından alınamadı.');
            return false;
        }

        // 2. Kullanıcının, hedef kanala abone olup olmadığını kontrol et (API endpoint: /api/v2/channels/{channel}/subscribers/{user})
        const subscriptionResponse = await fetch(`https://kick.com/api/v2/channels/${streamerSlug}/subscribers/${userSlug}`, {
            headers: { 'Accept': 'application/json' }
        });

        // 200 OK -> Abone. 404 Not Found -> Abone değil.
        if (subscriptionResponse.status === 200) {
            return true;
        } else if (subscriptionResponse.status === 404) {
            return false;
        } else {
            // Diğer durumlar (API hatası vb.)
            console.error(`Kick abonelik kontrolü ${subscriptionResponse.status} durumuyla başarısız oldu:`, await subscriptionResponse.text());
            return false;
        }

    } catch (error) {
        console.error('checkKickSubscription sırasında hata:', error);
        return false;
    }
}

export const onRequest = handleRequest;

