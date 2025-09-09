/**
 * Gelişmiş Sunucu Kodu (Backend) v2.3 - Detaylı Hata Ayıklama (Debug)
 * Bu kod Cloudflare sunucularında çalışır ve Kick OAuth2 akışındaki her adımı loglar.
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
            console.error("DEBUG: State mismatch or not found.", {state, storedStateJSON});
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
                console.log("DEBUG: Kick callback received. Attempting to exchange code for token.");
                const tokenData = await exchangeCodeForToken(provider, code, env);
                console.log("DEBUG: Kick token received successfully. Token data keys:", Object.keys(tokenData).join(', '));
                isSubscribed = await checkKickSubscription(tokenData.access_token, streamer);
                console.log(`DEBUG: Kick subscription check for '${streamer}' resulted in: ${isSubscribed}`);
            }
        } catch(error) {
            console.error(`DEBUG: OAuth callback error for ${provider}:`, error.message, error.stack);
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
    
    const responseData = await response.json();

    if (!response.ok) {
        console.error(`DEBUG: ${provider} token exchange failed. Status: ${response.status}. Response:`, JSON.stringify(responseData));
        throw new Error(`${provider} token exchange failed: ${JSON.stringify(responseData)}`);
    }
    console.log(`DEBUG: ${provider} token exchange successful.`);
    return responseData;
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


async function checkKickSubscription(accessToken, streamerSlug) {
    if (!streamerSlug) return false;

    try {
        console.log("DEBUG: Fetching Kick user info...");
        const userResponse = await fetch('https://kick.com/api/v1/user', {
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Accept': 'application/json',
            }
        });

        if (!userResponse.ok) {
            const errorText = await userResponse.text();
            console.error('DEBUG: Kick user info fetch failed. Status:', userResponse.status, 'Response:', errorText);
            return false;
        }
        const user = await userResponse.json();
        console.log("DEBUG: Kick user info received:", JSON.stringify(user));
        const userSlug = user.slug;

        if (!userSlug) {
            console.error('DEBUG: Kullanıcı adı (slug) Kick API yanıtından alınamadı.');
            return false;
        }
        console.log(`DEBUG: Extracted user slug: ${userSlug}`);

        const subscriptionUrl = `https://kick.com/api/v2/channels/${streamerSlug}/subscribers/${userSlug}`;
        console.log(`DEBUG: Checking Kick subscription at: ${subscriptionUrl}`);
        const subscriptionResponse = await fetch(subscriptionUrl, {
            headers: { 'Accept': 'application/json' }
        });

        console.log(`DEBUG: Kick subscription response status: ${subscriptionResponse.status}`);

        if (subscriptionResponse.status === 200) {
            return true;
        } else if (subscriptionResponse.status === 404) {
            return false;
        } else {
            const errorText = await subscriptionResponse.text();
            console.error(`DEBUG: Kick abonelik kontrolü ${subscriptionResponse.status} durumuyla başarısız oldu:`, errorText);
            return false;
        }

    } catch (error) {
        console.error('DEBUG: checkKickSubscription sırasında kritik hata:', error.message, error.stack);
        return false;
    }
}

export const onRequest = handleRequest;

