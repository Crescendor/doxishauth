/**
 * Gelişmiş Sunucu Kodu (Backend)
 * Bu kod Cloudflare sunucularında çalışır.
 * Giriş yapma, yayıncı ekleme, silme, listeleme ve tekil veri getirme işlemlerini yönetir.
 * Artık veritabanında JSON objeleri saklar.
 */
async function handleRequest(context) {
    const { request, env, params } = context;
    const url = new URL(request.url);
    const pathSegments = url.pathname.split('/').filter(Boolean); // e.g., ['api', 'streamers', 'elraenn']

    const db = env.STREAMERS;
    const adminPassword = env.ADMIN_PASSWORD;

    // --- API Rotaları ---
    
    // Rota: /api/login
    if (pathSegments[0] === 'api' && pathSegments[1] === 'login' && request.method === 'POST') {
        try {
            const { password } = await request.json();
            if (adminPassword && password === adminPassword) {
                return new Response(JSON.stringify({ success: true }), { status: 200 });
            } else {
                return new Response(JSON.stringify({ error: 'Invalid password' }), { status: 401 });
            }
        } catch (e) {
            return new Response(JSON.stringify({ error: 'Bad request' }), { status: 400 });
        }
    }

    // Rota: /api/streamers (Tüm yayıncıları listeleme)
    if (pathSegments[0] === 'api' && pathSegments[1] === 'streamers' && !pathSegments[2] && request.method === 'GET') {
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

    // Rota: /api/streamers (Yeni yayıncı ekleme)
    if (pathSegments[0] === 'api' && pathSegments[1] === 'streamers' && request.method === 'POST') {
        try {
            const { slug, displayText, password } = await request.json();
            if (password !== adminPassword) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
            if (!slug || !displayText) return new Response(JSON.stringify({ error: 'Slug and display text are required' }), { status: 400 });

            const data = JSON.stringify({ displayText });
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

    // Eşleşen rota yoksa
    return new Response('Not Found', { status: 404 });
}

export const onRequest = handleRequest;

