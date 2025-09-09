/**
 * Sunucu tarafı fonksiyonu (Backend)
 * Bu kod Cloudflare sunucularında çalışır, tarayıcıda değil.
 * Veritabanı işlemleri ve gizli şifre kontrolü burada yapılır.
 */
export async function onRequest(context) {
    // context objesinden gerekli bilgileri alıyoruz.
    // env: Gizli değişkenler (şifre) ve veritabanı bağlantısı
    // request: Kullanıcıdan gelen istek (GET, POST vs.)
    // params: URL'deki dinamik kısımlar
    const {
        request,
        env,
        params
    } = context;

    // Gelen isteğin URL'sini alıp basitleştiriyoruz
    const url = new URL(request.url);
    const path = url.pathname;

    // Veritabanı ve admin şifresini ortam değişkenlerinden alıyoruz
    const db = env.STREAMERS;
    const adminPassword = env.ADMIN_PASSWORD;

    // Sadece /api/streamers adresine gelen istekleri dinleyeceğiz
    if (path.startsWith('/api/streamers')) {
        // --- YAYINCI LİSTESİNİ GETİRME (GET isteği) ---
        if (request.method === 'GET') {
            try {
                // Veritabanındaki tüm anahtarları (yayıncı adlarını) listele
                const {
                    keys
                } = await db.list();
                const streamerSlugs = keys.map(key => key.name);
                // Listeyi JSON formatında geri gönder
                return new Response(JSON.stringify({
                    streamers: streamerSlugs
                }), {
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    status: 200
                });
            } catch (error) {
                console.error("KV Error:", error);
                return new Response(JSON.stringify({
                    error: 'Veritabanına erişirken bir hata oluştu.'
                }), {
                    status: 500
                });
            }
        }

        // --- YENİ YAYINCI EKLEME (POST isteği) ---
        if (request.method === 'POST') {
            try {
                const {
                    slug,
                    password
                } = await request.json();

                // Admin şifresi kontrolü
                if (!adminPassword || password !== adminPassword) {
                    return new Response(JSON.stringify({
                        error: 'Yetkisiz işlem: Geçersiz şifre.'
                    }), {
                        status: 401
                    });
                }

                // Gelen yayıncı adı geçerli mi kontrolü
                if (!slug || slug.length < 3) {
                    return new Response(JSON.stringify({
                        error: 'Geçersiz yayıncı adı.'
                    }), {
                        status: 400
                    });
                }
                
                // Yeni yayıncıyı veritabanına ekle
                await db.put(slug, 'true');

                // Başarılı olduğuna dair cevap gönder
                return new Response(JSON.stringify({
                    success: true,
                    slug: slug
                }), {
                    status: 200
                });

            } catch (error) {
                 console.error("Post request error:", error);
                 return new Response(JSON.stringify({
                    error: 'İstek işlenirken bir hata oluştu.'
                }), {
                    status: 500
                });
            }
        }

        // Desteklenmeyen bir metod ise hata ver
        return new Response('Method Not Allowed', {
            status: 405
        });
    }

    // Eğer /api/streamers dışında bir adrese istek gelirse 404 hatası ver
    return new Response('Not Found', {
        status: 404
    });
}

