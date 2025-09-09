/**
 * Frontend Logic (script.js)
 * Bu kod kullanıcının tarayıcısında çalışır.
 * Sayfa yönlendirmesi, form işlemleri ve backend ile iletişimi yönetir.
 */
document.addEventListener('DOMContentLoaded', () => {
    // --- Sayfa Elemanlarını Seçme ---
    const pages = document.querySelectorAll('.page');
    const streamerNameEl = document.getElementById('streamer-name');
    const streamerDisplayTextEl = document.getElementById('streamer-display-text');
    const subscriptionStatusEl = document.getElementById('subscription-status');
    const streamerListContainer = document.getElementById('streamer-list-container');
    const loginForm = document.getElementById('login-form');
    const passwordInput = document.getElementById('password-input');
    const loginErrorEl = document.getElementById('login-error');
    const addStreamerForm = document.getElementById('add-streamer-form');
    const logoutButton = document.getElementById('logout-button');

    // --- Yönlendirici (Router) Fonksiyonu ---
    // URL'ye göre hangi sayfanın gösterileceğine karar verir.
    async function router() {
        const path = window.location.pathname.toLowerCase();
        pages.forEach(p => p.classList.remove('active'));

        if (path === '/admin') {
            // Admin paneline girmeden önce giriş yapılmış mı diye kontrol et
            if (sessionStorage.getItem('admin_logged_in') === 'true') {
                document.getElementById('admin-page').classList.add('active');
                fetchAndDisplayStreamers();
            } else {
                document.getElementById('login-page').classList.add('active');
            }
        } else if (path === '/' || path === '/index.html') {
            document.getElementById('home-page').classList.add('active');
        } else {
            // URL'den yayıncı adını al ve o sayfayı göster
            const streamerSlug = path.substring(1).replace(/[^a-z0-9_]/gi, '');
            handleStreamerRoute(streamerSlug);
        }
    }

    // --- Sayfa Yönlendirme Fonksiyonları ---

    // Belirli bir yayıncının sayfasını hazırlar ve gösterir
    async function handleStreamerRoute(slug) {
        try {
            // Sunucudan yayıncı verilerini çek
            const response = await fetch(`/api/streamers/${slug}`);
            if (!response.ok) {
                // Yayıncı bulunamazsa ana sayfaya yönlendir
                window.location.href = '/';
                return;
            }
            const data = await response.json();
            
            document.getElementById('streamer-page').classList.add('active');
            streamerNameEl.textContent = data.slug;
            streamerDisplayTextEl.textContent = data.displayText;
            subscriptionStatusEl.textContent = '';
            
            // Butonlara tıklama olaylarını ata
            document.getElementById('kick-login').onclick = () => checkSubscription(data.slug);
            document.getElementById('discord-login').onclick = () => checkSubscription(data.slug);

        } catch (error) {
            console.error('Yayıncı verisi alınırken hata:', error);
            window.location.href = '/';
        }
    }

    // --- Admin Giriş İşlemleri ---
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        loginErrorEl.textContent = '';
        const password = passwordInput.value;
        
        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password })
            });
            
            if (response.ok) {
                sessionStorage.setItem('admin_logged_in', 'true');
                window.location.reload(); // Sayfayı yenileyerek router'ın admin panelini açmasını sağla
            } else {
                loginErrorEl.textContent = 'Hatalı şifre. Lütfen tekrar deneyin.';
            }
        } catch (error) {
            console.error('Giriş yapılırken hata:', error);
            loginErrorEl.textContent = 'Bir sunucu hatası oluştu.';
        }
    });
    
    logoutButton.addEventListener('click', () => {
        sessionStorage.removeItem('admin_logged_in');
        window.location.href = '/'; // Ana sayfaya yönlendir
    });

    // --- Admin Panel Fonksiyonları ---

    // Sunucudan tüm yayıncıları çeker ve listeler
    async function fetchAndDisplayStreamers() {
        streamerListContainer.innerHTML = '<div class="loader"></div>';
        try {
            const response = await fetch('/api/streamers');
            if (!response.ok) throw new Error('Yayıncılar alınamadı.');
            
            const streamers = await response.json();
            streamerListContainer.innerHTML = '';
            
            if (streamers.length === 0) {
                streamerListContainer.innerHTML = '<p class="text-gray-500">Henüz yayıncı eklenmedi.</p>';
                return;
            }

            streamers.forEach(streamer => {
                const streamerDiv = document.createElement('div');
                streamerDiv.className = 'flex items-center justify-between bg-gray-800 p-3 rounded-md';
                streamerDiv.innerHTML = `
                    <div>
                        <p class="font-semibold text-white">${streamer.slug}</p>
                        <p class="text-sm text-gray-400">${streamer.displayText}</p>
                    </div>
                    <button data-slug="${streamer.slug}" class="delete-btn text-red-400 hover:text-red-600 text-xs font-bold">SİL</button>
                `;
                streamerListContainer.appendChild(streamerDiv);
            });

        } catch (error) {
            console.error(error);
            streamerListContainer.innerHTML = '<p class="text-red-500">Hata: Yayıncılar yüklenemedi.</p>';
        }
    }
    
    // Yeni yayıncı ekleme formu gönderildiğinde çalışır
    addStreamerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const slugInput = document.getElementById('streamer-slug-input');
        const displayTextInput = document.getElementById('display-text-input');
        
        const newStreamer = {
            slug: slugInput.value.trim().toLowerCase(),
            displayText: displayTextInput.value.trim(),
            password: passwordInput.value || sessionStorage.getItem('temp_pass')
        };
        
        if (!newStreamer.slug || !newStreamer.displayText) {
            alert('Tüm alanlar doldurulmalıdır.');
            return;
        }

        try {
            const response = await fetch('/api/streamers', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(newStreamer)
            });

            if (response.ok) {
                alert('Yayıncı başarıyla eklendi!');
                addStreamerForm.reset();
                fetchAndDisplayStreamers();
            } else {
                const errorData = await response.json();
                alert(`Hata: ${errorData.error}`);
            }
        } catch (error) {
            console.error('Yayıncı eklenirken hata:', error);
            alert('Bir sunucu hatası oluştu.');
        }
    });

    // Yayıncı listesindeki silme butonlarına tıklama olayını dinler
    streamerListContainer.addEventListener('click', async (e) => {
        if (e.target.classList.contains('delete-btn')) {
            const slugToDelete = e.target.dataset.slug;
            if (confirm(`'${slugToDelete}' adlı yayıncıyı silmek istediğinizden emin misiniz?`)) {
                try {
                     const response = await fetch(`/api/streamers/${slugToDelete}`, {
                        method: 'DELETE',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ password: passwordInput.value || sessionStorage.getItem('temp_pass') })
                    });
                    
                    if(response.ok) {
                        alert('Yayıncı başarıyla silindi.');
                        fetchAndDisplayStreamers();
                    } else {
                        const errorData = await response.json();
                        alert(`Hata: ${errorData.error}`);
                    }
                } catch(error) {
                    console.error('Yayıncı silinirken hata:', error);
                    alert('Bir sunucu hatası oluştu.');
                }
            }
        }
    });

    // Admin girişi yapıldığında, sonraki işlemler için şifreyi geçici olarak sakla
    loginForm.addEventListener('submit', () => {
        sessionStorage.setItem('temp_pass', passwordInput.value);
    });

    // --- Diğer Fonksiyonlar ---

    // Simülasyonlu abonelik kontrolü
    function checkSubscription(streamerSlug) {
        subscriptionStatusEl.textContent = 'Kontrol ediliyor...';
        subscriptionStatusEl.classList.remove('text-green-400', 'text-red-400');
        
        setTimeout(() => {
            const isSubscribed = Math.random() > 0.5;
            if (isSubscribed) {
                subscriptionStatusEl.textContent = `Tebrikler, ${streamerSlug} adlı yayıncıya abonesiniz!`;
                subscriptionStatusEl.classList.add('text-green-400');
            } else {
                subscriptionStatusEl.textContent = `Maalesef, ${streamerSlug} adlı yayıncıya abone değilsiniz.`;
                subscriptionStatusEl.classList.add('text-red-400');
            }
        }, 1500);
    }

    // --- Sayfa Yüklendiğinde Başlat ---
    router();
});

