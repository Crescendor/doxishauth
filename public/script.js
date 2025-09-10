document.addEventListener('DOMContentLoaded', () => {
    const pages = {
        home: document.getElementById('home-page'),
        streamer: document.getElementById('streamer-page'),
        login: document.getElementById('login-page'),
        admin: document.getElementById('admin-page'),
    };

    const streamerNameEl = document.getElementById('streamer-name');
    const displayTextEl = document.getElementById('display-text');
    const kickLoginBtn = document.getElementById('kick-login');
    const discordLoginBtn = document.getElementById('discord-login');
    const subscriptionStatusEl = document.getElementById('subscription-status');
    
    const loginForm = document.getElementById('login-form');
    const passwordInput = document.getElementById('password-input');
    const loginErrorEl = document.getElementById('login-error');

    const addStreamerForm = document.getElementById('add-streamer-form');
    const addStreamerBtn = document.getElementById('add-streamer-btn');
    const streamerSlugInput = document.getElementById('streamer-slug-input');
    const displayTextInput = document.getElementById('display-text-input');
    const discordGuildIdInput = document.getElementById('discord-guild-id-input');
    const discordRoleIdInput = document.getElementById('discord-role-id-input');
    const discordBotTokenInput = document.getElementById('discord-bot-token-input');
    const streamerListEl = document.getElementById('streamer-list');

    let currentStreamer = null;

    // --- Rota Yönetimi ---
    const handleRouting = async () => {
        const path = window.location.pathname.toLowerCase();
        
        if (path === '/admin') {
            if (sessionStorage.getItem('isAdminAuthenticated')) {
                showPage('admin');
                await loadAdminPanel();
            } else {
                showPage('login');
            }
        } else if (path.length > 1) {
            const slug = path.substring(1);
            currentStreamer = slug;
            await loadStreamerPage(slug);
        } else {
            showPage('home');
        }
    };

    const showPage = (pageId) => {
        Object.values(pages).forEach(page => page.classList.remove('active'));
        if (pages[pageId]) {
            pages[pageId].classList.add('active');
        }
    };
    
    // --- API İstek Yardımcısı ---
    async function apiRequest(path, options = {}) {
        const res = await fetch(`/api/${path.replace(/^\\//, '')}`, {
            method: options.method || 'GET',
            headers: options.headers || {},
            body: options.body || null,
        });

        if (!res.ok) {
            const text = await res.text();
            throw new Error(text || `HTTP ${res.status}`);
        }

        const ct = res.headers.get('content-type') || '';
        if (ct.includes('application/json')) {
            return await res.json();
        }
        return await res.text();
    }

    // --- Yayıncı Sayfasını Yükle ---
    const loadStreamerPage = async (slug) => {
        try {
            const data = await apiRequest(`/streamers/${slug}`);
            streamerNameEl.textContent = data.slug;
            displayTextEl.textContent = data.displayText;
            showPage('streamer');
            checkSubscriptionStatus();
        } catch (error) {
            window.location.pathname = '/'; // Yayıncı bulunamazsa anasayfaya yönlendir
        }
    };

    const checkSubscriptionStatus = () => {
        const urlParams = new URLSearchParams(window.location.search);
        const subscribed = urlParams.get('subscribed');
        const provider = urlParams.get('provider');
        const error = urlParams.get('error');

        // EKLENDİ: username gösterimi
        const username = urlParams.get('username');
        const identityEl = document.getElementById('user-identity');
        if (identityEl) {
            if (username) {
                const label = (provider === 'discord') ? 'Discord kullanıcı adı' : 'Kick kullanıcı adı';
                identityEl.textContent = `${label}: ${username}`;
            } else {
                identityEl.textContent = '';
            }
        }

        if (error) {
            subscriptionStatusEl.textContent = 'Giriş sırasında bir hata oluştu.';
            subscriptionStatusEl.className = 'mt-6 text-lg h-5 font-semibold text-red-400';
        } else if (subscribed !== null) {
             if (subscribed === 'true') {
                subscriptionStatusEl.textContent = `${provider.charAt(0).toUpperCase() + provider.slice(1)} aboneliğiniz doğrulandı!`;
                subscriptionStatusEl.className = 'mt-6 text-lg h-5 font-semibold text-green-400';
            } else {
                subscriptionStatusEl.textContent = `Bu kanala ${provider.charAt(0).toUpperCase() + provider.slice(1)} aboneliğiniz bulunamadı.`;
                subscriptionStatusEl.className = 'mt-6 text-lg h-5 font-semibold text-yellow-400';
            }
        }
        // URL'den parametreleri temizle
        window.history.replaceState({}, document.title, window.location.pathname);
    };

    kickLoginBtn.addEventListener('click', () => {
        window.location.href = `/api/auth/redirect/kick?streamer=${currentStreamer}`;
    });

    discordLoginBtn.addEventListener('click', () => {
        window.location.href = `/api/auth/redirect/discord?streamer=${currentStreamer}`;
    });


    // --- Admin Giriş Mantığı ---
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            loginErrorEl.textContent = '';
            try {
                await apiRequest('/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password: passwordInput.value })
                });
                sessionStorage.setItem('isAdminAuthenticated', 'true');
                window.location.pathname = '/admin';
            } catch (error) {
                loginErrorEl.textContent = 'Hatalı şifre. Lütfen tekrar deneyin.';
            }
        });
    }

    // --- Admin Paneli ---
    async function loadAdminPanel() {
        try {
            const list = await apiRequest('/streamers');
            streamerListEl.innerHTML = '';
            list.forEach((s) => {
                const row = document.createElement('div');
                row.className = 'flex items-center justify-between bg-gray-900 border border-gray-700 rounded-lg p-3';
                row.innerHTML = `
                    <div class="text-sm">
                        <div class="font-semibold text-white">${s.slug}</div>
                        <div class="text-gray-400">${s.displayText}</div>
                    </div>
                    <button data-del="${s.slug}" class="text-sm px-3 py-1 rounded bg-red-500 hover:bg-red-600 text-white">Sil</button>
                `;
                streamerListEl.appendChild(row);
            });
        } catch (error) {
            streamerListEl.innerHTML = `<div class="text-red-400">Liste alınamadı: ${error.message}</div>`;
        }
    }

    if (addStreamerForm) {
        addStreamerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = {
                password: sessionStorage.getItem('isAdminAuthenticated') ? '***' : '', // server kontrol ediyor
                slug: streamerSlugInput.value.trim(),
                displayText: displayTextInput.value.trim(),
                discordGuildId: discordGuildIdInput.value.trim() || null,
                discordRoleId: discordRoleIdInput.value.trim() || null,
                discordBotToken: discordBotTokenInput.value.trim() || null
            };
            const formErrorEl = document.getElementById('form-error');

            try {
                addStreamerBtn.disabled = true;
                addStreamerBtn.innerHTML = '<span class="inline-flex items-center gap-2"><span class="w-4 h-4 border-2 border-white/60 border-t-transparent rounded-full animate-spin"></span> Kaydediliyor</span>';

                await apiRequest('/streamers', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(formData)
                });
                addStreamerForm.reset();
                await loadAdminPanel();
            } catch (error) {
                formErrorEl.textContent = `Hata: ${error.message}`;
            } finally {
                addStreamerBtn.disabled = false;
                addStreamerBtn.innerHTML = '<span>Yayıncıyı Ekle</span>';
            }
        });
    }

    streamerListEl?.addEventListener('click', async (e) => {
        const target = e.target;
        if (target && target.matches('button[data-del]')) {
            const slug = target.getAttribute('data-del');
            // (Silme ucu backend'de yoksa, bu bölüm pasif kalır)
            alert(`Silme isteği: ${slug} (backend ucu yoksa no-op)`);
        }
    });

    // Start
    handleRouting();
});
