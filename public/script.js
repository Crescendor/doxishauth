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
    const streamerSlugInput = document.getElementById('streamer-slug-input');
    const displayTextFormInput = document.getElementById('display-text-input');
    const discordGuildIdInput = document.getElementById('discord-guild-id-input');
    const discordRoleIdInput = document.getElementById('discord-role-id-input');
    const discordBotTokenInput = document.getElementById('discord-bot-token-input');
    const streamerListEl = document.getElementById('streamer-list');
    const formErrorEl = document.getElementById('form-error');
    const addStreamerBtn = document.getElementById('add-streamer-btn');

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
    const apiRequest = async (endpoint, options = {}) => {
        try {
            const response = await fetch(`/api${endpoint}`, options);
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ error: 'Bilinmeyen bir hata oluştu.' }));
                throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
            }
            return await response.json();
        } catch (error) {
            console.error('API isteği hatası:', error);
            throw error;
        }
    };

    // --- Yayıncı Sayfası Mantığı ---
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

    // --- Admin Paneli Mantığı ---
    const loadAdminPanel = async () => {
        try {
            const streamers = await apiRequest('/streamers');
            renderStreamerList(streamers);
        } catch (error) {
            console.error('Yayıncılar yüklenemedi:', error);
        }
    };
    
    const renderStreamerList = (streamers) => {
        streamerListEl.innerHTML = '';
        if (streamers.length === 0) {
             streamerListEl.innerHTML = '<p class="text-gray-500">Henüz yayıncı eklenmemiş.</p>';
             return;
        }
        streamers.forEach(streamer => {
            const li = document.createElement('div');
            li.className = 'bg-gray-700 p-3 rounded-lg flex justify-between items-center';
            li.innerHTML = `
                <div>
                    <a href="/${streamer.slug}" target="_blank" class="font-semibold text-green-400 hover:underline">${streamer.slug}</a>
                    <p class="text-sm text-gray-400">"${streamer.displayText}"</p>
                </div>
                <button data-slug="${streamer.slug}" class="delete-btn bg-red-600 hover:bg-red-700 text-white font-bold py-1 px-3 rounded-md text-sm btn-press">Sil</button>
            `;
            streamerListEl.appendChild(li);
        });
    };

    if (addStreamerForm) {
        addStreamerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            formErrorEl.textContent = '';
            addStreamerBtn.disabled = true;
            addStreamerBtn.innerHTML = '<div class="loader"></div>';

            const formData = {
                slug: streamerSlugInput.value.toLowerCase().trim(),
                displayText: displayTextFormInput.value.trim(),
                discordGuildId: discordGuildIdInput.value.trim(),
                discordRoleId: discordRoleIdInput.value.trim(),
                discordBotToken: discordBotTokenInput.value.trim(),
                password: sessionStorage.getItem('adminPassword') || passwordInput.value
            };
            
            // Sadece Discord ayarlarının hepsi doluysa veya hepsi boşsa devam et
            const discordFields = [formData.discordGuildId, formData.discordRoleId, formData.discordBotToken];
            const filledFields = discordFields.filter(f => f).length;
            if (filledFields > 0 && filledFields < 3) {
                formErrorEl.textContent = 'Lütfen tüm Discord alanlarını doldurun veya hepsini boş bırakın.';
                addStreamerBtn.disabled = false;
                addStreamerBtn.innerHTML = '<span>Yayıncıyı Ekle</span>';
                return;
            }

            try {
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

    streamerListEl.addEventListener('click', async (e) => {
        if (e.target.classList.contains('delete-btn')) {
            const slug = e.target.dataset.slug;
            if (confirm(`'${slug}' adlı yayıncıyı silmek istediğinizden emin misiniz?`)) {
                try {
                     await apiRequest(`/streamers/${slug}`, {
                        method: 'DELETE',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ password: sessionStorage.getItem('adminPassword') || passwordInput.value })
                    });
                    await loadAdminPanel();
                } catch (error) {
                    alert(`Hata: ${error.message}`);
                }
            }
        }
    });

    // Başlangıç
    handleRouting();
});

