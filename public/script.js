/**
 * Gelişmiş Frontend Kodu v12.0 - Nihai Tasarım
 * Bu kod, ChatGPT tarafından sağlanan v10.1 backend ve yeni "retrowave" tasarımla tam uyumlu çalışır.
 * - Kalıcı veri saklama (localStorage) ile çoklu platform durum yönetimi.
 * - Admin panelinden gelen özel başlık, alt başlık ve arkaplanı uygular.
 * - Discord ayarları admin panelinden kaldırıldı, backend'den gelen veriye göre buton gösterilir.
 */
document.addEventListener("DOMContentLoaded", () => {
    const pages = {
        home: document.getElementById("home-page"),
        content: document.getElementById("content-page"),
        streamer: document.getElementById("streamer-card"),
        admin: document.getElementById("admin-card"),
        adminLogin: document.getElementById("admin-login-page"),
        adminPanel: document.getElementById("admin-panel-page"),
    };

    const defaultBg = "url('https://i.ibb.co/7Nbkyyss/Untitled-design.png')";

    const showPage = (pageName) => {
        // Hide all pages first
        Object.values(pages).forEach(p => {
            p.classList.remove('active');
            p.style.display = 'none';
        });

        if (pageName === "home") {
            pages.home.style.display = 'flex';
            pages.home.classList.add('active');
        } else if (pageName.startsWith('admin')) {
            pages.content.style.display = 'flex';
            pages.content.classList.add('active');
            pages.admin.style.display = 'block';
            pages.adminLogin.style.display = pageName === 'adminLogin' ? 'flex' : 'none';
            pages.adminPanel.style.display = pageName === 'adminPanel' ? 'flex' : 'none';
        } else if (pageName === 'streamer') {
            pages.content.style.display = 'flex';
            pages.content.classList.add('active');
            pages.streamer.style.display = 'block';
        }
    };

    const showToast = (message, isError = false) => {
        const toast = document.getElementById("toast");
        toast.textContent = message;
        toast.className = `fixed bottom-5 right-5 text-white py-2 px-5 rounded-lg shadow-lg opacity-0 translate-y-3 transition-all duration-300 ${isError ? 'bg-red-600 border-red-500' : 'bg-gray-800 border-gray-700'}`;
        
        // Trigger reflow to restart animation
        void toast.offsetWidth;

        toast.classList.add("show");
        setTimeout(() => toast.classList.remove("show"), 3000);
    };

    const handleRouting = async () => {
        const path = window.location.pathname.replace(/^\/+/, "");
        if (path.toLowerCase() === "admin") {
            document.body.style.backgroundImage = defaultBg;
            if (sessionStorage.getItem("isAdminAuthenticated")) {
                showPage("adminPanel");
                await loadAdminPanel();
            } else {
                showPage("adminLogin");
            }
        } else if (path) {
            try {
                const response = await fetch(`/api/streamers/${path}`);
                if (!response.ok) {
                    window.location.pathname = '/';
                    return;
                }
                const streamer = await response.json();
                
                document.getElementById("streamer-title").textContent = streamer.title;
                document.getElementById("streamer-subtitle").textContent = streamer.subtitle;
                document.body.style.backgroundImage = streamer.customBackgroundUrl ? `url('${streamer.customBackgroundUrl}')` : defaultBg;
                
                document.getElementById("kick-login").onclick = () => window.location.href = `/api/auth/redirect/kick?streamer=${streamer.slug}`;
                
                const discordButton = document.getElementById("discord-login");
                // Backend'den Discord bilgisi geliyorsa butonu göster
                if (streamer.discordGuildId && streamer.discordRoleId) {
                    discordButton.style.display = "flex";
                    discordButton.onclick = () => window.location.href = `/api/auth/redirect/discord?streamer=${streamer.slug}`;
                } else {
                    discordButton.style.display = "none";
                }
                
                showPage("streamer");
                handleCallbackAndUI(streamer.slug, !!streamer.discordGuildId);

            } catch (error) {
                console.error("Yayıncı verisi alınırken hata:", error);
                window.location.pathname = '/';
            }
        } else {
            document.body.style.backgroundImage = defaultBg;
            showPage("home");
        }
    };
    
    const getPersistentData = (streamerSlug) => {
        const key = `doxishauth_${streamerSlug}`;
        try {
            const data = localStorage.getItem(key);
            return data ? JSON.parse(data) : { kick: null, discord: null };
        } catch (e) { return { kick: null, discord: null }; }
    };

    const setPersistentData = (streamerSlug, data) => {
        const key = `doxishauth_${streamerSlug}`;
        localStorage.setItem(key, JSON.stringify(data));
    };
    
    const handleCallbackAndUI = (streamerSlug, isDiscordEnabled) => {
        const params = new URLSearchParams(window.location.search);
        let data = getPersistentData(streamerSlug);

        if (params.has("provider")) {
            const provider = params.get("provider");
            const isSubscribed = params.get("subscribed") === "true";
            const error = params.get("error");
            
            if (error) {
                showToast(`${provider.charAt(0).toUpperCase() + provider.slice(1)} girişi başarısız.`, true);
                 // Hatalı girişte veriyi null yap
                 data[provider] = null;
            } else {
                 data[provider] = {
                    linked: true,
                    subscribed: isSubscribed,
                    checkedAt: new Date().toISOString()
                };
            }
            setPersistentData(streamerSlug, data);
            
            window.history.replaceState({}, document.title, `/${streamerSlug}`);
        }
        
        updateUI(data, isDiscordEnabled);
    };

    const createBadge = (text, isGreen) => {
        const badge = document.createElement('span');
        badge.className = `status-badge ${isGreen ? 'status-badge-green' : 'status-badge-red'}`;
        badge.textContent = text;
        return badge;
    };

    const updateUI = (data, isDiscordEnabled) => {
        const discordContainer = document.getElementById("discord-status-container");
        if (isDiscordEnabled) {
            discordContainer.innerHTML = '';
            if (data.discord) {
                discordContainer.appendChild(createBadge('Discord : Bağlandı', true));
                discordContainer.appendChild(createBadge(data.discord.subscribed ? 'Rol : Mevcut' : 'Rol : Mevcut Değil', data.discord.subscribed));
            } else {
                discordContainer.appendChild(createBadge('Discord : Bağlı Değil', false));
            }
        } else {
            discordContainer.innerHTML = '';
        }


        const kickContainer = document.getElementById("kick-status-container");
        kickContainer.innerHTML = '';
        if (data.kick) {
            kickContainer.appendChild(createBadge('Kick : Bağlandı', true));
            kickContainer.appendChild(createBadge(data.kick.subscribed ? 'Abonelik : Kanalda Abone' : 'Abonelik : Kanalda Abone Değil', data.kick.subscribed));
        } else {
            kickContainer.appendChild(createBadge('Kick : Bağlı Değil', false));
        }

        const bothChecked = data.kick && (!isDiscordEnabled || data.discord);
        document.getElementById("result-message").classList.toggle("hidden", !bothChecked);
    };

    /* -------------------- ADMIN PANEL LOGIC -------------------- */
    
    document.getElementById("admin-login-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        const password = document.getElementById("admin-password-input").value;
        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password })
            });
            if (response.ok) {
                sessionStorage.setItem("isAdminAuthenticated", "true");
                sessionStorage.setItem("adminPassword", password);
                window.location.pathname = "/admin";
            } else { showToast("Hatalı şifre!", true); }
        } catch (error) { showToast("Giriş sırasında bir hata oluştu.", true); }
    });
    
    document.getElementById("logout-btn")?.addEventListener('click', () => {
        sessionStorage.clear();
        window.location.pathname = "/";
    });

    const loadAdminPanel = async () => {
        const listContainer = document.getElementById("streamer-list-container");
        listContainer.innerHTML = '<div class="loader"></div>';

        try {
            const response = await fetch("/api/streamers");
            if (!response.ok) throw new Error("API'den veri alınamadı.");
            const streamers = await response.json();
            
            listContainer.innerHTML = "";
            if(streamers.length === 0){
                listContainer.innerHTML = `<p class="text-gray-500 text-center">Henüz yayıncı eklenmemiş.</p>`;
                return;
            }

            streamers.forEach(streamer => {
                const item = document.createElement("div");
                item.className = "bg-gray-800/50 p-3 rounded-lg flex justify-between items-center";
                item.innerHTML = `
                    <div class="truncate mr-4">
                        <a href="/${streamer.slug}" target="_blank" class="text-lg font-semibold text-green-400 hover:underline">${streamer.title}</a>
                        <p class="text-sm text-gray-400 truncate">/${streamer.slug}</p>
                    </div>
                    <button data-slug="${streamer.slug}" class="delete-btn bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-3 rounded-lg btn-press text-sm flex-shrink-0">Sil</button>
                `;
                listContainer.appendChild(item);
            });
            
            document.querySelectorAll(".delete-btn").forEach(button => {
                button.addEventListener("click", handleDeleteStreamer);
            });
        } catch (error) {
            listContainer.innerHTML = `<p class="text-red-400 text-center">Yayıncılar yüklenemedi: ${error.message}</p>`;
        }
    };

    const handleDeleteStreamer = async (e) => {
        const slug = e.target.dataset.slug;
        
        // Use a custom modal for confirmation later if needed
        if (!confirm(`'${slug}' adlı yayıncıyı silmek istediğinizden emin misiniz?`)) return;
        
        const password = sessionStorage.getItem("adminPassword");
        try {
            const response = await fetch(`/api/streamers/${slug}`, {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password })
            });
            if (response.ok) {
                showToast("Yayıncı başarıyla silindi.");
                await loadAdminPanel();
            } else { throw new Error("Silme işlemi başarısız oldu."); }
        } catch (error) { showToast("Yayıncı silinirken bir hata oluştu.", true); }
    };
    
    document.getElementById("add-streamer-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        const data = Object.fromEntries(formData.entries());
        data.password = sessionStorage.getItem("adminPassword");
        
        for(const key in data) { if(data[key] === '') { delete data[key]; } }
        
        try {
            const response = await fetch("/api/streamers", {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            if (response.ok) {
                showToast("Yayıncı başarıyla eklendi.");
                e.target.reset();
                await loadAdminPanel();
            } else {
                 const error = await response.json();
                 throw new Error(error.error || "Ekleme işlemi başarısız oldu.");
            }
        } catch (error) { showToast(`Hata: ${error.message}`, true); }
    });

    handleRouting();
});

