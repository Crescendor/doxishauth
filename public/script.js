/**
 * Gelişmiş Frontend Kodu v11.0 - Yeni Arayüz
 * Bu kod, ChatGPT tarafından sağlanan v10.1 backend ve yeni görsel tasarımla tam uyumlu çalışır.
 * - Kalıcı veri saklama (localStorage) ile çoklu platform durum yönetimi.
 * - Yeni "retrowave" görsel arayüzünü (UI) yönetir.
 * - Oturum yönetimi (sessionStorage) ile admin panelini güvence altına alır.
 */
document.addEventListener("DOMContentLoaded", () => {
    const pages = {
        home: document.getElementById("home-page"),
        appLayout: document.getElementById("app-layout"),
        streamer: document.getElementById("streamer-page"),
        adminLogin: document.getElementById("admin-login-page"),
        adminPanel: document.getElementById("admin-panel-page"),
        adminContainer: document.getElementById("admin-page-container"),
    };

    const showPage = (pageName) => {
        pages.home.classList.remove("active");
        pages.appLayout.classList.remove("active");

        if (["streamer", "adminLogin", "adminPanel"].includes(pageName)) {
            pages.appLayout.classList.add("active");
            pages.streamer.style.display = pageName === "streamer" ? "flex" : "none";
            pages.adminContainer.style.display = pageName.startsWith("admin") ? "block" : "none";
            
            if (pageName.startsWith("admin")) {
                pages.adminLogin.classList.toggle("active", pageName === "adminLogin");
                pages.adminPanel.classList.toggle("active", pageName === "adminPanel");
            }
        } else {
            pages.home.classList.add("active");
        }
    };
    
    const showToast = (message, isError = false) => {
        const toast = document.getElementById("toast");
        toast.textContent = message;
        toast.className = `fixed bottom-5 right-5 text-white py-2 px-5 rounded-lg shadow-lg opacity-0 translate-y-3 transition-all duration-300 ${isError ? 'bg-red-600 border-red-500' : 'bg-gray-800 border-gray-700'}`;
        
        // Trigger reflow to restart animation
        toast.offsetHeight;

        toast.classList.add("show", "opacity-100", "translate-y-0");
        setTimeout(() => {
            toast.classList.remove("opacity-100", "translate-y-0");
        }, 3000);
    };

    const handleRouting = async () => {
        const path = window.location.pathname.replace(/^\/+/, "");
        if (path.toLowerCase() === "admin") {
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
                    showPage("home");
                    return;
                }
                const streamer = await response.json();
                
                document.getElementById("streamer-name").textContent = streamer.slug;
                document.getElementById("display-text").textContent = streamer.displayText;
                
                document.getElementById("kick-login").onclick = () => window.location.href = `/api/auth/redirect/kick?streamer=${streamer.slug}`;
                const discordButton = document.getElementById("discord-login");
                if (streamer.discordGuildId && streamer.discordRoleId) {
                    discordButton.classList.remove("hidden");
                    discordButton.onclick = () => window.location.href = `/api/auth/redirect/discord?streamer=${streamer.slug}`;
                } else {
                    discordButton.classList.add("hidden");
                }
                
                showPage("streamer");
                handleCallbackAndUI(streamer.slug);

            } catch (error) {
                console.error("Yayıncı verisi alınırken hata:", error);
                showPage("home");
            }
        } else {
            showPage("home");
        }
    };
    
    const getPersistentData = (streamerSlug) => {
        const key = `doxishauth_${streamerSlug}`;
        try {
            const data = localStorage.getItem(key);
            return data ? JSON.parse(data) : { kick: null, discord: null };
        } catch (e) {
            return { kick: null, discord: null };
        }
    };

    const setPersistentData = (streamerSlug, data) => {
        const key = `doxishauth_${streamerSlug}`;
        localStorage.setItem(key, JSON.stringify(data));
    };
    
    const handleCallbackAndUI = (streamerSlug) => {
        const params = new URLSearchParams(window.location.search);
        let data = getPersistentData(streamerSlug);

        if (params.has("provider")) {
            const provider = params.get("provider");
            const isSubscribed = params.get("subscribed") === "true";
            const error = params.get("error");
            
            if (error) {
                showToast(`${provider.charAt(0).toUpperCase() + provider.slice(1)} girişi başarısız: ${error}`, true);
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
        
        updateUI(data);
    };

    const createBadge = (text, isGreen) => {
        const badge = document.createElement('span');
        badge.className = `status-badge ${isGreen ? 'status-badge-green' : 'status-badge-red'}`;
        badge.textContent = text;
        return badge;
    };

    const updateUI = (data) => {
        const discordContainer = document.getElementById("discord-status-container");
        const discordBadges = document.getElementById("discord-status-badges");
        
        discordBadges.innerHTML = '';
        if (data.discord) {
            discordContainer.classList.remove('hidden');
            discordBadges.appendChild(createBadge('Discord : Bağlandı', true));
            discordBadges.appendChild(createBadge(data.discord.subscribed ? 'Rol : Mevcut' : 'Rol : Mevcut Değil', data.discord.subscribed));
        } else {
            discordContainer.classList.remove('hidden');
            discordBadges.appendChild(createBadge('Discord : Bağlı Değil', false));
        }

        const kickContainer = document.getElementById("kick-status-container");
        const kickBadges = document.getElementById("kick-status-badges");

        kickBadges.innerHTML = '';
        if (data.kick) {
            kickContainer.classList.remove('hidden');
            kickBadges.appendChild(createBadge('Kick : Bağlandı', true));
            kickBadges.appendChild(createBadge(data.kick.subscribed ? 'Abonelik : Kanalda Abone' : 'Abonelik : Kanalda Abone Değil', data.kick.subscribed));
        } else {
            kickContainer.classList.remove('hidden');
            kickBadges.appendChild(createBadge('Kick : Bağlı Değil', false));
        }

        const bothChecked = data.kick && (data.discord || !document.getElementById('discord-login').offsetParent);
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
            } else {
                showToast("Hatalı şifre!", true);
            }
        } catch (error) {
            showToast("Giriş sırasında bir hata oluştu.", true);
        }
    });
    
    const logoutBtn = document.getElementById("logout-btn");
    if(logoutBtn) {
        logoutBtn.addEventListener('click', () => {
            sessionStorage.clear();
            window.location.pathname = "/";
        });
    }

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
                    <div>
                        <a href="/${streamer.slug}" target="_blank" class="text-lg font-semibold text-green-400 hover:underline">${streamer.slug}</a>
                        <p class="text-sm text-gray-400">${streamer.displayText}</p>
                    </div>
                    <button data-slug="${streamer.slug}" class="delete-btn bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-3 rounded-lg btn-press text-sm">Sil</button>
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
            } else {
                throw new Error("Silme işlemi başarısız oldu.");
            }
        } catch (error) {
            showToast("Yayıncı silinirken bir hata oluştu.", true);
        }
    };
    
    document.getElementById("add-streamer-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        const data = Object.fromEntries(formData.entries());
        data.password = sessionStorage.getItem("adminPassword");
        
        for(const key in data) {
            if(data[key] === '') {
                delete data[key];
            }
        }
        
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
        } catch (error) {
            showToast(`Hata: ${error.message}`, true);
        }
    });

    handleRouting();
    window.addEventListener("popstate", handleRouting);
});

