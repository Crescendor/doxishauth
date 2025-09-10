/**
 * Gelişmiş Frontend Kodu v10.2
 * Bu kod, ChatGPT tarafından sağlanan v10.1 backend ve yeni görsel tasarımla tam uyumlu çalışır.
 * - Kalıcı veri saklama (localStorage) ile çoklu platform durum yönetimi.
 * - Yeni görsel arayüzü (UI) yönetir.
 * - Oturum yönetimi (sessionStorage) ile admin panelini güvence altına alır.
 */
document.addEventListener("DOMContentLoaded", () => {
    const pages = {
        home: document.getElementById("home-page"),
        appLayout: document.getElementById("app-layout"),
        streamer: document.getElementById("streamer-page"),
        adminLogin: document.getElementById("admin-login-page"),
        adminPanel: document.getElementById("admin-panel-page"),
    };

    // Belirli bir sayfayı veya layout'u aktif hale getirir
    const showPage = (pageName) => {
        // Önce tüm ana container'ları gizle
        pages.home.classList.remove("active");
        pages.appLayout.classList.remove("active");

        if (pageName === "streamer" || pageName === "adminLogin" || pageName === "adminPanel") {
             pages.appLayout.classList.add("active"); // Logo + Kart layoutunu göster
             
             // İlgili kartı layout içinde göster
             document.getElementById('streamer-page').style.display = 'none';
             document.getElementById('admin-page-container').style.display = 'none';
             
             if (pageName === "streamer") {
                document.getElementById('streamer-page').style.display = 'block';
             } else {
                document.getElementById('admin-page-container').style.display = 'block';
                document.getElementById('admin-login-page').style.display = pageName === 'adminLogin' ? 'flex' : 'none';
                document.getElementById('admin-panel-page').style.display = pageName === 'adminPanel' ? 'flex' : 'none';
             }
        } else {
            // Sadece ana sayfa gibi tekil sayfaları göster
            pages[pageName]?.classList.add("active");
        }
    };
    
    // Ekranın altında bilgilendirme mesajı gösterir
    const showToast = (message, isError = false) => {
        const toast = document.getElementById("toast");
        toast.textContent = message;
        toast.style.backgroundColor = isError ? '#c53030' : '#2d3748';
        toast.classList.add("show");
        setTimeout(() => toast.classList.remove("show"), 3000);
    };

    // URL'e göre hangi sayfanın gösterileceğini belirler
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
                
                // Arayüzü yayıncı bilgileriyle doldur
                document.getElementById("streamer-name").textContent = streamer.slug;
                document.getElementById("display-text").textContent = streamer.displayText;
                
                // Butonlara tıklama olaylarını ata
                document.getElementById("kick-login").onclick = () => window.location.href = `/api/auth/redirect/kick?streamer=${streamer.slug}`;
                const discordButton = document.getElementById("discord-login");
                if (streamer.discordGuildId && streamer.discordRoleId) {
                    discordButton.style.display = "flex";
                    discordButton.onclick = () => window.location.href = `/api/auth/redirect/discord?streamer=${streamer.slug}`;
                } else {
                    discordButton.style.display = "none";
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
    
    // localStorage'den veri okur
    const getPersistentData = (streamerSlug) => {
        const key = `doxishauth_${streamerSlug}`;
        const data = localStorage.getItem(key);
        return data ? JSON.parse(data) : { kick: null, discord: null };
    };

    // localStorage'e veri yazar
    const setPersistentData = (streamerSlug, data) => {
        const key = `doxishauth_${streamerSlug}`;
        localStorage.setItem(key, JSON.stringify(data));
    };
    
    // Giriş sonrası URL'den gelen sonucu işler ve arayüzü günceller
    const handleCallbackAndUI = (streamerSlug) => {
        const params = new URLSearchParams(window.location.search);
        let data = getPersistentData(streamerSlug);

        // Eğer URL'de yeni bir sonuç varsa, veriyi güncelle
        if (params.has("provider")) {
            const provider = params.get("provider");
            const isSubscribed = params.get("subscribed") === "true";
            const error = params.get("error");
            
            if (error) {
                showToast(`${provider.toUpperCase()} girişi başarısız: ${error}`, true);
            } else {
                 data[provider] = {
                    linked: true,
                    subscribed: isSubscribed,
                    checkedAt: new Date().toISOString()
                };
            }
            setPersistentData(streamerSlug, data);
            
            // Temiz bir görünüm için URL'i temizle
            window.history.replaceState({}, document.title, `/${streamerSlug}`);
        }
        
        // Arayüzü en güncel veriye göre güncelle
        updateUI(data);
    };

    // Arayüzü (UI) en güncel verilere göre günceller
    const updateUI = (data) => {
        // Discord UI
        const discordData = data.discord;
        document.getElementById("discord-status-not-linked").classList.toggle("hidden", !!discordData);
        document.getElementById("discord-status-linked").classList.toggle("hidden", !discordData || discordData.subscribed === null);
        document.getElementById("discord-status-subscribed").classList.toggle("hidden", !discordData || !discordData.subscribed);
        document.getElementById("discord-status-not-subscribed").classList.toggle("hidden", !discordData || discordData.subscribed);

        // Kick UI
        const kickData = data.kick;
        document.getElementById("kick-status-not-linked").classList.toggle("hidden", !!kickData);
        document.getElementById("kick-status-linked").classList.toggle("hidden", !kickData || kickData.subscribed === null);
        document.getElementById("kick-status-subscribed").classList.toggle("hidden", !kickData || !kickData.subscribed);
        document.getElementById("kick-status-not-subscribed").classList.toggle("hidden", !kickData || kickData.subscribed);

        // Eğer her iki kontrol de yapıldıysa sonuç mesajını göster
        document.getElementById("result-message").classList.toggle("hidden", !(kickData && discordData));
    };

    /* -------------------- ADMIN PANEL LOGIC -------------------- */
    
    // Admin Giriş Formu
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
                window.location.pathname = "/admin"; // Sayfayı yenileyerek paneli yükle
            } else {
                showToast("Hatalı şifre!", true);
            }
        } catch (error) {
            showToast("Giriş sırasında bir hata oluştu.", true);
        }
    });
    
    // Çıkış Butonu
    const logoutBtn = document.getElementById("logout-btn");
    if(logoutBtn) {
        logoutBtn.addEventListener('click', () => {
            sessionStorage.clear();
            window.location.pathname = "/";
        });
    }

    // Admin Panelini Yükle
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
                item.className = "bg-gray-800 p-3 rounded-lg flex justify-between items-center";
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

    // Yayıncı Sil
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
    
    // Yayıncı Ekle
    document.getElementById("add-streamer-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        const data = Object.fromEntries(formData.entries());
        data.password = sessionStorage.getItem("adminPassword");
        
        // İsteğe bağlı alanları boşsa gönderme
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

    // Sayfa yüklendiğinde yönlendirmeyi başlat
    handleRouting();
    window.addEventListener("popstate", handleRouting);
});

