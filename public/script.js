/**
 * Gelişmiş Frontend Kodu v16.0 - Nihai Sürüm
 * Bu kod, v16.0 backend ve yeni geniş tasarımla tam uyumlu çalışır.
 * - Yönlendirme sorunu DÜZELTİLDİ: Yayıncı bulunamazsa artık ana sayfaya atmak yerine hata mesajı gösterir.
 * - Admin paneline "Listeyi Yenile" butonu eklendi ve işlevselliği tanımlandı.
 * - Düzenleme modalı ve tüm yeni arayüz elemanlarını yönetir.
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
    const editModal = document.getElementById("edit-modal");
    const defaultBg = "url('https://i.ibb.co/7Nbkyyss/Untitled-design.png')";

    const showPage = (pageName) => {
        Object.values(pages).forEach(p => p.classList.remove('active'));
        if (pageName === "home") {
            pages.home.classList.add('active');
        } else {
            pages.content.classList.add('active');
            pages.streamer.style.display = 'none';
            pages.admin.style.display = 'none';
            if (pageName === 'streamer') {
                pages.streamer.style.display = 'block';
            } else if (pageName.startsWith('admin')) {
                pages.admin.style.display = 'block';
                pages.adminLogin.style.display = pageName === 'adminLogin' ? 'flex' : 'none';
                pages.adminPanel.style.display = pageName === 'adminPanel' ? 'flex' : 'none';
            }
        }
    };

    const showToast = (message, isError = false) => {
        const toast = document.getElementById("toast");
        toast.textContent = message;
        toast.className = `toast fixed bottom-5 right-5 text-white py-2 px-5 rounded-lg shadow-lg border ${isError ? 'bg-red-600/80 border-red-500' : 'bg-gray-800/80 border-gray-700'}`;
        
        void toast.offsetWidth; // Reflow
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
                // DÜZELTME: Yayıncı bulunamazsa ana sayfaya yönlendirmek yerine hata göster.
                if (!response.ok) {
                    showToast(`'${path}' adlı yayıncı bulunamadı.`, true);
                    document.body.style.backgroundImage = defaultBg;
                    showPage("home");
                    // URL'i temizle ki kullanıcı F5 yaparsa ana sayfada kalsın.
                    window.history.replaceState({}, document.title, `/`);
                    return;
                }
                const streamer = await response.json();
                
                document.getElementById("streamer-title").textContent = streamer.title;
                document.getElementById("streamer-subtitle").textContent = streamer.subtitle;
                document.body.style.backgroundImage = streamer.customBackgroundUrl ? `url('${streamer.customBackgroundUrl}')` : defaultBg;
                
                document.getElementById("kick-login").onclick = () => window.location.href = `/api/auth/redirect/kick?streamer=${streamer.slug}`;
                
                // DÜZELTME: Discord butonu her zaman görünür.
                const discordButton = document.getElementById("discord-login");
                discordButton.style.display = "flex";
                discordButton.onclick = () => window.location.href = `/api/auth/redirect/discord?streamer=${streamer.slug}`;
                
                showPage("streamer");
                handleCallbackAndUI(streamer.slug);

            } catch (error) {
                console.error("Yayıncı verisi alınırken hata:", error);
                showToast("Bir ağ hatası oluştu, lütfen tekrar deneyin.", true);
                showPage("home");
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
    
    const handleCallbackAndUI = (streamerSlug) => {
        const params = new URLSearchParams(window.location.search);
        let data = getPersistentData(streamerSlug);

        if (params.has("provider")) {
            const provider = params.get("provider");
            const isSubscribed = params.get("subscribed") === "true";
            
            data[provider] = { linked: true, subscribed: isSubscribed };
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
        const statusContainer = document.getElementById("status-container");
        statusContainer.innerHTML = '';

        const kickBadgeContainer = document.createElement('div');
        kickBadgeContainer.className = 'flex flex-wrap gap-2 justify-center';
        if (data.kick) {
            kickBadgeContainer.appendChild(createBadge('Kick : Bağlandı', true));
            kickBadgeContainer.appendChild(createBadge(data.kick.subscribed ? '✓ Abone' : 'X Abone Değil', data.kick.subscribed));
        } else {
            kickBadgeContainer.appendChild(createBadge('Kick : Bağlı Değil', false));
        }
        statusContainer.appendChild(kickBadgeContainer);

        const discordBadgeContainer = document.createElement('div');
        discordBadgeContainer.className = 'flex flex-wrap gap-2 justify-center';
        if (data.discord) {
            discordBadgeContainer.appendChild(createBadge('Discord : Bağlandı', true));
        } else {
            discordBadgeContainer.appendChild(createBadge('Discord : Bağlı Değil', false));
        }
        statusContainer.appendChild(discordBadgeContainer);
        
        // DÜZELTME: "Sayfayı kapatabilirsiniz" mesajı her iki platforma da giriş yapıldığında görünür.
        const bothChecked = data.kick && data.discord;
        document.getElementById("result-message").classList.toggle("hidden", !bothChecked);
    };

    /* -------------------- ADMIN PANEL LOGIC -------------------- */
    
    document.getElementById("admin-login-form")?.addEventListener("submit", async (e) => {
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

    // YENİ: Yenileme butonu için olay dinleyici
    document.getElementById("refresh-list-btn")?.addEventListener('click', () => {
        showToast("Liste yenileniyor...");
        loadAdminPanel();
    });

    const loadAdminPanel = async () => {
        const listContainer = document.getElementById("streamer-list-container");
        listContainer.innerHTML = '<div class="loader mx-auto"></div>';

        try {
            const response = await fetch("/api/streamers");
            if (!response.ok) throw new Error("API'den veri alınamadı.");
            const streamers = await response.json();
            
            listContainer.innerHTML = "";
            if(!streamers || streamers.length === 0){
                listContainer.innerHTML = `<p class="text-gray-500 text-center py-4">Henüz yayıncı eklenmemiş.</p>`;
                return;
            }

            streamers.forEach(streamer => {
                const item = document.createElement("div");
                item.className = "bg-gray-900/50 p-4 rounded-lg flex justify-between items-center";
                item.innerHTML = `
                    <div class="truncate mr-4 flex-1">
                        <a href="/${streamer.slug}" target="_blank" class="text-lg font-semibold text-green-400 hover:underline">${streamer.title}</a>
                        <p class="text-sm text-gray-400 truncate font-mono">/${streamer.slug}</p>
                    </div>
                    <div class="flex gap-2 flex-shrink-0">
                        <button data-slug="${streamer.slug}" class="edit-btn bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-3 rounded-lg btn-press text-sm">Düzenle</button>
                        <button data-slug="${streamer.slug}" class="delete-btn bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-3 rounded-lg btn-press text-sm">Sil</button>
                    </div>
                `;
                listContainer.appendChild(item);
            });
            
            document.querySelectorAll(".edit-btn").forEach(btn => btn.addEventListener("click", handleEditStreamer));
            document.querySelectorAll(".delete-btn").forEach(btn => btn.addEventListener("click", handleDeleteStreamer));
        } catch (error) {
            listContainer.innerHTML = `<p class="text-red-400 text-center">Yayıncılar yüklenemedi: ${error.message}</p>`;
        }
    };

    const handleEditStreamer = async (e) => {
        const slug = e.target.dataset.slug;
        const response = await fetch(`/api/streamers/${slug}`);
        const streamer = await response.json();
        
        const form = document.getElementById('edit-streamer-form');
        form.querySelector('[name="slug"]').value = streamer.slug;
        form.querySelector('[name="title"]').value = streamer.title;
        form.querySelector('[name="subtitle"]').value = streamer.subtitle;
        form.querySelector('[name="customBackgroundUrl"]').value = streamer.customBackgroundUrl || '';
        form.querySelector('[name="botghostWebhookUrl"]').value = streamer.botghostWebhookUrl || '';
        
        editModal.classList.add('active');
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
            } else { throw new Error("Silme işlemi başarısız oldu."); }
        } catch (error) { showToast("Yayıncı silinirken bir hata oluştu.", true); }
    };
    
    document.getElementById("add-streamer-form")?.addEventListener("submit", async (e) => {
        e.preventDefault();
        const form = e.target;
        const formData = new FormData(form);
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
                form.reset();
                await loadAdminPanel();
            } else {
                 const error = await response.json();
                 throw new Error(error.error || "Ekleme işlemi başarısız oldu.");
            }
        } catch (error) { showToast(`Hata: ${error.message}`, true); }
    });

    document.getElementById("edit-streamer-form")?.addEventListener("submit", async (e) => {
        e.preventDefault();
        const form = e.target;
        const formData = new FormData(form);
        const data = Object.fromEntries(formData.entries());
        data.password = sessionStorage.getItem("adminPassword");
        const slug = data.slug;
        
        const updateData = { ...data };
        delete updateData.slug;

        for(const key in updateData) { if(updateData[key] === '') { updateData[key] = null; } }

        try {
            const response = await fetch(`/api/streamers/${slug}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(updateData)
            });
            if(response.ok) {
                showToast("Yayıncı başarıyla güncellendi.");
                editModal.classList.remove('active');
                await loadAdminPanel();
            } else {
                const error = await response.json();
                throw new Error(error.error || "Güncelleme işlemi başarısız oldu.");
            }
        } catch (error) {
            showToast(`Hata: ${error.message}`, true);
        }
    });
    
    document.getElementById("cancel-edit-btn")?.addEventListener('click', () => {
        editModal.classList.remove('active');
    });

    handleRouting();
});




// --- Global Logout UX (Kick/Discord fark etmeksizin app-level logout) ---
    (function() {
      const globalLogoutBtn = document.getElementById("global-logout");

      function getCurrentSlug() {
        const p = location.pathname.replace(/^\/+/, "");
        return p.split("/")[0] || "";
      }

      // Callback'ten dönen provider/subscribed'ı session'a senkronize et
      (function syncAuthFromQuery() {
        try {
          const url = new URL(location.href);
          const provider = url.searchParams.get("provider");
          const subscribed = url.searchParams.get("subscribed");
          if (provider) {
            const auth = {
              provider,
              slug: getCurrentSlug(),
              subscribed: subscribed === "true",
              ts: Date.now()
            };
            sessionStorage.setItem("auth", JSON.stringify(auth));

            // Query temizle
            ["provider","subscribed","method","expires_at","logged_out"].forEach(k => url.searchParams.delete(k));
            const clean = url.pathname + (url.searchParams.toString() ? "?" + url.searchParams.toString() : "") + url.hash;
            window.history.replaceState({}, document.title, clean);
          }
        } catch (e) {
          console.warn("syncAuthFromQuery error", e);
        }
      })();

      function updateLogoutVisibility() {
        const isLogged = !!sessionStorage.getItem("auth");
        if (globalLogoutBtn) {
          if (isLogged) {
            globalLogoutBtn.classList.remove("hidden");
            globalLogoutBtn.style.display = ""; // ensure visible if no Tailwind
          } else {
            globalLogoutBtn.classList.add("hidden");
            globalLogoutBtn.style.display = "none";
          }
        }
      }

      // İlk yükleme
      updateLogoutVisibility();

      // Diğer sekmelerle senkronize ol
      window.addEventListener("storage", (ev) => {
        if (ev.key === "auth") updateLogoutVisibility();
      });

      // Çıkış
      globalLogoutBtn?.addEventListener("click", (e) => {
        e.preventDefault();
        try {
          sessionStorage.removeItem("auth");
          // Opsiyonel: admin oturumlarını da sil
          sessionStorage.removeItem("isAdminAuthenticated");
          sessionStorage.removeItem("adminPassword");
        } catch {}
        updateLogoutVisibility();

        const slug = getCurrentSlug();
        const url = new URL("/" + slug, location.origin);
        url.searchParams.set("logged_out", "1");
        location.href = url.toString();
      });
    })();
