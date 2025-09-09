document.addEventListener('DOMContentLoaded', () => {
    // Sayfa elemanları
    const pages = document.querySelectorAll('.page');
    const streamerNameEl = document.getElementById('streamer-name');
    const subscriptionStatusEl = document.getElementById('subscription-status');
    const streamerListEl = document.getElementById('streamer-list');

    async function router() {
        const path = window.location.pathname.toLowerCase();
        
        let streamers = [];
        try {
            const response = await fetch('/api/streamers');
            if(response.ok) {
                const data = await response.json();
                streamers = data.streamers || [];
            } else {
                 console.error("Yayıncılar alınamadı:", response.statusText);
            }
        } catch (error) {
            console.error("Yayıncıları alırken hata oluştu:", error);
        }

        pages.forEach(p => p.classList.remove('active'));

        if (path === '/admin') {
            handleAdminRoute();
        } else if (path === '/' || path === '/index.html') {
            document.getElementById('home-page').classList.add('active');
        } else {
            const streamerSlug = path.substring(1).replace(/[^a-z0-9_]/gi, '');
            if (streamers.includes(streamerSlug)) {
                handleStreamerRoute(streamerSlug);
            } else {
                document.getElementById('home-page').classList.add('active');
            }
        }
    }

    function handleStreamerRoute(slug) {
        document.getElementById('streamer-page').classList.add('active');
        streamerNameEl.textContent = slug;
        subscriptionStatusEl.textContent = '';
        
        document.getElementById('kick-login').onclick = () => checkSubscription(slug);
        document.getElementById('discord-login').onclick = () => checkSubscription(slug);
    }

    function handleAdminRoute() {
        const pass = prompt('Admin şifresini girin:');
        if (pass) {
            document.getElementById('admin-page').classList.add('active');
            loadStreamersIntoList();
            
            const addStreamerForm = document.getElementById('add-streamer-form');
            addStreamerForm.onsubmit = async (e) => {
                e.preventDefault();
                const input = document.getElementById('streamer-slug-input');
                const newSlug = input.value.trim().toLowerCase();
                if (newSlug) {
                    try {
                        const response = await fetch('/api/streamers', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({ slug: newSlug, password: pass }),
                        });

                        if (response.ok) {
                            alert(`${newSlug} başarıyla eklendi!`);
                            loadStreamersIntoList();
                            input.value = '';
                        } else {
                            const errorData = await response.json();
                            alert(`Hata: ${errorData.error || 'Bilinmeyen bir hata oluştu.'}`);
                        }
                    } catch (error) {
                        console.error('Yayıncı eklenirken hata:', error);
                        alert('Sunucuya bağlanırken bir hata oluştu.');
                    }
                }
            };
        } else {
             window.location.href = '/';
        }
    }

    async function loadStreamersIntoList() {
        streamerListEl.innerHTML = '<div class="loader"></div>';
        try {
            const response = await fetch('/api/streamers');
            if(!response.ok) throw new Error('Yayıncı listesi alınamadı.');
            
            const data = await response.json();
            const streamers = data.streamers || [];
            
            streamerListEl.innerHTML = '';
            if (streamers.length === 0) {
                streamerListEl.innerHTML = '<li class="text-gray-500">Henüz yayıncı eklenmedi.</li>';
                return;
            }
            streamers.forEach(slug => {
                const li = document.createElement('li');
                li.className = 'text-white';
                li.textContent = slug;
                streamerListEl.appendChild(li);
            });
        } catch(error) {
            console.error(error);
            streamerListEl.innerHTML = '<li class="text-red-500">Yayıncılar yüklenemedi.</li>';
        }
    }
    
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

    // Router'ı çalıştır
    router();
});

