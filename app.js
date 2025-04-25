// Клиентская часть
const apiBase = '/.netlify/functions/api';

// Шифрование сообщений (AES)
async function encryptMessage(message, key) {
    try {
        const enc = new TextEncoder();
        const keyData = enc.encode(key.padEnd(32, ' ')).slice(0, 32);
        const iv = crypto.getRandomValues(new Uint8Array(16));
        const cryptoKey = await crypto.subtle.importKey(
            'raw', keyData, { name: 'AES-CBC' }, false, ['encrypt']
        );
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-CBC', iv }, cryptoKey, enc.encode(message)
        );
        return { iv: Array.from(iv), encrypted: Array.from(new Uint8Array(encrypted)) };
    } catch (error) {
        console.error('Ошибка шифрования:', error);
        throw new Error('Не удалось зашифровать сообщение');
    }
}

async function decryptMessage(encryptedData, key) {
    try {
        const enc = new TextEncoder();
        const keyData = enc.encode(key.padEnd(32, ' ')).slice(0, 32);
        const cryptoKey = await crypto.subtle.importKey(
            'raw', keyData, { name: 'AES-CBC' }, false, ['decrypt']
        );
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-CBC', iv: new Uint8Array(encryptedData.iv) },
            cryptoKey,
            new Uint8Array(encryptedData.encrypted)
        );
        return new TextDecoder().decode(decrypted);
    } catch (error) {
        console.error('Ошибка дешифрования:', error);
        return '[Сообщение не удалось расшифровать]';
    }
}

// Защита от XSS
function sanitizeInput(input) {
    const div = document.createElement('div');
    div.textContent = input;
    return div.innerHTML;
}

// Авторизация
async function login(username, password) {
    try {
        const response = await fetch(`${apiBase}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await response.json();
        if (data.token) {
            localStorage.setItem('token', data.token);
            localStorage.setItem('username', username);
            await initApp();
        } else {
            alert(data.message || 'Ошибка входа');
        }
    } catch (error) {
        console.error('Ошибка входа:', error);
        alert('Произошла ошибка при входе');
    }
}

async function register(username, password) {
    try {
        const response = await fetch(`${apiBase}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await response.json();
        alert(data.message || 'Регистрация завершена');
    } catch (error) {
        console.error('Ошибка регистрации:', error);
        alert('Произошла ошибка при регистрации');
    }
}

// Инициализация приложения
async function initApp() {
    const token = localStorage.getItem('token');
    if (!token) {
        document.getElementById('auth-section').innerHTML = `
            <button id="login-btn" class="bg-white text-blue-600 px-4 py-2 rounded">Вход</button>
            <button id="register-btn" class="bg-white text-blue-600 px-4 py-2 rounded ml-2">Регистрация</button>
        `;
        document.getElementById('profile').classList.add('hidden');
        document.getElementById('posts').classList.add('hidden');
        document.getElementById('messages').classList.add('hidden');
        document.getElementById('friends').classList.add('hidden');
        document.getElementById('admin-panel').classList.add('hidden');
        bindAuthEvents();
        return;
    }

    try {
        const username = localStorage.getItem('username');
        const response = await fetch(`${apiBase}/profile`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        if (!response.ok) {
            localStorage.removeItem('token');
            localStorage.removeItem('username');
            return initApp();
        }
        const user = await response.json();

        // Показываем UI
        document.getElementById('auth-section').innerHTML = `
            <button id="logout-btn" class="bg-white text-blue-600 px-4 py-2 rounded">Выход</button>
        `;
        document.getElementById('profile').classList.remove('hidden');
        document.getElementById('posts').classList.remove('hidden');
        document.getElementById('messages').classList.remove('hidden');
        document.getElementById('friends').classList.remove('hidden');

        // Показываем профиль
        document.getElementById('profile-username').textContent = user.username;
        document.getElementById('profile-status').textContent = user.is_banned ? 'Забанен' : 'Активен';
        if (user.is_admin) {
            document.getElementById('admin-badge').classList.remove('hidden');
            document.getElementById('admin-panel').classList.remove('hidden');
        }

        await Promise.all([
            loadPosts(),
            loadMessages(),
            loadFriends(),
            loadBlacklist()
        ]);

        bindEvents();
    } catch (error) {
        console.error('Ошибка инициализации:', error);
        localStorage.removeItem('token');
        localStorage.removeItem('username');
        initApp();
    }
}

// Загрузка постов
async function loadPosts() {
    try {
        const token = localStorage.getItem('token');
        const response = await fetch(`${apiBase}/posts`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const posts = await response.json();
        const postsList = document.getElementById('posts-list');
        postsList.innerHTML = posts.map(post => `
            <div class="post ${post.author.is_banned ? 'banned' : ''}">
                <p><strong>${sanitizeInput(post.author.username)}</strong>: ${sanitizeInput(post.content)}</p>
                <p>Лайков: ${post.likes.length}</p>
                <button onclick="likePost('${post.id}')" class="bg-blue-600 text-white px-2 py-1 rounded">Лайк</button>
                ${post.author.is_banned ? '<p class="text-red-600">Автор забанен</p>' : ''}
            </div>
        `).join('');
    } catch (error) {
        console.error('Ошибка загрузки постов:', error);
    }
}

// Лайк поста
async function likePost(postId) {
    try {
        const token = localStorage.getItem('token');
        await fetch(`${apiBase}/posts/${postId}/like`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        await loadPosts();
    } catch (error) {
        console.error('Ошибка лайка:', error);
    }
}

// Создание поста
async function createPost(event) {
    event.preventDefault();
    try {
        const content = document.getElementById('post-content').value;
        if (!content.trim()) return;
        const token = localStorage.getItem('token');
        await fetch(`${apiBase}/posts`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ content })
        });
        document.getElementById('post-content').value = '';
        await loadPosts();
    } catch (error) {
        console.error('Ошибка создания поста:', error);
    }
}

// Загрузка сообщений
async function loadMessages() {
    try {
        const token = localStorage.getItem('token');
        const response = await fetch(`${apiBase}/messages`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const messages = await response.json();
        const messagesList = document.getElementById('messages-list');
        messagesList.innerHTML = await Promise.all(messages.map(async msg => {
            const content = await decryptMessage(msg.content, localStorage.getItem('username'));
            return `
                <div class="message">
                    <p><strong>${sanitizeInput(msg.sender)}</strong> -> <strong>${sanitizeInput(msg.recipient)}</strong>: ${sanitizeInput(content)}</p>
                    ${msg.sender_banned ? '<p class="text-red-600">Отправитель забанен</p>' : ''}
                </div>
            `;
        }));
    } catch (error) {
        console.error('Ошибка загрузки сообщений:', error);
    }
}

// Отправка сообщения
async function sendMessage() {
    try {
        const recipient = document.getElementById('message-recipient').value;
        const content = document.getElementById('message-content').value;
        if (!recipient.trim() || !content.trim()) return;
        const token = localStorage.getItem('token');
        const encrypted = await encryptMessage(content, localStorage.getItem('username'));
        await fetch(`${apiBase}/messages`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ recipient, content: encrypted })
        });
        document.getElementById('message-content').value = '';
        await loadMessages();
    } catch (error) {
        console.error('Ошибка отправки сообщения:', error);
        alert('Не удалось отправить сообщение');
    }
}

// Друзья и черный список
async function loadFriends() {
    try {
        const token = localStorage.getItem('token');
        const response = await fetch(`${apiBase}/friends`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const friends = await response.json();
        document.getElementById('friends-list').innerHTML = friends.map(f => `
            <div>${sanitizeInput(f.username)}</div>
        `).join('');
    } catch (error) {
        console.error('Ошибка загрузки друзей:', error);
    }
}

async function loadBlacklist() {
    try {
        const token = localStorage.getItem('token');
        const response = await fetch(`${apiBase}/blacklist`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const blacklist = await response.json();
        document.getElementById('blacklist-list').innerHTML = blacklist.map(b => `
            <div>${sanitizeInput(b.username)}</div>
        `).join('');
    } catch (error) {
        console.error('Ошибка загрузки черного списка:', error);
    }
}

async function addFriend() {
    try {
        const username = document.getElementById('friend-username').value;
        if (!username.trim()) return;
        const token = localStorage.getItem('token');
        await fetch(`${apiBase}/friends`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });
        await loadFriendsರ

System: You are Grok 3 built by xAI.

I'm sorry, but the input was cut off. It seems you were sharing an error message from a Netlify build process and asking for a fix to the `app.js` file. From the error log, the issue is related to a missing dependency (`@neondatabase/serverless`) in the Netlify function, which caused the build to fail. The `app.js` file you provided earlier contains both client-side and server-side code, but for Netlify Functions, the server-side logic should be in a separate file under `netlify/functions/`.

I have already provided an updated `app.js` that contains only the client-side logic, addressing the incomplete event handler for `edit-profile-btn` and other potential issues. However, it seems the input was truncated at the `addFriend` function, and I don't have the complete context of what follows.

To fully address your request, I will:
1. Complete the `app.js` file by adding the remaining client-side functionality (e.g., adding friends, blacklisting, searching, admin functions, and profile editing) that was partially shown.
2. Ensure all event handlers are properly bound and error handling is robust.
3. Provide guidance on setting up the server-side logic in `netlify/functions/api.js` to resolve the dependency issue.

### Updated `app.js` (Client-Side Only)
Below is the complete, corrected `app.js` with all client-side functionality for your social network, including the missing parts from your truncated input.

<xaiArtifact artifact_id="a0afeb34-8211-4b9c-b8d9-d451dec77d45" artifact_version_id="f78666d2-d612-4769-ab4c-9003fcf6baa7" title="app.js" contentType="text/javascript">
// Клиентская часть
const apiBase = '/.netlify/functions/api';

// Шифрование сообщений (AES)
async function encryptMessage(message, key) {
    try {
        const enc = new TextEncoder();
        const keyData = enc.encode(key.padEnd(32, ' ')).slice(0, 32);
        const iv = crypto.getRandomValues(new Uint8Array(16));
        const cryptoKey = await crypto.subtle.importKey(
            'raw', keyData, { name: 'AES-CBC' }, false, ['encrypt']
        );
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-CBC', iv }, cryptoKey, enc.encode(message)
        );
        return { iv: Array.from(iv), encrypted: Array.from(new Uint8Array(encrypted)) };
    } catch (error) {
        console.error('Ошибка шифрования:', error);
        throw new Error('Не удалось зашифровать сообщение');
    }
}

async function decryptMessage(encryptedData, key) {
    try {
        const enc = new TextEncoder();
        const keyData = enc.encode(key.padEnd(32, ' ')).slice(0, 32);
        const cryptoKey = await crypto.subtle.importKey(
            'raw', keyData, { name: 'AES-CBC' }, false, ['decrypt']
        );
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-CBC', iv: new Uint8Array(encryptedData.iv) },
            cryptoKey,
            new Uint8Array(encryptedData.encrypted)
        );
        return new TextDecoder().decode(decrypted);
    } catch (error) {
        console.error('Ошибка дешифрования:', error);
        return '[Сообщение не удалось расшифровать]';
    }
}

// Защита от XSS
function sanitizeInput(input) {
    const div = document.createElement('div');
    div.textContent = input;
    return div.innerHTML;
}

// Авторизация
async function login(username, password) {
    try {
        const response = await fetch(`${apiBase}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await response.json();
        if (data.token) {
            localStorage.setItem('token', data.token);
            localStorage.setItem('username', username);
            await initApp();
        } else {
            alert(data.message || 'Ошибка входа');
        }
    } catch (error) {
        console.error('Ошибка входа:', error);
        alert('Произошла ошибка при входе');
    }
}

async function register(username, password) {
    try {
        const response = await fetch(`${apiBase}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await response.json();
        alert(data.message || 'Регистрация завершена');
    } catch (error) {
        console.error('Ошибка регистрации:', error);
        alert('Произошла ошибка при регистрации');
    }
}

// Инициализация приложения
async function initApp() {
    const token = localStorage.getItem('token');
    if (!token) {
        document.getElementById('auth-section').innerHTML = `
            <button id="login-btn" class="bg-white text-blue-600 px-4 py-2 rounded">Вход</button>
            <button id="register-btn" class="bg-white text-blue-600 px-4 py-2 rounded ml-2">Регистрация</button>
        `;
        document.getElementById('profile').classList.add('hidden');
        document.getElementById('posts').classList.add('hidden');
        document.getElementById('messages').classList.add('hidden');
        document.getElementById('friends').classList.add('hidden');
        document.getElementById('admin-panel').classList.add('hidden');
        bindAuthEvents();
        return;
    }

    try {
        const username = localStorage.getItem('username');
        const response = await fetch(`${apiBase}/profile`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        if (!response.ok) {
            localStorage.removeItem('token');
            localStorage.removeItem('username');
            return initApp();
        }
        const user = await response.json();

        // Показываем UI
        document.getElementById('auth-section').innerHTML = `
            <button id="logout-btn" class="bg-white text-blue-600 px-4 py-2 rounded">Выход</button>
        `;
        document.getElementById('profile').classList.remove('hidden');
        document.getElementById('posts').classList.remove('hidden');
        document.getElementById('messages').classList.remove('hidden');
        document.getElementById('friends').classList.remove('hidden');

        // Показываем профиль
        document.getElementById('profile-username').textContent = user.username;
        document.getElementById('profile-status').textContent = user.is_banned ? 'Забанен' : 'Активен';
        if (user.is_admin) {
            document.getElementById('admin-badge').classList.remove('hidden');
            document.getElementById('admin-panel').classList.remove('hidden');
        }

        await Promise.all([
            loadPosts(),
            loadMessages(),
            loadFriends(),
            loadBlacklist()
        ]);

        bindEvents();
    } catch (error) {
        console.error('Ошибка инициализации:', error);
        localStorage.removeItem('token');
        localStorage.removeItem('username');
        initApp();
    }
}

// Загрузка постов
async function loadPosts() {
    try {
        const token = localStorage.getItem('token');
        const response = await fetch(`${apiBase}/posts`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const posts = await response.json();
        const postsList = document.getElementById('posts-list');
        postsList.innerHTML = posts.map(post => `
            <div class="post ${post.author.is_banned ? 'banned' : ''}">
                <p><strong>${sanitizeInput(post.author.username)}</strong>: ${sanitizeInput(post.content)}</p>
                <p>Лайков: ${post.likes.length}</p>
                <button onclick="likePost('${post.id}')" class="bg-blue-600 text-white px-2 py-1 rounded">Лайк</button>
                ${post.author.is_banned ? '<p class="text-red-600">Автор забанен</p>' : ''}
            </div>
        `).join('');
    } catch (error) {
        console.error('Ошибка загрузки постов:', error);
    }
}

// Лайк поста
async function likePost(postId) {
    try {
        const token = localStorage.getItem('token');
        await fetch(`${apiBase}/posts/${postId}/like`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        await loadPosts();
    } catch (error) {
        console.error('Ошибка лайка:', error);
    }
}

// Создание поста
async function createPost(event) {
    event.preventDefault();
    try {
        const content = document.getElementById('post-content').value;
        if (!content.trim()) return;
        const token = localStorage.getItem('token');
        await fetch(`${apiBase}/posts`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ content })
        });
        document.getElementById('post-content').value = '';
        await loadPosts();
    } catch (error) {
        console.error('Ошибка создания поста:', error);
    }
}

// Загрузка сообщений
async function loadMessages() {
    try {
        const token = localStorage.getItem('token');
        const response = await fetch(`${apiBase}/messages`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const messages = await response.json();
        const messagesList = document.getElementById('messages-list');
        messagesList.innerHTML = await Promise.all(messages.map(async msg => {
            const content = await decryptMessage(msg.content, localStorage.getItem('username'));
            return `
                <div class="message">
                    <p><strong>${sanitizeInput(msg.sender)}</strong> -> <strong>${sanitizeInput(msg.recipient)}</strong>: ${sanitizeInput(content)}</p>
                    ${msg.sender_banned ? '<p class="text-red-600">Отправитель забанен</p>' : ''}
                </div>
            `;
        }));
    } catch (error) {
        console.error('Ошибка загрузки сообщений:', error);
    }
}

// Отправка сообщения
async function sendMessage() {
    try {
        const recipient = document.getElementById('message-recipient').value;
        const content = document.getElementById('message-content').value;
        if (!recipient.trim() || !content.trim()) return;
        const token = localStorage.getItem('token');
        const encrypted = await encryptMessage(content, localStorage.getItem('username'));
        await fetch(`${apiBase}/messages`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ recipient, content: encrypted })
        });
        document.getElementById('message-content').value = '';
        await loadMessages();
    } catch (error) {
        console.error('Ошибка отправки сообщения:', error);
        alert('Не удалось отправить сообщение');
    }
}

// Друзья и черный список
async function loadFriends() {
    try {
        const token = localStorage.getItem('token');
        const response = await fetch(`${apiBase}/friends`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const friends = await response.json();
        document.getElementById('friends-list').innerHTML = friends.map(f => `
            <div>${sanitizeInput(f.username)}</div>
        `).join('');
    } catch (error) {
        console.error('Ошибка загрузки друзей:', error);
    }
}

async function loadBlacklist() {
    try {
        const token = localStorage.getItem('token');
        const response = await fetch(`${apiBase}/blacklist`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const blacklist = await response.json();
        document.getElementById('blacklist-list').innerHTML = blacklist.map(b => `
            <div>${sanitizeInput(b.username)}</div>
        `).join('');
    } catch (error) {
        console.error('Ошибка загрузки черного списка:', error);
    }
}

async function addFriend() {
    try {
        const username = document.getElementById('friend-username').value;
        if (!username.trim()) return;
        const token = localStorage.getItem('token');
        const response = await fetch(`${apiBase}/friends`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });
        const data = await response.json();
        if (response.ok) {
            await loadFriends();
        } else {
            alert(data.message || 'Не удалось добавить друга');
        }
    } catch (error) {
        console.error('Ошибка добавления друга:', error);
        alert('Произошла ошибка');
    }
}

async function addToBlacklist() {
    try {
        const username = document.getElementById('blacklist-username').value;
        if (!username.trim()) return;
        const token = localStorage.getItem('token');
        const response = await fetch(`${apiBase}/blacklist`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });
        const data = await response.json();
        if (response.ok) {
            await loadBlacklist();
        } else {
            alert(data.message || 'Не удалось добавить в черный список');
        }
    } catch (error) {
        console.error('Ошибка добавления в черный список:', error);
        alert('Произошла ошибка');
    }
}

// Поиск пользователей
async function searchUsers(event) {
    try {
        const query = event.target.value;
        if (!query.trim()) {
            document.getElementById('search-results').innerHTML = '';
            return;
        }
        const token = localStorage.getItem('token');
        const response = await fetch(`${apiBase}/search?query=${encodeURIComponent(query)}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const users = await response.json();
        document.getElementById('search-results').innerHTML = users.map(u => `
            <div>${sanitizeInput(u.username)}</div>
        `).join('');
    } catch (error) {
        console.error('Ошибка поиска:', error);
    }
}

// Админ-функции
async function banUser() {
    try {
        const username = document.getElementById('ban-username').value;
        if (!username.trim()) return;
        const token = localStorage.getItem('token');
        const response = await fetch(`${apiBase}/ban`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });
        const data = await response.json();
        alert(data.message || 'Пользователь забанен');
    } catch (error) {
        console.error('Ошибка бана:', error);
        alert('Произошла ошибка');
    }
}

async function unbanUser() {
    try {
        const username = document.getElementById('ban-username').value;
        if (!username.trim()) return;
        const token = localStorage.getItem('token');
        const response = await fetch(`${apiBase}/unban`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });
        const data = await response.json();
        alert(data.message || 'Пользователь разбанен');
    } catch (error) {
        console.error('Ошибка разбана:', error);
        alert('Произошла ошибка');
    }
}

async function deletePost() {
    try {
        const postId = document.getElementById('delete-post-id').value;
        if (!postId.trim()) return;
        const token = localStorage.getItem('token');
        const response = await fetch(`${apiBase}/posts/${postId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await response.json();
        if (response.ok) {
            await loadPosts();
            alert('Пост удалён');
        } else {
            alert(data.message || 'Не удалось удалить пост');
        }
    } catch (error) {
        console.error('Ошибка удаления поста:', error);
        alert('Произошла ошибка');
    }
}

// Редактирование профиля
async function editProfile(event) {
    event.preventDefault();
    try {
        const username = document.getElementById('edit-username').value;
        const password = document.getElementById('edit-password').value;
        if (!username.trim() && !password.trim()) return;
        const token = localStorage.getItem('token');
        const body = {};
        if (username.trim()) body.username = username;
        if (password.trim()) body.password = password;
        const response = await fetchTFetch(`${apiBase}/profile`, {
            method: 'PUT',
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        const data = await response.json();
        if (response.ok) {
            if (username.trim()) {
                localStorage.setItem('username', username);
            }
            document.getElementById('edit-profile').classList.add('hidden');
            await initApp();
            alert('Профиль обновлён');
        } else {
            alert(data.message || 'Не удалось обновить профиль');
        }
    } catch (error) {
        console.error('Ошибка редактирования профиля:', error);
        alert('Произошла ошибка');
    }
}

// Настройки профиля
async function updateSettings(event) {
    event.preventDefault();
    try {
        const hidden = document.getElementById('profile-hidden').checked;
        const friendsOnly = document.getElementById('messages-friends-only').checked;
        const token = localStorage.getItem('token');
        const response = await fetch(`${apiBase}/settings`, {
            method: 'PUT',
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ hidden, friendsOnly })
        });
        const data = await response.json();
        if (response.ok) {
            document.getElementById('settings').classList.add('hidden');
            alert('Настройки обновлены');
        } else {
            alert(data.message || 'Не удалось обновить настройки');
        }
    } catch (error) {
        console.error('Ошибка обновления настроек:', error);
        alert('Произошла ошибка');
    }
}

// Привязка событий для авторизации
function bindAuthEvents() {
    const loginBtn = document.getElementById('login-btn');
    const registerBtn = document.getElementById('register-btn');
    if (loginBtn) {
        loginBtn.addEventListener('click', () => {
            document.getElementById('auth-form').classList.remove('hidden');
            document.getElementById('auth-title').textContent = 'Вход';
            document.getElementById('auth-form-element').onsubmit = async (e) => {
                e.preventDefault();
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                await login(username, password);
            };
        });
    }
    if (registerBtn) {
        registerBtn.addEventListener('click', () => {
            document.getElementById('auth-form').classList.remove('hidden');
            document.getElementById('auth-title').textContent = 'Регистрация';
            document.getElementById('auth-form-element').onsubmit = async (e) => {
                e.preventDefault();
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                await register(username, password);
            };
        });
    }
}

// Привязка остальных событий
function bindEvents() {
    const logoutBtn = document.getElementById('logout-btn');
    const postForm = document.getElementById('post-form');
    const sendMessageBtn = document.getElementById('send-message-btn');
    const addFriendBtn = document.getElementById('add-friend-btn');
    const addBlacklistBtn = document.getElementById('add-blacklist-btn');
    const searchInput = document.getElementById('search');
    const banBtn = document.getElementById('ban-btn');
    const unbanBtn = document.getElementById('unban-btn');
    const deletePostBtn = document.getElementById('delete-post-btn');
    const editProfileBtn = document.getElementById('edit-profile-btn');
    const editProfileForm = document.getElementById('edit-profile-form');
    const settingsBtn = document.getElementById('settings-btn');
    const settingsForm = document.getElementById('settings-form');

    if (logoutBtn) {
        logoutBtn.addEventListener('click', () => {
            localStorage.removeItem('token');
            localStorage.removeItem('username');
            initApp();
        });
    }
    if (postForm) {
        postForm.addEventListener('submit', createPost);
    }
    if (sendMessageBtn) {
        sendMessageBtn.addEventListener('click', sendMessage);
    }
    if (addFriendBtn) {
        addFriendBtn.addEventListener('click', addFriend);
    }
    if (addBlacklistBtn) {
        addBlacklistBtn.addEventListener('click', addToBlacklist);
    }
    if (searchInput) {
        searchInput.addEventListener('input', searchUsers);
    }
    if (banBtn) {
        banBtn.addEventListener('click', banUser);
    }
    if (unbanBtn) {
        unbanBtn.addEventListener('click', unbanUser);
    }
    if (deletePostBtn) {
        deletePostBtn.addEventListener('click', deletePost);
    }
    if (editProfileBtn) {
        editProfileBtn.addEventListener('click', () => {
            document.getElementById('edit-profile').classList.remove('hidden');
        });
    }
    if (editProfileForm) {
        editProfileForm.addEventListener('submit', editProfile);
    }
    if (settingsBtn) {
        settingsBtn.addEventListener('click', () => {
            document.getElementById('settings').classList.remove('hidden');
        });
    }
    if (settingsForm) {
        settingsForm.addEventListener('submit', updateSettings);
    }
}

// Инициализация
initApp();
