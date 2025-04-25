// Клиентская и серверная логика в одном файле
// Серверная часть работает через Netlify Functions

// Клиентская часть
const apiBase = '/.netlify/functions/api';

// Шифрование сообщений (AES)
async function encryptMessage(message, key) {
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
}

async function decryptMessage(encryptedData, key) {
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
}

// Защита от XSS
function sanitizeInput(input) {
    const div = document.createElement('div');
    div.textContent = input;
    return div.innerHTML;
}

// Авторизация
async function login(username, password) {
    const response = await fetch(`${apiBase}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    });
    const data = await response.json();
    if (data.token) {
        localStorage.setItem('token', data.token);
        localStorage.setItem('username', username);
        initApp();
    } else {
        alert(data.message);
    }
}

async function register(username, password) {
    const response = await fetch(`${apiBase}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    });
    const data = await response.json();
    alert(data.message);
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
        return;
    }

    const username = localStorage.getItem('username');
    const response = await fetch(`${apiBase}/profile`, {
        headers: { 'Authorization': `Bearer ${token}` }
    });
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
    document.getElementById('profile-status').textContent = user.isBanned ? 'Забанен' : 'Активен';
    if (user.isAdmin) {
        document.getElementById('admin-badge').classList.remove('hidden');
        document.getElementById('admin-panel').classList.remove('hidden');
    }

    loadPosts();
    loadMessages();
    loadFriends();
    loadBlacklist();
}

// Загрузка постов
async function loadPosts() {
    const token = localStorage.getItem('token');
    const response = await fetch(`${apiBase}/posts`, {
        headers: { 'Authorization': `Bearer ${token}` }
    });
    const posts = await response.json();
    const postsList = document.getElementById('posts-list');
    postsList.innerHTML = posts.map(post => `
        <div class="post ${post.author.isBanned ? 'banned' : ''}">
            <p><strong>${sanitizeInput(post.author.username)}</strong>: ${sanitizeInput(post.content)}</p>
            <p>Лайков: ${post.likes.length}</p>
            <button onclick="likePost('${post.id}')" class="bg-blue-600 text-white px-2 py-1 rounded">Лайк</button>
            ${post.author.isBanned ? '<p class="text-red-600">Автор забанен</p>' : ''}
        </div>
    `).join('');
}

// Лайк поста
async function likePost(postId) {
    const token = localStorage.getItem('token');
    await fetch(`${apiBase}/posts/${postId}/like`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
    });
    loadPosts();
}

// Создание поста
document.getElementById('post-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const content = document.getElementById('post-content').value;
    const token = localStorage.getItem('token');
    await fetch(`${apiBase}/posts`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ content })
    });
    document.getElementById('post-content').value = '';
    loadPosts();
});

// Загрузка сообщений
async function loadMessages() {
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
                ${msg.senderBanned ? '<p class="text-red-600">Отправитель забанен</p>' : ''}
            </div>
        `;
    }));
}

// Отправка сообщения
document.getElementById('send-message-btn').addEventListener('click', async () => {
    const recipient = document.getElementById('message-recipient').value;
    const content = document.getElementById('message-content').value;
    const token = localStorage.getItem('token');
    const encrypted = await encryptMessage(content, localStorage.getItem('username'));
    await fetch(`${apiBase}/messages`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipient, content: encrypted })
    });
    document.getElementById('message-content').value = '';
    loadMessages();
});

// Друзья и черный список
async function loadFriends() {
    const token = localStorage.getItem('token');
    const response = await fetch(`${apiBase}/friends`, {
        headers: { 'Authorization': `Bearer ${token}` }
    });
    const friends = await response.json();
    document.getElementById('friends-list').innerHTML = friends.map(f => `
        <div>${sanitizeInput(f.username)}</div>
    `).join('');
}

async function loadBlacklist() {
    const token = localStorage.getItem('token');
    const response = await fetch(`${apiBase}/blacklist`, {
        headers: { 'Authorization': `Bearer ${token}` }
    });
    const blacklist = await response.json();
    document.getElementById('blacklist-list').innerHTML = blacklist.map(b => `
        <div>${sanitizeInput(b.username)}</div>
    `).join('');
}

document.getElementById('add-friend-btn').addEventListener('click', async () => {
    const username = document.getElementById('friend-username').value;
    const token = localStorage.getItem('token');
    await fetch(`${apiBase}/friends`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ username })
    });
    loadFriends();
});

document.getElementById('add-blacklist-btn').addEventListener('click', async () => {
    const username = document.getElementById('blacklist-username').value;
    const token = localStorage.getItem('token');
    await fetch(`${apiBase}/blacklist`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ username })
    });
    loadBlacklist();
});

// Поиск пользователей
document.getElementById('search').addEventListener('input', async (e) => {
    const query = e.target.value;
    const token = localStorage.getItem('token');
    const response = await fetch(`${apiBase}/search?query=${encodeURIComponent(query)}`, {
        headers: { 'Authorization': `Bearer ${token}` }
    });
    const users = await response.json();
    document.getElementById('search-results').innerHTML = users.map(u => `
        <div>${sanitizeInput(u.username)}</div>
    `).join('');
});

// Админ-функции
document.getElementById('ban-btn').addEventListener('click', async () => {
    const username = document.getElementById('ban-username').value;
    const token = localStorage.getItem('token');
    await fetch(`${apiBase}/ban`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ username })
    });
    alert('Пользователь забанен');
});

document.getElementById('unban-btn').addEventListener('click', async () => {
    const username = document.getElementById('ban-username').value;
    const token = localStorage.getItem('token');
    await fetch(`${apiBase}/unban`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ username })
    });
    alert('Пользователь разбанен');
});

document.getElementById('delete-post-btn').addEventListener('click', async () => {
    const postId = document.getElementById('delete-post-id').value;
    const token = localStorage.getItem('token');
    await fetch(`${apiBase}/posts/${postId}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
    });
    loadPosts();
});

// Обработчики UI
document.getElementById('login-btn').addEventListener('click', () => {
    document.getElementById('auth-form').classList.remove('hidden');
    document.getElementById('auth-title').textContent = 'Вход';
    document.getElementById('auth-form-element').onsubmit = async (e) => {
        e.preventDefault();
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        await login(username, password);
    };
});

document.getElementById('register-btn').addEventListener('click', () => {
    document.getElementById('auth-form').classList.remove('hidden');
    document.getElementById('auth-title').textContent = 'Регистрация';
    document.getElementById('auth-form-element').onsubmit = async (e) => {
        e.preventDefault();
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        await register(username, password);
    };
});

document.getElementById('logout-btn').addEventListener('click', () => {
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    initApp();
});

document.getElementById('edit-profile-btn').addEventListener('click', () => {
    document.getElementById('edit-profile').classList.remove('hidden');
});

document.getElementById('edit-profile-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('edit-username').value;
    const password = document.getElementById('edit-password').value;
    const token = localStorage.getItem('token');
    await fetch(`${apiBase}/profile`, {
        method: 'PUT',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    });
    document.getElementById('edit-profile').classList.add('hidden');
    initApp();
});

document.getElementById('settings-btn').addEventListener('click', () => {
    document.getElementById('settings').classList.remove('hidden');
});

document.getElementById('settings-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const hidden = document.getElementById('profile-hidden').checked;
    const friendsOnly = document.getElementById('messages-friends-only').checked;
    const token = localStorage.getItem('token');
    await fetch(`${apiBase}/settings`, {
        method: 'PUT',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ hidden, friendsOnly })
    });
    document.getElementById('settings').classList.add('hidden');
});

// Инициализация
initApp();

// Серверная часть (Netlify Functions)
const { Client } = require('@neondatabase/serverless');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

exports.handler = async (event, context) => {
    const client = new Client(process.env.NEON_DATABASE_URL);
    await client.connect();

    const path = event.path.replace('/.netlify/functions/api', '');
    const method = event.httpMethod;
    const headers = event.headers;
    const body = event.body ? JSON.parse(event.body) : {};

    // Проверка токена
    async function verifyToken(token) {
        try {
            return jwt.verify(token, 'secret'); // Замените 'secret' на безопасный ключ в .env
        } catch {
            return null;
        }
    }

    // Регистрация
    if (path === '/register' && method === 'POST') {
        const { username, password } = body;
        const hashedPassword = await bcrypt.hash(password, 10);
        try {
            await client.query(
                'INSERT INTO users (username, password, is_admin) VALUES ($1, $2, $3)',
                [username, hashedPassword, username === 'GregroyBale' ? true : false]
            );
            return {
                statusCode: 200,
                body: JSON.stringify({ message: 'Регистрация успешна' })
            };
        } catch (e) {
            return {
                statusCode: 400,
                body: JSON.stringify({ message: 'Пользователь уже существует' })
            };
        }
    }

    // Вход
    if (path === '/login' && method === 'POST') {
        const { username, password } = body;
        const result = await client.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];
        if (user && await bcrypt.compare(password, user.password)) {
            const token = jwt.sign({ username, isAdmin: user.is_admin }, 'secret', { expiresIn: '1h' });
            return {
                statusCode: 200,
                body: JSON.stringify({ token })
            };
        }
        return {
            statusCode: 401,
            body: JSON.stringify({ message: 'Неверный логин или пароль' })
        };
    }

    // Проверка токена для защищённых маршрутов
    const token = headers.authorization?.replace('Bearer ', '');
    const decoded = await verifyToken(token);
    if (!decoded && path !== '/register' && path !== '/login') {
        return {
            statusCode: 401,
            body: JSON.stringify({ message: 'Неавторизован' })
        };
    }

    // Профиль
    if (path === '/profile' && method === 'GET') {
        const result = await client.query('SELECT * FROM users WHERE username = $1', [decoded.username]);
        return {
            statusCode: 200,
            body: JSON.stringify(result.rows[0])
        };
    }

    if (path === '/profile' && method === 'PUT') {
        const { username, password } = body;
        const updates = [];
        const values = [];
        let index = 1;
        if (username) {
            updates.push(`username = $${index++}`);
            values.push(username);
        }
        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            updates.push(`password = $${index++}`);
            values.push(hashedPassword);
        }
        values.push(decoded.username);
        await client.query(`UPDATE users SET ${updates.join(', ')} WHERE username = $${index}`, values);
        return {
            statusCode: 200,
            body: JSON.stringify({ message: 'Профиль обновлён' })
        };
    }

    // Настройки
    if (path === '/settings' && method === 'PUT') {
        const { hidden, friendsOnly } = body;
        await client.query(
            'UPDATE users SET hidden = $1, messages_friends_only = $2 WHERE username = $3',
            [hidden, friendsOnly, decoded.username]
        );
        return {
            statusCode: 200,
            body: JSON.stringify({ message: 'Настройки обновлены' })
        };
    }

    // Посты
    if (path === '/posts' && method === 'GET') {
        const result = await client.query(`
            SELECT p.*, u.username, u.is_banned
            FROM posts p
            JOIN users u ON p.user_id = u.id
            ORDER BY p.created_at DESC
        `);
        return {
            statusCode: 200,
            body: JSON.stringify(result.rows)
        };
    }

    if (path === '/posts' && method === 'POST') {
        const { content } = body;
        const userResult = await client.query('SELECT id FROM users WHERE username = $1', [decoded.username]);
        const userId = userResult.rows[0].id;
        const result = await client.query(
            'INSERT INTO posts (user_id, content) VALUES ($1, $2) RETURNING *',
            [userId, content]
        );
        return {
            statusCode: 200,
            body: JSON.stringify(result.rows[0])
        };
    }

    if (path.startsWith('/posts/') && method === 'POST' && path.endsWith('/like')) {
        const postId = path.split('/')[2];
        const userResult = await client.query('SELECT id FROM users WHERE username = $1', [decoded.username]);
        const userId = userResult.rows[0].id;
        await client.query(
            'INSERT INTO likes (user_id, post_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
            [userId, postId]
        );
        return {
            statusCode: 200,
            body: JSON.stringify({ message: 'Лайк добавлен' })
        };
    }

    if (path.startsWith('/posts/') && method === 'DELETE') {
        const postId = path.split('/')[2];
        if (!decoded.isAdmin) {
            return {
                statusCode: 403,
                body: JSON.stringify({ message: 'Только админ может удалять посты' })
            };
        }
        await client.query('DELETE FROM posts WHERE id = $1', [postId]);
        return {
            statusCode: 200,
            body: JSON.stringify({ message: 'Пост удалён' })
        };
    }

    // Сообщения
    if (path === '/messages' && method === 'GET') {
        const userResult = await client.query('SELECT id FROM users WHERE username = $1', [decoded.username]);
        const userId = userResult.rows[0].id;
        const result = await client.query(`
            SELECT m.*, u1.username AS sender, u2.username AS recipient, u1.is_banned AS sender_banned
            FROM messages m
            JOIN users u1 ON m.sender_id = u1.id
            JOIN users u2 ON m.recipient_id = u2.id
            WHERE m.sender_id = $1 OR m.recipient_id = $1
            ORDER BY m.created_at DESC
        `, [userId]);
        return {
            statusCode: 200,
            body: JSON.stringify(result.rows)
        };
    }

    if (path === '/messages' && method === 'POST') {
        const { recipient, content } = body;
        const senderResult = await client.query('SELECT id FROM users WHERE username = $1', [decoded.username]);
        const recipientResult = await client.query('SELECT id, messages_friends_only FROM users WHERE username = $1', [recipient]);
        if (!recipientResult.rows[0]) {
            return {
                statusCode: 404,
                body: JSON.stringify({ message: 'Получатель не найден' })
            };
        }
        const senderId = senderResult.rows[0].id;
        const recipientId = recipientResult.rows[0].id;
        if (recipientResult.rows[0].messages_friends_only) {
            const friendCheck = await client.query(
                'SELECT 1 FROM friends WHERE user_id = $1 AND friend_id = $2',
                [recipientId, senderId]
            );
            if (!friendCheck.rows[0]) {
                return {
                    statusCode: 403,
                    body: JSON.stringify({ message: 'Можно отправлять сообщения только друзьям' })
                };
            }
        }
        await client.query(
            'INSERT INTO messages (sender_id, recipient_id, content) VALUES ($1, $2, $3)',
            [senderId, recipientId, content]
        );
        return {
            statusCode: 200,
            body: JSON.stringify({ message: 'Сообщение отправлено' })
        };
    }

    // Друзья
    if (path === '/friends' && method === 'GET') {
        const userResult = await client.query('SELECT id FROM users WHERE username = $1', [decoded.username]);
        const userId = userResult.rows[0].id;
        const result = await client.query(`
            SELECT u.username
            FROM friends f
            JOIN users u ON f.friend_id = u.id
            WHERE f.user_id = $1
        `, [userId]);
        return {
            statusCode: 200,
            body: JSON.stringify(result.rows)
        };
    }

    if (path === '/friends' && method === 'POST') {
        const { username } = body;
        const userResult = await client.query('SELECT id FROM users WHERE username = $1', [decoded.username]);
        const friendResult = await client.query('SELECT id FROM users WHERE username = $1', [username]);
        if (!friendResult.rows[0]) {
            return {
                statusCode: 404,
                body: JSON.stringify({ message: 'Пользователь не найден' })
            };
        }
        await client.query(
            'INSERT INTO friends (user_id, friend_id) VALUES ($1, $2)',
            [userResult.rows[0].id, friendResult.rows[0].id]
        );
        return {
            statusCode: 200,
            body: JSON.stringify({ message: 'Друг добавлен' })
        };
    }

    // Черный список
    if (path === '/blacklist' && method === 'GET') {
        const userResult = await client.query('SELECT id FROM users WHERE username = $1', [decoded.username]);
        const userId = userResult.rows[0].id;
        const result = await client.query(`
            SELECT u.username
            FROM blacklist b
            JOIN users u ON b.blocked_id = u.id
            WHERE b.user_id = $1
        `, [userId]);
        return {
            statusCode: 200,
            body: JSON.stringify(result.rows)
        };
    }

    if (path === '/blacklist' && method === 'POST') {
        const { username } = body;
        const userResult = await client.query('SELECT id FROM users WHERE username = $1', [decoded.username]);
        const blockedResult = await client.query('SELECT id FROM users WHERE username = $1', [username]);
        if (!blockedResult.rows[0]) {
            return {
                statusCode: 404,
                body: JSON.stringify({ message: 'Пользователь не найден' })
            };
        }
        await client.query(
            'INSERT INTO blacklist (user_id, blocked_id) VALUES ($1, $2)',
            [userResult.rows[0].id, blockedResult.rows[0].id]
        );
        return {
            statusCode: 200,
            body: JSON.stringify({ message: 'Добавлен в черный список' })
        };
    }

    // Поиск
    if (path.startsWith('/search') && method === 'GET') {
        const query = event.queryStringParameters.query || '';
        const result = await client.query(
            'SELECT username FROM users WHERE username ILIKE $1 AND hidden = false',
            [`%${query}%`]
        );
        return {
            statusCode: 200,
            body: JSON.stringify(result.rows)
        };
    }

    // Админ-функции
    if (path === '/ban' && method === 'POST') {
        if (!decoded.isAdmin) {
            return {
                statusCode: 403,
                body: JSON.stringify({ message: 'Только админ может банить' })
            };
        }
        const { username } = body;
        await client.query('UPDATE users SET is_banned = true WHERE username = $1', [username]);
        return {
            statusCode: 200,
            body: JSON.stringify({ message: 'Пользователь забанен' })
        };
    }

    if (path === '/unban' && method === 'POST') {
        if (!decoded.isAdmin) {
            return {
                statusCode: 403,
                body: JSON.stringify({ message: 'Только админ может разбанить' })
            };
        }
        const { username } = body;
        await client.query('UPDATE users SET is_banned = false WHERE username = $1', [username]);
        return {
            statusCode: 200,
            body: JSON.stringify({ message: 'Пользователь разбанен' })
        };
    }

    await client.end();
    return {
        statusCode: 404,
        body: JSON.stringify({ message: 'Маршрут не найден' })
    };
};
