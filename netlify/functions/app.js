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
            return jwt.verify(token, process.env.JWT_SECRET);
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
            const token = jwt.sign({ username, isAdmin: user.is_admin }, process.env.JWT_SECRET, { expiresIn: '1h' });
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
