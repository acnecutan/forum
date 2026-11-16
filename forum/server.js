require('dotenv').config();
const express = require('express');
const { createClient } = require('@libsql/client');
const bcrypt = require('bcryptjs');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const { rateLimit, ipKeyGenerator } = require('express-rate-limit');
const session = require('express-session');
const { v2: cloudinary } = require('cloudinary');
const { CloudinaryStorage } = require('multer-storage-cloudinary');

const app = express();
const isProduction = process.env.NODE_ENV === 'production';
// На Render (и за любым обратным проксированием) запросы всегда идут через
// прокси-сервер, поэтому в production по умолчанию ДОВЕРЯЕМ заголовкам
// X-Forwarded-For (trust proxy = true). Без этого express.session/req.ip
// видит IP прокси Render для ВСЕХ пользователей одновременно — и любые
// лимиты "на IP" превращаются в общий лимит на весь сайт.
// Если вы НЕ на Render и нет прокси перед сервером — выставьте TRUST_PROXY=false.
// Render автоматически выставляет переменную RENDER=true для всех сервисов —
// используем это как дополнительный признак "мы за прокси", на случай если
// NODE_ENV почему-то не выставлен в production.
const isOnRender = !!process.env.RENDER;
const trustProxy = process.env.TRUST_PROXY === 'false' ? false : (process.env.TRUST_PROXY === 'true' ? true : (isProduction || isOnRender));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// На Render цепочка X-Forwarded-For состоит из нескольких хопов
// (например: "клиент, edge-прокси Render, внутренний LB Render"), поэтому
// trust proxy = 1 доверяет только последнему (внутреннему, общему для всех)
// адресу. Берём весь список (true) и используем САМЫЙ ЛЕВЫЙ адрес — это и
// есть настоящий IP клиента, который Render подставляет первым в XFF.
app.set('trust proxy', trustProxy ? true : false);
console.log(`[INFO] trust proxy = ${app.get('trust proxy')} (NODE_ENV=${process.env.NODE_ENV || 'unset'}, TRUST_PROXY=${process.env.TRUST_PROXY || 'unset'}, RENDER=${process.env.RENDER || 'unset'})`);

// ─── HEALTHCHECK ──────────────────────────────────────────────────────────────
// Лёгкий эндпоинт без обращения к БД и без утечки конфигурации.
// Используется Render (healthCheckPath), Docker HEALTHCHECK и keep-alive.
app.get('/healthz', (req, res) => res.status(200).json({ status: 'ok', uptime: Math.round(process.uptime()) }));

// ─── РАННЯЯ ЗАЩИТА ОТ ФЛУДА (до сессии/БД) ────────────────────────────────────
// КРИТИЧНО: сессии хранятся в Turso (сетевая БД). app.use(session(...)) ниже
// делает сетевой SELECT к БД на КАЖДЫЙ запрос (LibsqlStore.get), даже если
// запрос потом будет отброшен другими лимитерами. Если флуд-скрипт шлёт,
// например, ~100 запросов/сек, это превращается в ~100 лишних запросов/сек
// к общей БД — она начинает тормозить, и из-за этого "лагает" весь сайт для
// всех пользователей (БД одна на всех). Поэтому базовый лимит по IP должен
// стоять ПЕРЕД session middleware, чтобы отсекать флуд до похода в БД.
const earlyFloodLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 300, // запросов в минуту с одного IP — щедро для обычного пользователя
    standardHeaders: true, legacyHeaders: false,
    keyGenerator: (req) => ipKeyGenerator(req.ip || req.socket.remoteAddress || 'unknown'),
    message: { error: 'Слишком много запросов с этого адреса. Подождите минуту.' },
});
app.use(earlyFloodLimiter);

// ─── CLOUDINARY CONFIG ────────────────────────────────────────────────────────
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key:    process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
});

// ─── TURSO DB ─────────────────────────────────────────────────────────────────
const dbUrl   = process.env.DATABASE_URL;
const dbToken = process.env.DATABASE_AUTH_TOKEN || '';
if (!dbUrl) {
    console.error('[FATAL] DATABASE_URL не задан. Пример: libsql://my-db-org.turso.io (или file:./local.db для локальной разработки).');
    process.exit(1);
}

const db = createClient({ url: dbUrl, authToken: dbToken });
console.log('Инициализировано подключение к Turso DB (libsql).');

// ─── CUSTOM SESSION STORE ─────────────────────────────────────────────────────
// ОПТИМИЗАЦИЯ: без кэша express-session дёргает store.get() на КАЖДЫЙ HTTP
// запрос (это SELECT к Turso — сетевой round-trip). Добавляем простой
// in-memory кэш с коротким TTL: повторные запросы того же sid в течение
// CACHE_TTL_MS обслуживаются из памяти без похода в БД. При set/destroy кэш
// обновляется сразу, поэтому данные не "протухают" для текущего инстанса.
const SESSION_CACHE_TTL_MS = 10 * 1000; // 10 секунд достаточно — сессии редко меняются между запросами
const _sessionCache = new Map(); // sid -> { data, expires }

const TursoStore = function(session) {
    const Store = session.Store;
    function LibsqlStore() { Store.call(this); }
    Object.setPrototypeOf(LibsqlStore.prototype, Store.prototype);

    LibsqlStore.prototype.get = async function(sid, cb) {
        const cached = _sessionCache.get(sid);
        if (cached && cached.expires > Date.now()) {
            // Возвращаем копию, чтобы случайные мутации req.session не портили кэш
            return cb(null, cached.data ? JSON.parse(JSON.stringify(cached.data)) : null);
        }
        try {
            const res = await db.execute({ sql: "SELECT sess FROM sessions WHERE sid = ?", args: [sid] });
            if (res.rows.length === 0) {
                _sessionCache.set(sid, { data: null, expires: Date.now() + SESSION_CACHE_TTL_MS });
                return cb(null, null);
            }
            const parsed = JSON.parse(res.rows[0].sess);
            _sessionCache.set(sid, { data: parsed, expires: Date.now() + SESSION_CACHE_TTL_MS });
            return cb(null, JSON.parse(JSON.stringify(parsed)));
        } catch (err) { return cb(err); }
    };

    LibsqlStore.prototype.set = async function(sid, sess, cb) {
        try {
            const sessStr = JSON.stringify(sess);
            // Обновляем кэш сразу — следующий get() для этого sid не пойдёт в БД
            _sessionCache.set(sid, { data: JSON.parse(sessStr), expires: Date.now() + SESSION_CACHE_TTL_MS });
            await db.execute({
                sql: "INSERT INTO sessions (sid, sess) VALUES (?, ?) ON CONFLICT(sid) DO UPDATE SET sess = ?",
                args: [sid, sessStr, sessStr]
            });
            return cb(null);
        } catch (err) { return cb(err); }
    };

    LibsqlStore.prototype.destroy = async function(sid, cb) {
        try {
            _sessionCache.delete(sid);
            await db.execute({ sql: "DELETE FROM sessions WHERE sid = ?", args: [sid] });
            return cb(null);
        } catch (err) { return cb(err); }
    };
    return LibsqlStore;
};

// Периодическая очистка протухших записей кэша сессий (раз в 5 минут)
setInterval(() => {
    const now = Date.now();
    for (const [sid, entry] of _sessionCache) {
        if (entry.expires <= now) _sessionCache.delete(sid);
    }
}, 5 * 60 * 1000);

const SESSION_SECRET = process.env.SESSION_SECRET || '';
if (isProduction && SESSION_SECRET.length < 32) {
    throw new Error('SESSION_SECRET must be set to at least 32 characters in production.');
}
const effectiveSessionSecret = SESSION_SECRET || 'development-only-session-secret-change-before-deploy';
const LibsqlSessionStore = TursoStore(session);

app.use(session({
    store: new LibsqlSessionStore(),
    secret: effectiveSessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: isProduction,
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// ─── DB HELPERS ───────────────────────────────────────────────────────────────
const dbStructure = {
    serialize: (fn) => fn(),
    run: async (sql, params = [], cb) => {
        if (typeof params === 'function') { cb = params; params = []; }
        try {
            const res = await db.execute({ sql, args: params });
            const lastID = res.lastInsertRowid ? Number(res.lastInsertRowid) : null;
            if (cb) cb.call({ changes: res.rowsAffected, lastID }, null);
        } catch (err) { if (cb) cb(err); }
    },
    get: async (sql, params = [], cb) => {
        if (typeof params === 'function') { cb = params; params = []; }
        try {
            const res = await db.execute({ sql, args: params });
            if (cb) cb(null, res.rows[0] || null);
        } catch (err) { if (cb) cb(err); }
    },
    all: async (sql, params = [], cb) => {
        if (typeof params === 'function') { cb = params; params = []; }
        try {
            const res = await db.execute({ sql, args: params });
            if (cb) cb(null, res.rows);
        } catch (err) { if (cb) cb(err); }
    }
};

// ─── SECURITY HEADERS ─────────────────────────────────────────────────────────
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'same-origin');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Content-Security-Policy', [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline'",
        "style-src 'self' 'unsafe-inline'",
        // Allow Cloudinary image/media URLs
        "img-src 'self' data: https://res.cloudinary.com",
        // Allow any external/blob audio so the About-page music player (paste URL / local file) can load tracks
        "media-src 'self' https: blob: https://res.cloudinary.com",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'self'",
        "frame-ancestors 'none'",
        "form-action 'self'"
    ].join('; '));
    next();
});

// ─── CSRF PROTECTION ──────────────────────────────────────────────────────────
app.use((req, res, next) => {
    const unsafeMethods = ['POST', 'PUT', 'PATCH', 'DELETE'];
    if (!unsafeMethods.includes(req.method)) return next();
    const origin = req.get('origin');
    const referer = req.get('referer');
    const source = origin || referer;
    if (!source) return res.status(403).json({ error: 'Unsafe requests must include Origin or Referer.' });
    try {
        const originUrl = new URL(source);
        const host = req.get('host');
        if (originUrl.host === host) return next();
    } catch (e) {
        return res.status(403).json({ error: 'Некорректный Origin запроса.' });
    }
    return res.status(403).json({ error: 'Запрос заблокирован защитой от CSRF.' });
});

// ─── RATE LIMITING ────────────────────────────────────────────────────────────
const ipRateKey = (req) => ipKeyGenerator(req.ip || req.socket.remoteAddress || 'unknown');

const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, max: 1500,
    message: { error: "Слишком много запросов. Пожалуйста, подождите 15 минут." },
    standardHeaders: true, legacyHeaders: false, keyGenerator: ipRateKey,
});

const authLimiter = rateLimit({
    windowMs: 10 * 60 * 1000, max: 8,
    message: { error: "Слишком много попыток. Доступ заблокирован на 5 минут." },
    standardHeaders: true, legacyHeaders: false, skipSuccessfulRequests: true,
    keyGenerator: (req) => {
        const identifier = String(req.body?.loginInput || req.body?.username || req.body?.email || '')
            .trim().toLowerCase().slice(0, 100);
        return `${ipRateKey(req)}:${identifier}`;
    },
});
app.use('/api/login', authLimiter);
app.use('/api/register', authLimiter);
app.use('/api/', globalLimiter);

const writeLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, max: 120,
    message: { error: 'Too many actions. Please wait 15 minutes.' },
    standardHeaders: true, legacyHeaders: false,
    keyGenerator: (req) => `${ipRateKey(req)}:${req.session?.userId || 'anon'}`,
});
app.use('/api/', (req, res, next) => {
    const unsafeMethods = ['POST', 'PUT', 'PATCH', 'DELETE'];
    if (!unsafeMethods.includes(req.method)) return next();
    return writeLimiter(req, res, next);
});

// ─── CONNECTION LIMIT (защита SSE от флуда) ──────────────────────────────────
const _connectionsByIp = new Map();
const _connectionsByUser = new Map();

const MAX_SSE_PER_IP = 8;     // одновременных SSE-соединений с одного IP
const MAX_SSE_PER_USER = 3;   // одновременных SSE-соединений с одного аккаунта

function connectionLimit(req, res, next) {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    const userId = req.session?.userId || null;

    const ipCount = _connectionsByIp.get(ip) || 0;
    if (ipCount >= MAX_SSE_PER_IP) {
        return res.status(429).json({ error: 'Too many connections from your IP.' });
    }

    if (userId) {
        const userCount = _connectionsByUser.get(userId) || 0;
        if (userCount >= MAX_SSE_PER_USER) {
            return res.status(429).json({ error: 'Too many open connections for this account.' });
        }
        _connectionsByUser.set(userId, userCount + 1);
    }

    _connectionsByIp.set(ip, ipCount + 1);

    let released = false;
    const release = () => {
        if (released) return;
        released = true;
        const newIpCount = (_connectionsByIp.get(ip) || 1) - 1;
        if (newIpCount <= 0) _connectionsByIp.delete(ip);
        else _connectionsByIp.set(ip, newIpCount);

        if (userId) {
            const newUserCount = (_connectionsByUser.get(userId) || 1) - 1;
            if (newUserCount <= 0) _connectionsByUser.delete(userId);
            else _connectionsByUser.set(userId, newUserCount);
        }
    };
    res.on('close', release);
    res.on('finish', release);
    next();
}

// Отдельный лимитер на сами ПОПЫТКИ открыть SSE-соединение (защита от
// скриптов, которые открывают новые соединения батчами по 10-20 в секунду).
const streamOpenLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 20,
    message: { error: 'Слишком много попыток подключения. Подождите минуту.' },
    standardHeaders: true, legacyHeaders: false,
    keyGenerator: (req) => `stream:${ipKeyGenerator(req.ip || req.socket.remoteAddress || 'unknown')}:${req.session?.userId || 'anon'}`,
});

// ─── MULTER + CLOUDINARY STORAGE ─────────────────────────────────────────────
const SAFE_IMAGE_EXTENSIONS   = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
const SAFE_MEDIA_EXTENSIONS   = ['.mp3', '.wav', '.ogg', '.m4a', '.mp4', '.webm', '.mov'];
const SAFE_DISPLAY_EXTENSIONS = [...SAFE_IMAGE_EXTENSIONS, ...SAFE_MEDIA_EXTENSIONS];
const SAFE_MIME_PREFIXES      = ['image/', 'audio/', 'video/'];
const MAX_FILE_SIZE_MB        = 5;
const MAX_FILES_PER_POST      = 5;

function mimeToExt(mimetype) {
    const map = {
        'audio/mpeg': 'mp3', 'audio/mp3': 'mp3',
        'audio/wav': 'wav', 'audio/wave': 'wav', 'audio/x-wav': 'wav',
        'audio/ogg': 'ogg', 'audio/vorbis': 'ogg',
        'audio/mp4': 'm4a', 'audio/x-m4a': 'm4a', 'audio/aac': 'aac',
        'audio/webm': 'webm',
        'video/mp4': 'mp4', 'video/webm': 'webm', 'video/quicktime': 'mov',
        'image/jpeg': 'jpg', 'image/png': 'png', 'image/gif': 'gif', 'image/webp': 'webp',
    };
    return map[mimetype] || undefined;
}

const cloudinaryStorage = new CloudinaryStorage({
    cloudinary,
    params: async (req, file) => {
        const isProfileImage = file.fieldname === 'avatar' || file.fieldname === 'banner';
        return {
            folder: isProfileImage ? 'forum_avatars' : 'forum_posts',
            resource_type: isProfileImage ? 'image' : 'auto',
            format: mimeToExt(file.mimetype),
            public_id: `${Date.now()}-${Math.round(Math.random() * 1e9)}`,
        };
    },
});

const uploadFilter = (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const isProfileImage = file.fieldname === 'avatar' || file.fieldname === 'banner';
    const allowedExtensions = isProfileImage ? SAFE_IMAGE_EXTENSIONS : SAFE_DISPLAY_EXTENSIONS;
    const mimeAllowed = SAFE_MIME_PREFIXES.some(prefix => (file.mimetype || '').startsWith(prefix));
    if (allowedExtensions.includes(ext) && mimeAllowed) {
        cb(null, true);
    } else {
        cb(new Error('Загрузка файлов данного типа заблокирована из соображений безопасности.'), false);
    }
};

const upload = multer({
    storage: cloudinaryStorage,
    fileFilter: uploadFilter,
    limits: { fileSize: MAX_FILE_SIZE_MB * 1024 * 1024 }
});

// With Cloudinary storage there are no local files to check magic bytes on,
// so we skip the hasSafeMagicBytes check (Cloudinary validates on its end).
function flattenUploadedFiles(req) {
    if (!req.file && !req.files) return [];
    if (req.file) return [req.file];
    if (Array.isArray(req.files)) return req.files;
    return Object.values(req.files).flat();
}

// ─── HELPERS ──────────────────────────────────────────────────────────────────
function escapeHTML(str) {
    if (!str) return '';
    return str.replace(/[&<>"']/g, (match) => {
        const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#x27;' };
        return map[match];
    });
}

function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function getFormattedDate() {
    return new Date().toLocaleString('ru-RU', { hour12: false }).replace(',', '');
}

// Helper: delete old file from Cloudinary when replacing avatar/banner
async function deleteCloudinaryFile(url) {
    if (!url || !url.includes('res.cloudinary.com')) return;
    try {
        // Extract public_id from URL: .../folder/public_id.ext
        const matches = url.match(/\/upload\/(?:v\d+\/)?(.+)\.[a-z0-9]+$/i);
        if (matches && matches[1]) {
            await cloudinary.uploader.destroy(matches[1]);
        }
    } catch (e) {
        console.error('Failed to delete old Cloudinary asset:', e.message);
    }
}

// Helpers: simple key/value site settings (used for the global About-page track)
async function getSiteSetting(key) {
    const res = await db.execute({ sql: 'SELECT value FROM site_settings WHERE key = ?', args: [key] });
    return res.rows[0] ? res.rows[0].value : null;
}
async function setSiteSetting(key, value) {
    await db.execute({
        sql: `INSERT INTO site_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
        args: [key, value]
    });
}

// ─── DB INIT ──────────────────────────────────────────────────────────────────
dbStructure.serialize(() => {
    dbStructure.run(`CREATE TABLE IF NOT EXISTS sessions (sid TEXT PRIMARY KEY, sess TEXT)`);
    dbStructure.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE, email TEXT UNIQUE, password TEXT,
        isAdmin INTEGER DEFAULT 0, is_banned INTEGER DEFAULT 0,
        role_name TEXT DEFAULT 'USER', role_color TEXT DEFAULT '#909090',
        avatar_url TEXT DEFAULT '', banner_url TEXT DEFAULT '',
        bio TEXT DEFAULT '', last_seen TEXT DEFAULT CURRENT_TIMESTAMP,
        registered_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`);
    dbStructure.run(`CREATE TABLE IF NOT EXISTS banned_data (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, email TEXT UNIQUE)`);
    dbStructure.run(`CREATE TABLE IF NOT EXISTS topics (
        id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, text TEXT, author TEXT,
        isAdminPost INTEGER DEFAULT 0, isPinned INTEGER DEFAULT 0, isFeatured INTEGER DEFAULT 0,
        image_url TEXT, upvotes INTEGER DEFAULT 0, created_at TEXT, tags TEXT DEFAULT ''
    )`);
    dbStructure.run(`CREATE TABLE IF NOT EXISTS replies (
        id INTEGER PRIMARY KEY AUTOINCREMENT, topicId INTEGER, text TEXT, author TEXT,
        isAdminReply INTEGER DEFAULT 0, image_url TEXT, created_at TEXT,
        FOREIGN KEY(topicId) REFERENCES topics(id) ON DELETE CASCADE
    )`);
    dbStructure.run('CREATE TABLE IF NOT EXISTS topic_upvotes (userId INTEGER, topicId INTEGER, PRIMARY KEY(userId, topicId))');
    dbStructure.run(`CREATE TABLE IF NOT EXISTS profile_comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT, profileId INTEGER, author TEXT, text TEXT, created_at TEXT
    )`);
    dbStructure.run(`CREATE TABLE IF NOT EXISTS prefix_hierarchy (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        role_name TEXT UNIQUE NOT NULL,
        role_color TEXT DEFAULT '#909090',
        sort_order INTEGER NOT NULL DEFAULT 999
    )`);

    // ─── SITE SETTINGS (key/value, used for the global About-page track) ─────
    dbStructure.run(`CREATE TABLE IF NOT EXISTS site_settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )`);

    // ─── CHAT & PRIVATE MESSAGES TABLES ──────────────────────────────────────
    dbStructure.run(`CREATE TABLE IF NOT EXISTS chat_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        author TEXT NOT NULL,
        text TEXT NOT NULL,
        created_at TEXT NOT NULL
    )`);
    dbStructure.run(`CREATE TABLE IF NOT EXISTS private_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        from_user TEXT NOT NULL,
        to_user TEXT NOT NULL,
        text TEXT NOT NULL,
        is_read INTEGER DEFAULT 0,
        created_at TEXT NOT NULL
    )`);
    dbStructure.run(`CREATE INDEX IF NOT EXISTS idx_pm_participants ON private_messages (from_user, to_user)`);
    dbStructure.run(`CREATE INDEX IF NOT EXISTS idx_pm_to_user ON private_messages (to_user)`);
    dbStructure.run(`CREATE INDEX IF NOT EXISTS idx_chat_id ON chat_messages (id DESC)`);

    // ─── NOTIFICATIONS TABLE ──────────────────────────────────────────────────
    dbStructure.run(`CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        recipient TEXT NOT NULL,
        type TEXT NOT NULL,
        actor TEXT NOT NULL,
        topic_id INTEGER,
        topic_title TEXT,
        reply_id INTEGER,
        profile_id INTEGER,
        is_read INTEGER DEFAULT 0,
        created_at TEXT NOT NULL
    )`);
    dbStructure.run(`CREATE INDEX IF NOT EXISTS idx_notif_recipient ON notifications (recipient, id DESC)`);

    dbStructure.all("PRAGMA table_info(users);", (err, columns) => {
        if (!err && columns) {
            if (!columns.some(c => c.name === 'last_seen'))
                dbStructure.run("ALTER TABLE users ADD COLUMN last_seen TEXT DEFAULT '2026-01-01 00:00:00'");
            if (!columns.some(c => c.name === 'is_banned'))
                dbStructure.run("ALTER TABLE users ADD COLUMN is_banned INTEGER DEFAULT 0");
            if (!columns.some(c => c.name === 'registered_at'))
                dbStructure.run("ALTER TABLE users ADD COLUMN registered_at TEXT", [], () => {
                    dbStructure.run("UPDATE users SET registered_at = last_seen WHERE registered_at IS NULL");
                });
        }
    });
    dbStructure.all("PRAGMA table_info(topics);", (err, columns) => {
        if (!err && columns && !columns.some(c => c.name === 'images_json'))
            dbStructure.run("ALTER TABLE topics ADD COLUMN images_json TEXT DEFAULT '[]'");
    });
    dbStructure.all("PRAGMA table_info(replies);", (err, columns) => {
        if (!err && columns && !columns.some(c => c.name === 'images_json'))
            dbStructure.run("ALTER TABLE replies ADD COLUMN images_json TEXT DEFAULT '[]'");
    });
});

// ─── BAN CHECK MIDDLEWARE ─────────────────────────────────────────────────────
// ОПТИМИЗАЦИЯ: раньше на КАЖДЫЙ запрос залогиненного пользователя выполнялось
// 2 запроса к Turso (SELECT is_banned/isAdmin + UPDATE last_seen). Теперь
// результат SELECT кэшируется в памяти на USER_STATUS_CACHE_TTL_MS, а
// last_seen обновляется не чаще раза в LAST_SEEN_UPDATE_INTERVAL_MS на
// пользователя. Это убирает обе сетевые операции из горячего пути на
// большинстве запросов.
const USER_STATUS_CACHE_TTL_MS = 30 * 1000;       // как часто перепроверять бан/админку
const LAST_SEEN_UPDATE_INTERVAL_MS = 60 * 1000;   // как часто писать last_seen в БД
const _userStatusCache = new Map(); // userId -> { is_banned, isAdmin, expires }
const _lastSeenWriteAt = new Map(); // userId -> timestamp последней записи

app.use((req, res, next) => {
    if (req.session && req.session.userId) {
        const userId = req.session.userId;
        const now = Date.now();
        const cached = _userStatusCache.get(userId);

        const proceed = (user) => {
            if (!user || user.is_banned === 1) {
                _userStatusCache.delete(userId);
                req.session.destroy(() => {
                    res.clearCookie('connect.sid');
                    return res.status(403).json({ error: "Ваш аккаунт заблокирован администрацией." });
                });
                return;
            }
            req.session.isAdmin = user.isAdmin === 1;

            // last_seen пишем не чаще раза в минуту на пользователя
            const lastWrite = _lastSeenWriteAt.get(userId) || 0;
            if (now - lastWrite > LAST_SEEN_UPDATE_INTERVAL_MS) {
                _lastSeenWriteAt.set(userId, now);
                dbStructure.run("UPDATE users SET last_seen = datetime('now') WHERE id = ?", [userId], () => {});
            }
            next();
        };

        if (cached && cached.expires > now) {
            proceed(cached);
        } else {
            dbStructure.get("SELECT is_banned, isAdmin FROM users WHERE id = ?", [userId], (err, user) => {
                if (err || !user) return proceed(null);
                _userStatusCache.set(userId, { is_banned: user.is_banned, isAdmin: user.isAdmin, expires: now + USER_STATUS_CACHE_TTL_MS });
                proceed(user);
            });
        }
    } else {
        next();
    }
});

// Очистка устаревших записей раз в 10 минут
setInterval(() => {
    const now = Date.now();
    for (const [uid, entry] of _userStatusCache) {
        if (entry.expires <= now) _userStatusCache.delete(uid);
    }
}, 10 * 60 * 1000);

// ─── STATIC ───────────────────────────────────────────────────────────────────
// /uploads route is no longer needed — files are served from Cloudinary CDN directly.
// Kept for backward-compat with any old local URLs still in DB (returns 404 gracefully).
app.get('/uploads/:filename', (req, res) => res.status(404).json({ error: 'File not found' }));

app.use(express.static(path.join(__dirname, 'public'), {
    fallthrough: true,
    setHeaders: (res) => { res.setHeader('X-Content-Type-Options', 'nosniff'); }
}));

// ─── SIDEBAR ──────────────────────────────────────────────────────────────────
// ОПТИМИЗАЦИЯ: раньше /api/sidebar/stats делал 5 запросов к Turso ПОСЛЕДОВАТЕЛЬНО
// (каждый ждёт предыдущий — это 5 сетевых round-trip подряд). Теперь все 5
// чисел/списков собираются в ОДНОМ запросе через подзапросы (scalar subqueries
// возвращают JSON-массивы через json_group_array).
app.get('/api/sidebar/stats', (req, res) => {
    const sql = `SELECT
        (SELECT COUNT(*) FROM users WHERE is_banned = 0) as userCount,
        (SELECT COUNT(*) FROM topics) as threadCount,
        (SELECT COUNT(*) FROM replies) as replyCount,
        (SELECT json_group_array(json_object('id', id, 'username', username, 'role_color', role_color, 'role_name', role_name))
            FROM (SELECT id, username, role_color, role_name FROM users WHERE last_seen > datetime('now', '-5 minutes') AND is_banned = 0)) as onlineUsersJson,
        (SELECT json_group_array(json_object('id', id, 'username', username, 'avatar_url', avatar_url, 'role_color', role_color))
            FROM (SELECT id, username, avatar_url, role_color FROM users WHERE is_banned = 0 ORDER BY id DESC LIMIT 5)) as newestUsersJson
    `;
    dbStructure.get(sql, [], (err, row) => {
        if (err || !row) return res.status(500).json({ error: 'Ошибка БД.' });
        res.json({
            userCount: Number(row.userCount) || 0,
            threadCount: Number(row.threadCount) || 0,
            replyCount: Number(row.replyCount) || 0,
            onlineUsers: JSON.parse(row.onlineUsersJson || '[]'),
            newestUsers: JSON.parse(row.newestUsersJson || '[]'),
        });
    });
});

app.get('/api/sidebar/trending', (req, res) => {
    dbStructure.all(`SELECT t.id, t.title, (SELECT COUNT(*) FROM replies WHERE topicId = t.id) as replyCount FROM topics t ORDER BY replyCount DESC, t.id DESC LIMIT 5`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.get('/api/sidebar/activity', (req, res) => {
    dbStructure.all(`SELECT r.id, r.text, r.author, r.topicId, t.title as topicTitle, u.avatar_url, u.role_color FROM replies r JOIN topics t ON r.topicId = t.id LEFT JOIN users u ON r.author = u.username ORDER BY r.id DESC LIMIT 5`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.get('/api/sidebar/staff', (req, res) => {
    dbStructure.all("SELECT id, username, role_name, role_color, avatar_url FROM users WHERE isAdmin = 1 AND is_banned = 0 ORDER BY username ASC", [], (err, rows) => {
        res.json(rows || []);
    });
});

// ─── SIDEBAR: POPULAR TAGS ────────────────────────────────────────────────────
app.get('/api/sidebar/tags', (req, res) => {
    dbStructure.all(
        "SELECT tags FROM topics WHERE tags IS NOT NULL AND tags != '' LIMIT 200",
        [],
        (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            // Parse comma-separated tags from all threads and count them
            const counts = {};
            (rows || []).forEach(row => {
                if (!row.tags) return;
                row.tags.split(',').forEach(t => {
                    const tag = t.trim().toLowerCase();
                    if (tag) counts[tag] = (counts[tag] || 0) + 1;
                });
            });
            const sorted = Object.entries(counts)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 15)
                .map(([tag, count]) => ({ tag, count }));
            res.json(sorted);
        }
    );
});

// ─── SIDEBAR: TOP POSTERS ─────────────────────────────────────────────────────
app.get('/api/sidebar/top-users', (req, res) => {
    dbStructure.all(
        `SELECT u.id, u.username, u.avatar_url, u.role_color, u.role_name,
            (
                (SELECT COUNT(*) FROM topics WHERE author = u.username) +
                (SELECT COUNT(*) FROM replies WHERE author = u.username)
            ) as post_count
         FROM users u
         WHERE u.is_banned = 0
         ORDER BY post_count DESC
         LIMIT 5`,
        [],
        (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json((rows || []).map(r => ({ ...r, post_count: Number(r.post_count) })));
        }
    );
});

// ─── SIDEBAR: COMBINED ENDPOINT ───────────────────────────────────────────────
// ОПТИМИЗАЦИЯ: фронтенд раньше делал 6 ПОСЛЕДОВАТЕЛЬНЫХ fetch'ей для отрисовки
// сайдбара (stats, trending, activity, staff, tags, top-users), каждый из
// которых ждёт предыдущий — это 6+ сетевых round-trip подряд при каждой
// загрузке страницы и каждые 30 секунд для каждого пользователя.
// Теперь один endpoint выполняет все запросы к Turso ПАРАЛЛЕЛЬНО (Promise.all)
// и результат кэшируется на SIDEBAR_CACHE_TTL_MS — данные одинаковы для всех
// пользователей и не нужно пересчитывать их при каждом запросе.
const SIDEBAR_CACHE_TTL_MS = 15 * 1000;
let _sidebarCache = null; // { data, expires }

function getSidebarStats() {
    const sql = `SELECT
        (SELECT COUNT(*) FROM users WHERE is_banned = 0) as userCount,
        (SELECT COUNT(*) FROM topics) as threadCount,
        (SELECT COUNT(*) FROM replies) as replyCount,
        (SELECT json_group_array(json_object('id', id, 'username', username, 'role_color', role_color, 'role_name', role_name))
            FROM (SELECT id, username, role_color, role_name FROM users WHERE last_seen > datetime('now', '-5 minutes') AND is_banned = 0)) as onlineUsersJson,
        (SELECT json_group_array(json_object('id', id, 'username', username, 'avatar_url', avatar_url, 'role_color', role_color))
            FROM (SELECT id, username, avatar_url, role_color FROM users WHERE is_banned = 0 ORDER BY id DESC LIMIT 5)) as newestUsersJson
    `;
    return db.execute(sql).then(res => {
        const row = res.rows[0] || {};
        return {
            userCount: Number(row.userCount) || 0,
            threadCount: Number(row.threadCount) || 0,
            replyCount: Number(row.replyCount) || 0,
            onlineUsers: JSON.parse(row.onlineUsersJson || '[]'),
            newestUsers: JSON.parse(row.newestUsersJson || '[]'),
        };
    });
}

function getSidebarTrending() {
    return db.execute(`SELECT t.id, t.title, (SELECT COUNT(*) FROM replies WHERE topicId = t.id) as replyCount FROM topics t ORDER BY replyCount DESC, t.id DESC LIMIT 5`)
        .then(res => res.rows);
}

function getSidebarActivity() {
    return db.execute(`SELECT r.id, r.text, r.author, r.topicId, t.title as topicTitle, u.avatar_url, u.role_color FROM replies r JOIN topics t ON r.topicId = t.id LEFT JOIN users u ON r.author = u.username ORDER BY r.id DESC LIMIT 5`)
        .then(res => res.rows);
}

function getSidebarStaff() {
    return db.execute("SELECT id, username, role_name, role_color, avatar_url FROM users WHERE isAdmin = 1 AND is_banned = 0 ORDER BY username ASC")
        .then(res => res.rows);
}

function getSidebarTags() {
    return db.execute("SELECT tags FROM topics WHERE tags IS NOT NULL AND tags != '' LIMIT 200").then(res => {
        const counts = {};
        (res.rows || []).forEach(row => {
            if (!row.tags) return;
            row.tags.split(',').forEach(t => {
                const tag = t.trim().toLowerCase();
                if (tag) counts[tag] = (counts[tag] || 0) + 1;
            });
        });
        return Object.entries(counts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 15)
            .map(([tag, count]) => ({ tag, count }));
    });
}

function getSidebarTopUsers() {
    return db.execute(
        `SELECT u.id, u.username, u.avatar_url, u.role_color, u.role_name,
            (
                (SELECT COUNT(*) FROM topics WHERE author = u.username) +
                (SELECT COUNT(*) FROM replies WHERE author = u.username)
            ) as post_count
         FROM users u
         WHERE u.is_banned = 0
         ORDER BY post_count DESC
         LIMIT 5`
    ).then(res => (res.rows || []).map(r => ({ ...r, post_count: Number(r.post_count) })));
}

app.get('/api/sidebar/all', async (req, res) => {
    const now = Date.now();
    if (_sidebarCache && _sidebarCache.expires > now) {
        return res.json(_sidebarCache.data);
    }
    try {
        const [stats, trending, activity, staff, tags, topUsers] = await Promise.all([
            getSidebarStats(),
            getSidebarTrending(),
            getSidebarActivity(),
            getSidebarStaff(),
            getSidebarTags(),
            getSidebarTopUsers(),
        ]);
        const data = { stats, trending, activity, staff, tags, topUsers };
        _sidebarCache = { data, expires: now + SIDEBAR_CACHE_TTL_MS };
        res.json(data);
    } catch (err) {
        res.status(500).json({ error: 'Ошибка БД.' });
    }
});



// ─── ABOUT PAGE TEXT (GLOBAL, EDITABLE BY ADMIN ONLY) ────────────────────────
app.get('/api/about/text', async (req, res) => {
    try {
        const text = await getSiteSetting('about_page_text');
        res.json({ text: text || '' });
    } catch (e) {
        res.status(500).json({ error: 'Не удалось загрузить текст.' });
    }
});

app.post('/api/about/text', async (req, res) => {
    if (!req.session.userId || !req.session.isAdmin) return res.status(403).json({ error: 'Нет доступа.' });
    const text = (req.body.text ?? '').slice(0, 10000);
    try {
        await setSiteSetting('about_page_text', text);
        res.json({ success: true, text });
    } catch (e) {
        res.status(500).json({ error: 'Не удалось сохранить текст.' });
    }
});

// ─── ABOUT PAGE MUSIC (GLOBAL, SAME FOR EVERYONE) ─────────────────────────────
app.get('/api/about/music', async (req, res) => {
    try {
        const url  = await getSiteSetting('about_track_url');
        const name = await getSiteSetting('about_track_name');
        res.json({ url: url || '', name: name || '' });
    } catch (e) {
        res.status(500).json({ error: 'Не удалось загрузить трек.' });
    }
});

// Set the global track via a direct URL (admin only)
app.post('/api/about/music', async (req, res) => {
    if (!req.session.userId || !req.session.isAdmin) return res.status(403).json({ error: 'Нет доступа.' });

    const url  = (req.body.url  || '').trim();
    const name = (req.body.name || '').trim().slice(0, 200) || url.split('/').pop().split('?')[0] || 'track';
    if (!url || !/^https?:\/\//i.test(url)) return res.status(400).json({ error: 'Укажите корректную ссылку (http/https).' });

    try {
        const oldUrl = await getSiteSetting('about_track_url');
        if (oldUrl && oldUrl !== url) await deleteCloudinaryFile(oldUrl);
        await setSiteSetting('about_track_url', url);
        await setSiteSetting('about_track_name', name);
        res.json({ url, name });
    } catch (e) {
        res.status(500).json({ error: 'Не удалось сохранить трек.' });
    }
});

// Upload an audio file to Cloudinary and set it as the global track (admin only)
function uploadAboutTrack(req, res, next) {
    upload.single('track')(req, res, (err) => {
        if (err) return res.status(400).json({ error: err.message || 'Ошибка загрузки файла.' });
        next();
    });
}
app.post('/api/about/music/upload', uploadAboutTrack, async (req, res) => {
    if (!req.session.userId || !req.session.isAdmin) return res.status(403).json({ error: 'Нет доступа.' });
    if (!req.file) return res.status(400).json({ error: 'Файл не получен.' });

    const url  = req.file.path; // Cloudinary secure URL
    const name = (req.file.originalname || 'track').slice(0, 200);

    try {
        const oldUrl = await getSiteSetting('about_track_url');
        if (oldUrl && oldUrl !== url) await deleteCloudinaryFile(oldUrl);
        await setSiteSetting('about_track_url', url);
        await setSiteSetting('about_track_name', name);
        res.json({ url, name });
    } catch (e) {
        res.status(500).json({ error: 'Не удалось сохранить трек.' });
    }
});

// Remove the global track entirely (admin only)
app.delete('/api/about/music', async (req, res) => {
    if (!req.session.userId || !req.session.isAdmin) return res.status(403).json({ error: 'Нет доступа.' });
    try {
        const oldUrl = await getSiteSetting('about_track_url');
        if (oldUrl) await deleteCloudinaryFile(oldUrl);
        await setSiteSetting('about_track_url', '');
        await setSiteSetting('about_track_name', '');
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: 'Не удалось удалить трек.' });
    }
});

// Remove the global track entirely (admin only)
app.delete('/api/about/music', async (req, res) => {
    if (!req.session.userId || !req.session.isAdmin) return res.status(403).json({ error: 'Нет доступа.' });
    try {
        const oldUrl = await getSiteSetting('about_track_url');
        if (oldUrl) await deleteCloudinaryFile(oldUrl);
        await setSiteSetting('about_track_url', '');
        await setSiteSetting('about_track_name', '');
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: 'Не удалось удалить трек.' });
    }
});

// ─── BACKGROUND IMAGES ────────────────────────────────────────────────────────
// Multer middleware for bg image uploads (image-only, 8 MB max)
function uploadBgMiddleware(req, res, next) {
    const bgStorage = new CloudinaryStorage({
        cloudinary,
        params: async () => ({
            folder: 'forum_backgrounds',
            resource_type: 'image',
            public_id: `bg-${Date.now()}-${Math.round(Math.random() * 1e9)}`,
        }),
    });
    const bgUpload = multer({
        storage: bgStorage,
        fileFilter: (req, file, cb) => {
            const allowed = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
            const ext = path.extname(file.originalname).toLowerCase();
            cb(null, allowed.includes(ext));
        },
        limits: { fileSize: 8 * 1024 * 1024 },
    });
    bgUpload.single('bg')(req, res, (err) => {
        if (err) return res.status(400).json({ error: err.message || 'Ошибка загрузки.' });
        next();
    });
}

// GET  /api/bg/forum  — get current forum background URL
app.get('/api/bg/forum', async (req, res) => {
    try { res.json({ url: (await getSiteSetting('forum_bg_url')) || '' }); }
    catch (e) { res.json({ url: '' }); }
});
// POST /api/bg/forum/upload — upload new forum background (admin only)
app.post('/api/bg/forum/upload', uploadBgMiddleware, async (req, res) => {
    if (!req.session.userId || !req.session.isAdmin) return res.status(403).json({ error: 'Нет доступа.' });
    if (!req.file) return res.status(400).json({ error: 'Файл не получен.' });
    try {
        const oldUrl = await getSiteSetting('forum_bg_url');
        if (oldUrl) await deleteCloudinaryFile(oldUrl);
        await setSiteSetting('forum_bg_url', req.file.path);
        res.json({ url: req.file.path });
    } catch (e) { res.status(500).json({ error: 'Не удалось сохранить фон.' }); }
});
// DELETE /api/bg/forum — remove forum background (admin only)
app.delete('/api/bg/forum', async (req, res) => {
    if (!req.session.userId || !req.session.isAdmin) return res.status(403).json({ error: 'Нет доступа.' });
    try {
        const oldUrl = await getSiteSetting('forum_bg_url');
        if (oldUrl) await deleteCloudinaryFile(oldUrl);
        await setSiteSetting('forum_bg_url', '');
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: 'Не удалось удалить фон.' }); }
});

// GET  /api/bg/about  — get current about page background URL
app.get('/api/bg/about', async (req, res) => {
    try { res.json({ url: (await getSiteSetting('about_bg_url')) || '' }); }
    catch (e) { res.json({ url: '' }); }
});
// POST /api/bg/about/upload — upload new about background (admin only)
app.post('/api/bg/about/upload', uploadBgMiddleware, async (req, res) => {
    if (!req.session.userId || !req.session.isAdmin) return res.status(403).json({ error: 'Нет доступа.' });
    if (!req.file) return res.status(400).json({ error: 'Файл не получен.' });
    try {
        const oldUrl = await getSiteSetting('about_bg_url');
        if (oldUrl) await deleteCloudinaryFile(oldUrl);
        await setSiteSetting('about_bg_url', req.file.path);
        res.json({ url: req.file.path });
    } catch (e) { res.status(500).json({ error: 'Не удалось сохранить фон.' }); }
});
// DELETE /api/bg/about — remove about background (admin only)
app.delete('/api/bg/about', async (req, res) => {
    if (!req.session.userId || !req.session.isAdmin) return res.status(403).json({ error: 'Нет доступа.' });
    try {
        const oldUrl = await getSiteSetting('about_bg_url');
        if (oldUrl) await deleteCloudinaryFile(oldUrl);
        await setSiteSetting('about_bg_url', '');
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: 'Не удалось удалить фон.' }); }
});

// ─── AUTH ─────────────────────────────────────────────────────────────────────
app.get('/api/auth/me', (req, res) => {
    if (!req.session || !req.session.userId) return res.status(401).json({ authenticated: false });
    dbStructure.get('SELECT id, username, isAdmin, is_banned, role_name, role_color, avatar_url, banner_url, bio FROM users WHERE id = ?', [req.session.userId], (err, user) => {
        if (err || !user || user.is_banned === 1) return res.status(401).json({ authenticated: false });
        res.json({ authenticated: true, user });
    });
});

app.post('/api/register', async (req, res) => {
    let { username, email, password } = req.body;
    if (!username || !email || !password || !username.trim() || !password.trim())
        return res.status(400).json({ error: 'Заполните все обязательные поля корректно' });

    const usernameRegex = /^[a-zA-Z0-9_-]+$/;
    if (!usernameRegex.test(username.trim()))
        return res.status(400).json({ error: 'Никнейм может содержать только латинские буквы, цифры, дефис и нижнее подчеркивание' });
    if (!isValidEmail(email.trim()))
        return res.status(400).json({ error: 'Введен некорректный формат Email.' });
    if (username.length > 25) return res.status(400).json({ error: 'Никнейм слишком длинный (максимум 25 символов)' });
    if (email.length > 60)    return res.status(400).json({ error: 'Email слишком длинный (максимум 60 символов)' });
    if (password.length > 100) return res.status(400).json({ error: 'Пароль слишком длинный' });

    const cleanUsername = username.trim();
    const cleanEmail    = email.trim().toLowerCase();

    try {
        const bannedCheck = await db.execute({ sql: "SELECT id FROM banned_data WHERE username = ? OR email = ?", args: [cleanUsername, cleanEmail] });
        if (bannedCheck.rows.length > 0) return res.status(400).json({ error: 'Данный никнейм или email заблокированы' });

        const userCheck = await db.execute({ sql: "SELECT id FROM users WHERE username = ? OR email = ?", args: [cleanUsername, cleanEmail] });
        if (userCheck.rows.length > 0) return res.status(400).json({ error: 'Никнейм или Email уже заняты другим пользователем' });

        const hash = await bcrypt.hash(password, 10);
        const countCheck = await db.execute("SELECT COUNT(*) as count FROM users");
        const totalUsers = countCheck.rows[0].count;

        const allowFirstAdmin = process.env.ALLOW_FIRST_USER_ADMIN === 'true' && !isProduction;
        const isAdmin = (allowFirstAdmin && totalUsers === 0) ? 1 : 0;
        const role  = isAdmin ? 'ADMIN' : 'USER';
        const color = isAdmin ? '#ff3333' : '#909090';

        await db.execute({
            sql: `INSERT INTO users (username, email, password, isAdmin, role_name, role_color, last_seen, registered_at) VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))`,
            args: [cleanUsername, cleanEmail, hash, isAdmin, role, color]
        });
        return res.json({ success: true });
    } catch (err) {
        console.error("Ошибка при регистрации в Turso DB:", err);
        return res.status(500).json({ error: 'Ошибка записи базы данных при регистрации: ' + err.message });
    }
});

app.post('/api/login', (req, res) => {
    const { loginInput, password } = req.body;
    if (!loginInput || !password || !loginInput.trim())
        return res.status(400).json({ error: 'Введите логин и пароль' });

    const cleanInput = loginInput.trim();
    dbStructure.get('SELECT * FROM users WHERE username = ? OR email = ?', [cleanInput, cleanInput], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: 'Неверные учетные данные' });
        if (user.is_banned === 1) return res.status(403).json({ error: 'Ваш аккаунт заблокирован.' });

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(400).json({ error: 'Неверные учетные данные' });

        if (user.username === 'admin') {
            try {
                await db.execute("UPDATE users SET isAdmin = 1, role_name = 'ADMIN', role_color = '#ff3333' WHERE username = ?", [user.username]);
                user.isAdmin = 1; user.role_name = 'ADMIN'; user.role_color = '#ff3333';
            } catch (dbErr) { console.error("Не удалось обновить права админа в БД:", dbErr); }
        }

        req.session.userId   = user.id;
        req.session.username = user.username;
        req.session.isAdmin  = user.isAdmin === 1;

        res.json({ id: user.id, username: user.username, isAdmin: user.isAdmin === 1, role_name: user.role_name, role_color: user.role_color, avatar_url: user.avatar_url, banner_url: user.banner_url, bio: user.bio });
    });
});

app.post('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) return res.status(500).json({ error: 'Не удалось выйти из системы' });
        res.clearCookie('connect.sid');
        res.json({ success: true });
    });
});

// ─── USERS / PROFILES ────────────────────────────────────────────────────────
app.get('/api/users', (req, res) => {
    const page  = Math.max(1, parseInt(req.query.page) || 1);
    const limit = 24;
    const offset = (page - 1) * limit;
    const baseSql = 'FROM users u LEFT JOIN prefix_hierarchy ph ON LOWER(u.role_name) = LOWER(ph.role_name)';
    const orderSql = "ORDER BY CASE WHEN UPPER(u.role_name) = 'USER' OR u.role_name = '' OR u.role_name IS NULL THEN 1 ELSE 0 END ASC, COALESCE(ph.sort_order,999) ASC, u.id ASC";
    dbStructure.get(`SELECT COUNT(*) as total ${baseSql}`, [], (err, countRow) => {
        const total = countRow ? Number(countRow.total) : 0;
        dbStructure.all(`SELECT u.id, u.username, u.role_name, u.role_color, u.avatar_url, u.bio, u.is_banned, COALESCE(ph.sort_order,999) as prefix_order ${baseSql} ${orderSql} LIMIT ? OFFSET ?`, [limit, offset], (err2, rows) => {
            res.json({ users: rows || [], total, page, limit });
        });
    });
});

// ─── ADMIN: HIERARCHY ─────────────────────────────────────────────────────────
app.get('/api/admin/hierarchy', (req, res) => {
    if (!req.session || !req.session.isAdmin) return res.status(403).json({ error: 'Нет доступа.' });
    dbStructure.all('SELECT * FROM prefix_hierarchy ORDER BY sort_order ASC', [], (err, rows) => {
        res.json(rows || []);
    });
});

app.post('/api/admin/hierarchy', async (req, res) => {
    if (!req.session || !req.session.isAdmin) return res.status(403).json({ error: 'Нет доступа.' });
    const { hierarchy } = req.body;
    if (!Array.isArray(hierarchy)) return res.status(400).json({ error: 'Неверный формат данных.' });
    try {
        await db.execute('DELETE FROM prefix_hierarchy');
        for (let i = 0; i < hierarchy.length; i++) {
            const item = hierarchy[i];
            if (!item.role_name || item.role_name.trim() === '') continue;
            const name  = escapeHTML(item.role_name.trim());
            const color = /^#[0-9a-fA-F]{6}$/.test(item.role_color || '') ? item.role_color.toUpperCase() : '#909090';
            if (name.toUpperCase() === 'USER') continue;
            await db.execute({
                sql: 'INSERT OR REPLACE INTO prefix_hierarchy (role_name, role_color, sort_order) VALUES (?, ?, ?)',
                args: [name, color, i + 1]
            });
        }
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Ошибка сохранения иерархии: ' + err.message });
    }
});

app.get('/api/users/by-username/:username', (req, res) => {
    dbStructure.get('SELECT id, username, role_name, role_color, avatar_url, banner_url, bio, isAdmin, is_banned, last_seen, registered_at FROM users WHERE username = ?', [req.params.username], (err, row) => {
        if (err || !row) return res.status(404).json({ error: 'Профиль не найден' });
        res.json(row);
    });
});

app.get('/api/users/:id', (req, res) => {
    const userIdParam = parseInt(req.params.id, 10);
    if (isNaN(userIdParam)) return res.status(400).json({ error: 'Некорректный идентификатор пользователя.' });
    dbStructure.get('SELECT id, username, role_name, role_color, avatar_url, banner_url, bio, isAdmin, is_banned, last_seen, registered_at FROM users WHERE id = ?', [userIdParam], (err, row) => {
        if (err || !row) return res.status(404).json({ error: 'Профиль не найден' });
        res.json(row);
    });
});

function updateUserPrefix(req, res, userIdParam) {
    if (!req.session.userId || !req.session.isAdmin)
        return res.status(403).json({ error: 'Действие заблокировано: отказ в доступе.' });

    userIdParam = parseInt(userIdParam, 10);
    if (isNaN(userIdParam)) return res.status(400).json({ error: 'Некорректный ID пользователя.' });

    let { role_name, role_color } = req.body;
    role_name  = (role_name  || '').trim();
    role_color = (role_color || '').trim();

    if (!role_name) role_name = 'USER';
    if (role_name.length > 32) return res.status(400).json({ error: 'Префикс слишком длинный (макс 32 символа).' });
    if (!/^#[0-9a-fA-F]{6}$/.test(role_color))
        return res.status(400).json({ error: 'Цвет префикса должен быть в формате #RRGGBB.' });

    role_name  = escapeHTML(role_name);
    role_color = role_color.toUpperCase();

    dbStructure.run('UPDATE users SET role_name = ?, role_color = ? WHERE id = ?', [role_name, role_color, userIdParam], function(err) {
        if (err) return res.status(500).json({ error: 'Ошибка обновления префикса.' });
        dbStructure.get('SELECT id, username, isAdmin, is_banned, role_name, role_color, avatar_url, banner_url, bio, last_seen FROM users WHERE id = ?', [userIdParam], (selectErr, user) => {
            if (selectErr || !user) return res.status(500).json({ error: 'Префикс обновлен, но профиль не удалось перечитать.' });
            res.json({ success: true, user });
        });
    });
}

app.post('/api/admin/prefix', (req, res) => { updateUserPrefix(req, res, req.body.userId); });
app.post('/api/admin/users/:id/prefix', (req, res) => { updateUserPrefix(req, res, req.params.id); });

app.post('/api/users/:id/update',
    (req, res, next) => {
        const userIdParam = parseInt(req.params.id, 10);
        if (!req.session.userId || req.session.userId !== userIdParam)
            return res.status(403).json({ error: 'У вас нет прав на редактирование этого профиля' });
        next();
    },
    upload.fields([{ name: 'avatar', maxCount: 1 }, { name: 'banner', maxCount: 1 }]),
    async (req, res) => {
        const userIdParam = parseInt(req.params.id, 10);
        let { bio } = req.body;

        dbStructure.get('SELECT avatar_url, banner_url, bio FROM users WHERE id = ?', [userIdParam], async (err, user) => {
            if (err || !user) return res.status(404).json({ error: 'Пользователь не найден' });

            let avatarUrl = user.avatar_url || '';
            let bannerUrl = user.banner_url || '';

            // Cloudinary gives us the secure URL directly in req.files[field][0].path
            if (req.files && req.files['avatar']) {
                await deleteCloudinaryFile(avatarUrl);
                avatarUrl = req.files['avatar'][0].path; // Cloudinary secure URL
            }
            if (req.files && req.files['banner']) {
                await deleteCloudinaryFile(bannerUrl);
                bannerUrl = req.files['banner'][0].path; // Cloudinary secure URL
            }

            if (bio !== undefined) {
                if (bio.length > 500) return res.status(400).json({ error: 'Описание профиля слишком длинное (макс 500)' });
                bio = escapeHTML(bio.trim());
            } else { bio = user.bio; }

            dbStructure.run('UPDATE users SET bio = ?, avatar_url = ?, banner_url = ? WHERE id = ?', [bio, avatarUrl, bannerUrl, userIdParam], (err) => {
                if (err) return res.status(500).json({ error: 'Ошибка обновления БД' });
                dbStructure.get('SELECT id, username, isAdmin, role_name, role_color, avatar_url, banner_url, bio FROM users WHERE id = ?', [userIdParam], (err, updatedUser) => {
                    res.json(updatedUser);
                });
            });
        });
    }
);

// ─── PROFILE WALL ─────────────────────────────────────────────────────────────
app.get('/api/users/:id/comments', (req, res) => {
    const profileIdParam = parseInt(req.params.id, 10);
    if (isNaN(profileIdParam)) return res.status(400).json({ error: 'Некорректный ID.' });
    dbStructure.all(`SELECT c.*, u.id as author_id, u.avatar_url, u.role_name, u.role_color FROM profile_comments c LEFT JOIN users u ON c.author = u.username WHERE c.profileId = ? ORDER BY c.id DESC`, [profileIdParam], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});

app.post('/api/users/:id/comments', (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Необходимо войти в аккаунт' });
    const profileIdParam = parseInt(req.params.id, 10);
    if (isNaN(profileIdParam)) return res.status(400).json({ error: 'Некорректный ID профиля.' });

    let { text } = req.body;
    if (!text || !text.trim()) return res.status(400).json({ error: 'Текст комментария пуст' });

    text = escapeHTML(text.trim());
    const author    = req.session.username;
    const createdAt = getFormattedDate();

    dbStructure.get('SELECT is_banned FROM users WHERE id = ?', [profileIdParam], (err, targetUser) => {
        if (err || !targetUser) return res.status(404).json({ error: 'Профиль не найден' });
        if (targetUser.is_banned === 1) return res.status(403).json({ error: 'Профиль заблокирован.' });
        dbStructure.run(`INSERT INTO profile_comments (profileId, author, text, created_at) VALUES (?, ?, ?, ?)`, [profileIdParam, author, text, createdAt], function(err) {
            if (err) return res.status(500).json({ error: 'Ошибка сохранения комментария' });
            // Notify profile owner (unless commenting on own wall)
            dbStructure.get('SELECT username FROM users WHERE id = ?', [profileIdParam], (e2, profileOwner) => {
                if (profileOwner && profileOwner.username !== author) {
                    dbStructure.run(
                        `INSERT INTO notifications (recipient, type, actor, profile_id, created_at) VALUES (?, 'profile_comment', ?, ?, ?)`,
                        [profileOwner.username, author, profileIdParam, createdAt],
                        function() {
                            notifyUser(profileOwner.username, {
                                type: 'notification',
                                data: {
                                    id: this.lastID,
                                    type: 'profile_comment',
                                    actor: author,
                                    profile_id: profileIdParam,
                                    is_read: 0,
                                    created_at: createdAt
                                }
                            });
                        }
                    );
                }
            });
            res.json({ success: true });
        });
    });
});

app.delete('/api/profile-comments/:id', (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Необходимо войти в аккаунт' });
    const commentId = parseInt(req.params.id, 10);
    dbStructure.get('SELECT * FROM profile_comments WHERE id = ?', [commentId], (err, comment) => {
        if (err || !comment) return res.status(404).json({ error: 'Комментарий не найден' });
        if (req.session.isAdmin || req.session.username === comment.author || req.session.userId === comment.profileId) {
            dbStructure.run('DELETE FROM profile_comments WHERE id = ?', [commentId], (err) => {
                if (err) return res.status(500).json({ error: 'Ошибка БД' });
                res.json({ success: true });
            });
        } else { res.status(403).json({ error: 'Недостаточно прав' }); }
    });
});

// ─── ADMIN: BAN ───────────────────────────────────────────────────────────────
app.post('/api/admin/ban', (req, res) => {
    if (!req.session.userId || !req.session.isAdmin)
        return res.status(403).json({ error: 'Действие заблокировано: отказ в доступе.' });

    const targetUserId = parseInt(req.body.userId, 10);
    const action = req.body.action;

    if (isNaN(targetUserId)) return res.status(400).json({ error: 'Некорректный ID пользователя.' });
    if (targetUserId === req.session.userId) return res.status(400).json({ error: 'Вы не можете заблокировать самого себя.' });

    dbStructure.get('SELECT username, email, isAdmin FROM users WHERE id = ?', [targetUserId], (err, targetUser) => {
        if (err || !targetUser) return res.status(404).json({ error: 'Пользователь не найден.' });
        if (targetUser.isAdmin === 1) return res.status(403).json({ error: 'Запрещено блокировать администраторов.' });

        const banStatus = action === 'ban' ? 1 : 0;
        dbStructure.serialize(() => {
            dbStructure.run('UPDATE users SET is_banned = ? WHERE id = ?', [banStatus, targetUserId]);
            if (action === 'ban') {
                dbStructure.run('INSERT OR IGNORE INTO banned_data (username, email) VALUES (?, ?)', [targetUser.username, targetUser.email]);
            } else {
                dbStructure.run('DELETE FROM banned_data WHERE username = ? OR email = ?', [targetUser.username, targetUser.email]);
            }
            _userStatusCache.delete(targetUserId); // мгновенно применить смену статуса бана
            res.json({ success: true, message: `Статус изменен.` });
        });
    });
});

// ─── ADMIN: DELETE USER ───────────────────────────────────────────────────────
app.delete('/api/admin/users/:id/delete', async (req, res) => {
    if (!req.session.userId || !req.session.isAdmin)
        return res.status(403).json({ error: 'Действие заблокировано: отказ в доступе.' });

    const targetUserId = parseInt(req.params.id, 10);
    if (isNaN(targetUserId)) return res.status(400).json({ error: 'Некорректный ID пользователя.' });
    if (targetUserId === req.session.userId) return res.status(400).json({ error: 'Нельзя удалить собственный аккаунт.' });

    try {
        const userRes = await db.execute({ sql: 'SELECT username, email, isAdmin, avatar_url, banner_url FROM users WHERE id = ?', args: [targetUserId] });
        const user = userRes.rows[0];
        if (!user) return res.status(404).json({ error: 'Пользователь не найден.' });
        if (user.isAdmin === 1) return res.status(403).json({ error: 'Нельзя удалить администратора.' });

        // Удаляем аватар и баннер из Cloudinary
        await deleteCloudinaryFile(user.avatar_url);
        await deleteCloudinaryFile(user.banner_url);

        // Удаляем все данные пользователя
        await db.execute({ sql: 'DELETE FROM profile_comments WHERE profileId = ? OR author = ?', args: [targetUserId, user.username] });
        await db.execute({ sql: 'DELETE FROM topic_upvotes WHERE userId = ?', args: [targetUserId] });
        await db.execute({ sql: 'DELETE FROM replies WHERE author = ?', args: [user.username] });
        await db.execute({ sql: 'DELETE FROM topics WHERE author = ?', args: [user.username] });
        await db.execute({ sql: 'DELETE FROM banned_data WHERE username = ? OR email = ?', args: [user.username, user.email] });
        await db.execute({ sql: 'DELETE FROM users WHERE id = ?', args: [targetUserId] });

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Ошибка удаления: ' + err.message });
    }
});

// ─── THREADS ───────────────────────────────────────────────────────────────────
app.get('/api/threads', (req, res) => {
    const page   = Math.max(1, parseInt(req.query.page) || 1);
    const limit  = 10; // должно совпадать с THREADS_PER_PAGE на фронтенде
    const offset = (page - 1) * limit;
    const tag    = req.query.tag    ? req.query.tag.trim().toLowerCase()  : null;
    const search = req.query.search ? req.query.search.trim()             : null;
    const sort   = req.query.sort === 'popular' ? 'popular' : 'new';

    const conditions = [];
    const args = [];

    if (tag) {
        conditions.push(`(',' || LOWER(t.tags) || ',') LIKE ?`);
        args.push(`%,${tag},%`);
    }
    if (search) {
        const s = `%${search.toLowerCase()}%`;
        conditions.push(`(LOWER(t.title) LIKE ? OR LOWER(t.text) LIKE ? OR LOWER(t.author) LIKE ? OR EXISTS (SELECT 1 FROM replies r WHERE r.topicId = t.id AND (LOWER(r.text) LIKE ? OR LOWER(r.author) LIKE ?)))`);
        args.push(s, s, s, s, s);
    }

    const where   = conditions.length ? ' WHERE ' + conditions.join(' AND ') : '';
    const orderBy = sort === 'popular'
        ? 'ORDER BY t.isPinned DESC, t.upvotes DESC, t.id DESC'
        : 'ORDER BY t.isPinned DESC, t.id DESC';

    const sql = `SELECT t.*, u.avatar_url, u.role_name, u.role_color,
        (SELECT COUNT(*) FROM replies WHERE topicId = t.id) as replyCount
        FROM topics t LEFT JOIN users u ON t.author = u.username
        ${where} ${orderBy} LIMIT ? OFFSET ?`;

    dbStructure.all(sql, [...args, limit, offset], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        const countSql = `SELECT COUNT(*) as total FROM topics t${where}`;
        dbStructure.get(countSql, args, (err2, countRow) => {
            res.json({ threads: rows || [], total: countRow ? Number(countRow.total) : 0, page, limit });
        });
    });
});

app.get('/api/threads/:id', (req, res) => {
    const threadId = parseInt(req.params.id, 10);
    if (isNaN(threadId)) return res.status(400).json({ error: 'Некорректный ID треда.' });

    dbStructure.get(`SELECT t.*, u.avatar_url, u.role_name, u.role_color,
        (SELECT COUNT(*) FROM replies WHERE topicId = t.id) as replyCount
        FROM topics t LEFT JOIN users u ON t.author = u.username WHERE t.id = ?`,
        [threadId], (err, thread) => {
            if (err || !thread) return res.status(404).json({ error: 'Тред не найден.' });

            const userId = req.session.userId || null;
            const REPLIES_PER_PAGE = 20;
            const replyPage = Math.max(1, parseInt(req.query.replyPage) || 1);
            const replyOffset = (replyPage - 1) * REPLIES_PER_PAGE;
            const fetchReplies = (upvoted) => {
                thread.userUpvoted = upvoted;
                dbStructure.get(`SELECT COUNT(*) as total FROM replies WHERE topicId = ?`, [threadId], (errC, countRow) => {
                    const totalReplies = countRow ? Number(countRow.total) : 0;
                    dbStructure.all(`SELECT r.*, u2.avatar_url, u2.role_name, u2.role_color FROM replies r LEFT JOIN users u2 ON r.author = u2.username WHERE r.topicId = ? ORDER BY r.id ASC LIMIT ? OFFSET ?`, [threadId, REPLIES_PER_PAGE, replyOffset], (err2, replies) => {
                        res.json({ thread, replies: replies || [], totalReplies, replyPage, replyLimit: REPLIES_PER_PAGE });
                    });
                });
            };

            if (userId) {
                dbStructure.get('SELECT 1 FROM topic_upvotes WHERE userId = ? AND topicId = ?', [userId, threadId], (e, row) => fetchReplies(!!row));
            } else {
                fetchReplies(false);
            }
        });
});

app.post('/api/threads', upload.array('images', MAX_FILES_PER_POST), async (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Необходимо войти в аккаунт.' });

    let { title, text, tags, isPinned, isFeatured } = req.body;
    if (!title || !title.trim()) return res.status(400).json({ error: 'Заголовок треда обязателен.' });
    if (title.trim().length > 150) return res.status(400).json({ error: 'Заголовок слишком длинный (макс 150 символов).' });

    title = escapeHTML(title.trim());
    text  = escapeHTML((text || '').trim());

    let safeTags = '';
    if (tags) {
        const tagList = tags.split(',').map(t => escapeHTML(t.trim())).filter(t => t.length > 0 && t.length <= 30).slice(0, 5);
        safeTags = tagList.join(',');
    }

    // Support multiple files; keep legacy image_url as first for backward compat
    const files = req.files || [];
    const imageUrl   = files[0] ? files[0].path : '';
    const imagesJson = JSON.stringify(files.map(f => f.path));
    const createdAt = getFormattedDate();
    const isAdminPost = req.session.isAdmin ? 1 : 0;
    const pinVal      = (req.session.isAdmin && parseInt(isPinned)   === 1) ? 1 : 0;
    const featVal     = (req.session.isAdmin && parseInt(isFeatured) === 1) ? 1 : 0;

    dbStructure.run(
        `INSERT INTO topics (title, text, author, isAdminPost, isPinned, isFeatured, image_url, images_json, created_at, tags) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [title, text, req.session.username, isAdminPost, pinVal, featVal, imageUrl, imagesJson, createdAt, safeTags],
        function(err) {
            if (err) return res.status(500).json({ error: 'Ошибка сохранения треда.' });
            dbStructure.get('SELECT last_insert_rowid() as id', [], (e, row) => {
                res.json({ success: true, id: row ? row.id : null });
            });
        }
    );
});

app.delete('/api/threads/:id', (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Необходимо войти в аккаунт.' });
    const threadId = parseInt(req.params.id, 10);
    if (isNaN(threadId)) return res.status(400).json({ error: 'Некорректный ID.' });

    dbStructure.get('SELECT author, image_url, images_json FROM topics WHERE id = ?', [threadId], async (err, thread) => {
        if (err || !thread) return res.status(404).json({ error: 'Тред не найден.' });
        if (!req.session.isAdmin && req.session.username !== thread.author)
            return res.status(403).json({ error: 'Недостаточно прав.' });

        let urls = [];
        try { urls = JSON.parse(thread.images_json || '[]'); } catch(e) {}
        if (!urls.length && thread.image_url) urls = [thread.image_url];
        await Promise.all(urls.map(u => deleteCloudinaryFile(u)));

        dbStructure.run('DELETE FROM topics WHERE id = ?', [threadId], (e) => {
            if (e) return res.status(500).json({ error: 'Ошибка удаления.' });
            _sidebarCache = null; // инвалидируем кэш — счётчики изменились
            res.json({ success: true });
        });
    });
});

// ─── REPLIES ─────────────────────────────────────────────────────────────────
app.post('/api/threads/:id/replies', upload.array('images', MAX_FILES_PER_POST), (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Необходимо войти в аккаунт.' });

    const threadId = parseInt(req.params.id, 10);
    if (isNaN(threadId)) return res.status(400).json({ error: 'Некорректный ID треда.' });

    let { text } = req.body;
    const files = req.files || [];
    if ((!text || !text.trim()) && files.length === 0)
        return res.status(400).json({ error: 'Ответ не может быть пустым.' });

    text = escapeHTML((text || '').trim());
    const imageUrl   = files[0] ? files[0].path : '';
    const imagesJson = JSON.stringify(files.map(f => f.path));
    const createdAt  = getFormattedDate();
    const isAdminReply = req.session.isAdmin ? 1 : 0;

    dbStructure.get('SELECT id, title, author FROM topics WHERE id = ?', [threadId], (err, thread) => {
        if (err || !thread) return res.status(404).json({ error: 'Тред не найден.' });
        dbStructure.run(
            `INSERT INTO replies (topicId, text, author, isAdminReply, image_url, images_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [threadId, text, req.session.username, isAdminReply, imageUrl, imagesJson, createdAt],
            function(err2) {
                if (err2) return res.status(500).json({ error: 'Ошибка сохранения ответа.' });
                const replyId = this.lastID;
                // Notify thread author (unless replying to own thread)
                if (thread.author && thread.author !== req.session.username) {
                    dbStructure.run(
                        `INSERT INTO notifications (recipient, type, actor, topic_id, topic_title, reply_id, created_at) VALUES (?, 'reply', ?, ?, ?, ?, ?)`,
                        [thread.author, req.session.username, threadId, thread.title, replyId ?? null, createdAt],
                        function() {
                            notifyUser(thread.author, {
                                type: 'notification',
                                data: {
                                    id: this.lastID,
                                    type: 'reply',
                                    actor: req.session.username,
                                    topic_id: threadId,
                                    topic_title: thread.title,
                                    reply_id: replyId,
                                    is_read: 0,
                                    created_at: createdAt
                                }
                            });
                        }
                    );
                }
                res.json({ success: true, id: replyId });
            }
        );
    });
});

app.delete('/api/replies/:id', (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Необходимо войти в аккаунт.' });
    const replyId = parseInt(req.params.id, 10);
    if (isNaN(replyId)) return res.status(400).json({ error: 'Некорректный ID.' });

    dbStructure.get('SELECT author, image_url, images_json FROM replies WHERE id = ?', [replyId], async (err, reply) => {
        if (err || !reply) return res.status(404).json({ error: 'Ответ не найден.' });
        if (!req.session.isAdmin && req.session.username !== reply.author)
            return res.status(403).json({ error: 'Недостаточно прав.' });

        let urls = [];
        try { urls = JSON.parse(reply.images_json || '[]'); } catch(e) {}
        if (!urls.length && reply.image_url) urls = [reply.image_url];
        await Promise.all(urls.map(u => deleteCloudinaryFile(u)));

        dbStructure.run('DELETE FROM replies WHERE id = ?', [replyId], (e) => {
            if (e) return res.status(500).json({ error: 'Ошибка удаления.' });
            _sidebarCache = null; // инвалидируем кэш — счётчики изменились
            res.json({ success: true });
        });
    });
});

// ─── UPVOTES ─────────────────────────────────────────────────────────────────
app.post('/api/threads/:id/upvote', (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Необходимо войти в аккаунт.' });
    const threadId = parseInt(req.params.id, 10);
    if (isNaN(threadId)) return res.status(400).json({ error: 'Некорректный ID треда.' });
    const userId = req.session.userId;

    dbStructure.get('SELECT 1 FROM topic_upvotes WHERE userId = ? AND topicId = ?', [userId, threadId], (err, row) => {
        if (err) return res.status(500).json({ error: 'Ошибка БД.' });
        if (row) {
            dbStructure.run('DELETE FROM topic_upvotes WHERE userId = ? AND topicId = ?', [userId, threadId], (e) => {
                if (e) return res.status(500).json({ error: 'Ошибка БД.' });
                dbStructure.run('UPDATE topics SET upvotes = MAX(0, upvotes - 1) WHERE id = ?', [threadId], () => {
                    dbStructure.get('SELECT upvotes FROM topics WHERE id = ?', [threadId], (e3, t) => {
                        res.json({ success: true, upvoted: false, upvotes: t ? t.upvotes : 0 });
                    });
                });
            });
        } else {
            dbStructure.run('INSERT INTO topic_upvotes (userId, topicId) VALUES (?, ?)', [userId, threadId], (e) => {
                if (e) return res.status(500).json({ error: 'Ошибка БД.' });
                dbStructure.run('UPDATE topics SET upvotes = upvotes + 1 WHERE id = ?', [threadId], () => {
                    dbStructure.get('SELECT upvotes, title, author FROM topics WHERE id = ?', [threadId], (e3, t) => {
                        // Notify thread author on upvote (not self-upvote)
                        if (t && t.author && t.author !== req.session.username) {
                            const createdAt = getFormattedDate();
                            dbStructure.run(
                                `INSERT INTO notifications (recipient, type, actor, topic_id, topic_title, created_at) VALUES (?, 'upvote', ?, ?, ?, ?)`,
                                [t.author, req.session.username, threadId, t.title, createdAt],
                                function() {
                                    notifyUser(t.author, {
                                        type: 'notification',
                                        data: {
                                            id: this.lastID,
                                            type: 'upvote',
                                            actor: req.session.username,
                                            topic_id: threadId,
                                            topic_title: t.title,
                                            is_read: 0,
                                            created_at: createdAt
                                        }
                                    });
                                }
                            );
                        }
                        res.json({ success: true, upvoted: true, upvotes: t ? t.upvotes : 0 });
                    });
                });
            });
        }
    });
});

// ─── ADMIN: PIN / FEATURE ─────────────────────────────────────────────────────
app.post('/api/admin/threads/:id/pin', (req, res) => {
    if (!req.session.userId || !req.session.isAdmin)
        return res.status(403).json({ error: 'Действие заблокировано: отказ в доступе.' });
    const threadId = parseInt(req.params.id, 10);
    if (isNaN(threadId)) return res.status(400).json({ error: 'Некорректный ID.' });

    dbStructure.get('SELECT isPinned FROM topics WHERE id = ?', [threadId], (err, thread) => {
        if (err || !thread) return res.status(404).json({ error: 'Тред не найден.' });
        const newVal = thread.isPinned === 1 ? 0 : 1;
        dbStructure.run('UPDATE topics SET isPinned = ? WHERE id = ?', [newVal, threadId], (e) => {
            if (e) return res.status(500).json({ error: 'Ошибка БД.' });
            res.json({ success: true, isPinned: newVal });
        });
    });
});

app.post('/api/admin/threads/:id/feature', (req, res) => {
    if (!req.session.userId || !req.session.isAdmin)
        return res.status(403).json({ error: 'Действие заблокировано: отказ в доступе.' });
    const threadId = parseInt(req.params.id, 10);
    if (isNaN(threadId)) return res.status(400).json({ error: 'Некорректный ID.' });

    dbStructure.get('SELECT isFeatured FROM topics WHERE id = ?', [threadId], (err, thread) => {
        if (err || !thread) return res.status(404).json({ error: 'Тред не найден.' });
        const newVal = thread.isFeatured === 1 ? 0 : 1;
        dbStructure.run('UPDATE topics SET isFeatured = ? WHERE id = ?', [newVal, threadId], (e) => {
            if (e) return res.status(500).json({ error: 'Ошибка БД.' });
            res.json({ success: true, isFeatured: newVal });
        });
    });
});

// ═══════════════════════════════════════════════════════════════════════════════
// ─── CHAT & PRIVATE MESSAGES ──────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════════

// ─── SSE: GLOBAL CHAT CLIENTS ─────────────────────────────────────────────────
const chatClients = new Set();

// ─── SSE: PRIVATE MESSAGES CLIENTS ────────────────────────────────────────────
// Map<username, Set<res>>
const dmClients = new Map();

// ─── SSE: NOTIFICATION CLIENTS ────────────────────────────────────────────────
// Map<username, Set<res>>
const notifClients = new Map();

function notifyUser(toUsername, data) {
    const clients = notifClients.get(toUsername);
    if (!clients) return;
    const payload = `data: ${JSON.stringify(data)}\n\n`;
    clients.forEach(client => {
        try { client.write(payload); } catch (e) { clients.delete(client); }
    });
}

function broadcastChat(data) {
    const payload = `data: ${JSON.stringify(data)}\n\n`;
    chatClients.forEach(client => {
        try { client.write(payload); } catch (e) { chatClients.delete(client); }
    });
}

function notifyDM(toUsername, data) {
    const clients = dmClients.get(toUsername);
    if (!clients) return;
    const payload = `data: ${JSON.stringify(data)}\n\n`;
    clients.forEach(client => {
        try { client.write(payload); } catch (e) { clients.delete(client); }
    });
}

// ─── RATE LIMITERS FOR CHAT ───────────────────────────────────────────────────
const chatLimiter = rateLimit({
    windowMs: 10 * 1000, max: 5,
    message: { error: 'Слишком часто. Подождите несколько секунд.' },
    standardHeaders: true, legacyHeaders: false,
    keyGenerator: (req) => `chat:${req.session?.userId || ipRateKey(req)}`,
});

const dmLimiter = rateLimit({
    windowMs: 60 * 1000, max: 30,
    message: { error: 'Слишком много сообщений. Подождите.' },
    standardHeaders: true, legacyHeaders: false,
    keyGenerator: (req) => `dm:${req.session?.userId || ipRateKey(req)}`,
});

// ─── GLOBAL CHAT ROUTES ───────────────────────────────────────────────────────

app.get('/api/chat/stream', streamOpenLimiter, connectionLimit, (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Необходимо войти.' });

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders();

    chatClients.add(res);

    const heartbeat = setInterval(() => {
        try { res.write(': ping\n\n'); } catch (e) { /* ignore */ }
    }, 25000);

    req.on('close', () => {
        clearInterval(heartbeat);
        chatClients.delete(res);
    });
});

app.get('/api/chat/messages', (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Необходимо войти.' });
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);

    dbStructure.all(
        `SELECT cm.*, u.avatar_url, u.role_color, u.role_name
         FROM chat_messages cm
         LEFT JOIN users u ON cm.author = u.username
         ORDER BY cm.id DESC LIMIT ?`,
        [limit],
        (err, rows) => {
            if (err) return res.status(500).json({ error: 'Ошибка БД.' });
            res.json((rows || []).reverse());
        }
    );
});

app.post('/api/chat/messages', chatLimiter, (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Необходимо войти.' });

    let { text } = req.body;
    if (!text || !text.trim()) return res.status(400).json({ error: 'Сообщение пустое.' });
    if (text.length > 500) return res.status(400).json({ error: 'Сообщение слишком длинное (макс 500 символов).' });

    text = escapeHTML(text.trim());
    const author = req.session.username;
    const createdAt = getFormattedDate();

    dbStructure.run(
        `INSERT INTO chat_messages (author, text, created_at) VALUES (?, ?, ?)`,
        [author, text, createdAt],
        function(err) {
            if (err) return res.status(500).json({ error: 'Ошибка сохранения.' });

            dbStructure.get(
                `SELECT avatar_url, role_color, role_name FROM users WHERE username = ?`,
                [author],
                (e, u) => {
                    const msg = {
                        id: this.lastID,
                        author,
                        text,
                        created_at: createdAt,
                        avatar_url: u?.avatar_url || '',
                        role_color: u?.role_color || '#909090',
                        role_name: u?.role_name || 'USER',
                    };
                    broadcastChat({ type: 'message', data: msg });
                    res.json({ success: true, message: msg });
                }
            );
        }
    );
});

app.delete('/api/chat/messages/:id', (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Необходимо войти.' });
    const msgId = parseInt(req.params.id, 10);
    if (isNaN(msgId)) return res.status(400).json({ error: 'Некорректный ID.' });

    dbStructure.get('SELECT author FROM chat_messages WHERE id = ?', [msgId], (err, row) => {
        if (err || !row) return res.status(404).json({ error: 'Сообщение не найдено.' });
        if (!req.session.isAdmin && req.session.username !== row.author)
            return res.status(403).json({ error: 'Нет прав.' });

        dbStructure.run('DELETE FROM chat_messages WHERE id = ?', [msgId], (e) => {
            if (e) return res.status(500).json({ error: 'Ошибка удаления.' });
            broadcastChat({ type: 'delete', id: msgId });
            res.json({ success: true });
        });
    });
});

// ─── PRIVATE MESSAGES ROUTES ──────────────────────────────────────────────────

app.get('/api/dm/stream', streamOpenLimiter, connectionLimit, (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Необходимо войти.' });

    const username = req.session.username;
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders();

    if (!dmClients.has(username)) dmClients.set(username, new Set());
    dmClients.get(username).add(res);

    const heartbeat = setInterval(() => {
        try { res.write(': ping\n\n'); } catch (e) { /* ignore */ }
    }, 25000);

    req.on('close', () => {
        clearInterval(heartbeat);
        const clients = dmClients.get(username);
        if (clients) {
            clients.delete(res);
            if (clients.size === 0) dmClients.delete(username);
        }
    });
});

app.get('/api/dm/conversations', (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Необходимо войти.' });
    const me = req.session.username;

    dbStructure.all(
        `SELECT
            CASE WHEN from_user = ? THEN to_user ELSE from_user END AS partner,
            MAX(id) AS last_id,
            MAX(created_at) AS last_at,
            SUM(CASE WHEN to_user = ? AND is_read = 0 THEN 1 ELSE 0 END) AS unread_count
         FROM private_messages
         WHERE from_user = ? OR to_user = ?
         GROUP BY partner
         ORDER BY last_id DESC`,
        [me, me, me, me],
        (err, rows) => {
            if (err) return res.status(500).json({ error: 'Ошибка БД.' });

            const result = rows || [];
            if (!result.length) return res.json([]);

            let done = 0;
            result.forEach((row, i) => {
                dbStructure.get(
                    `SELECT id, from_user, to_user, text, created_at, is_read
                     FROM private_messages WHERE id = ?`,
                    [row.last_id],
                    (e, lastMsg) => {
                        result[i].last_message = lastMsg || null;
                        dbStructure.get(
                            `SELECT avatar_url, role_color, role_name FROM users WHERE username = ?`,
                            [row.partner],
                            (e2, u) => {
                                result[i].avatar_url = u?.avatar_url || '';
                                result[i].role_color = u?.role_color || '#909090';
                                result[i].role_name  = u?.role_name || 'USER';
                                done++;
                                if (done === result.length) res.json(result);
                            }
                        );
                    }
                );
            });
        }
    );
});

app.get('/api/dm/conversation/:username', (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Необходимо войти.' });
    const me = req.session.username;
    const partner = req.params.username;
    if (me === partner) return res.status(400).json({ error: 'Нельзя писать самому себе.' });

    const limit = Math.min(parseInt(req.query.limit) || 60, 100);
    const before = parseInt(req.query.before) || 0;
    const beforeClause = before > 0 ? 'AND id < ?' : '';
    const args = before > 0
        ? [me, partner, partner, me, before, limit]
        : [me, partner, partner, me, limit];

    dbStructure.all(
        `SELECT pm.*, u.avatar_url, u.role_color, u.role_name
         FROM private_messages pm
         LEFT JOIN users u ON pm.from_user = u.username
         WHERE ((from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?))
         ${beforeClause}
         ORDER BY id DESC LIMIT ?`,
        args,
        (err, rows) => {
            if (err) return res.status(500).json({ error: 'Ошибка БД.' });

            dbStructure.run(
                `UPDATE private_messages SET is_read = 1 WHERE to_user = ? AND from_user = ? AND is_read = 0`,
                [me, partner],
                () => {}
            );

            res.json((rows || []).reverse());
        }
    );
});

app.post('/api/dm/send', dmLimiter, (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Необходимо войти.' });

    const from = req.session.username;
    let { to, text } = req.body;
    if (!to || !text?.trim()) return res.status(400).json({ error: 'Получатель или текст отсутствуют.' });
    if (from === to) return res.status(400).json({ error: 'Нельзя писать самому себе.' });
    if (text.length > 2000) return res.status(400).json({ error: 'Сообщение слишком длинное (макс 2000).' });

    text = escapeHTML(text.trim());
    const createdAt = getFormattedDate();

    dbStructure.get('SELECT id, is_banned FROM users WHERE username = ?', [to], (err, targetUser) => {
        if (err || !targetUser) return res.status(404).json({ error: 'Пользователь не найден.' });
        if (targetUser.is_banned) return res.status(403).json({ error: 'Нельзя писать заблокированному пользователю.' });

        dbStructure.run(
            `INSERT INTO private_messages (from_user, to_user, text, created_at) VALUES (?, ?, ?, ?)`,
            [from, to, text, createdAt],
            function(e) {
                if (e) return res.status(500).json({ error: 'Ошибка сохранения.' });

                dbStructure.get(
                    `SELECT avatar_url, role_color, role_name FROM users WHERE username = ?`,
                    [from],
                    (e2, u) => {
                        const msg = {
                            id: this.lastID,
                            from_user: from,
                            to_user: to,
                            text,
                            created_at: createdAt,
                            is_read: 0,
                            avatar_url: u?.avatar_url || '',
                            role_color: u?.role_color || '#909090',
                            role_name: u?.role_name || 'USER',
                        };
                        notifyDM(to, { type: 'message', data: msg });
                        res.json({ success: true, message: msg });
                    }
                );
            }
        );
    });
});

app.get('/api/dm/unread-count', (req, res) => {
    if (!req.session.userId) return res.json({ count: 0 });
    dbStructure.get(
        `SELECT COUNT(*) as count FROM private_messages WHERE to_user = ? AND is_read = 0`,
        [req.session.username],
        (err, row) => res.json({ count: Number(row?.count) || 0 })
    );
});

app.delete('/api/dm/:id', (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Необходимо войти.' });
    const msgId = parseInt(req.params.id, 10);
    if (isNaN(msgId)) return res.status(400).json({ error: 'Некорректный ID.' });

    dbStructure.get('SELECT from_user, to_user FROM private_messages WHERE id = ?', [msgId], (err, row) => {
        if (err || !row) return res.status(404).json({ error: 'Сообщение не найдено.' });
        const isParticipant = row.from_user === req.session.username || row.to_user === req.session.username;
        if (!req.session.isAdmin && !isParticipant)
            return res.status(403).json({ error: 'Нет прав.' });

        dbStructure.run('DELETE FROM private_messages WHERE id = ?', [msgId], (e) => {
            if (e) return res.status(500).json({ error: 'Ошибка удаления.' });
            res.json({ success: true });
        });
    });
});

// ─── NOTIFICATIONS ────────────────────────────────────────────────────────────

app.get('/api/notifications/stream', streamOpenLimiter, connectionLimit, (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Необходимо войти.' });
    const username = req.session.username;
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders();

    if (!notifClients.has(username)) notifClients.set(username, new Set());
    notifClients.get(username).add(res);

    const heartbeat = setInterval(() => {
        try { res.write(': ping\n\n'); } catch (e) { /* ignore */ }
    }, 25000);

    req.on('close', () => {
        clearInterval(heartbeat);
        const clients = notifClients.get(username);
        if (clients) {
            clients.delete(res);
            if (clients.size === 0) notifClients.delete(username);
        }
    });
});

app.get('/api/notifications', (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Необходимо войти.' });
    const limit = Math.min(parseInt(req.query.limit) || 30, 50);
    dbStructure.all(
        `SELECT * FROM notifications WHERE recipient = ? ORDER BY id DESC LIMIT ?`,
        [req.session.username, limit],
        (err, rows) => {
            if (err) return res.status(500).json({ error: 'Ошибка БД.' });
            res.json(rows || []);
        }
    );
});

app.get('/api/notifications/unread-count', (req, res) => {
    if (!req.session.userId) return res.json({ count: 0 });
    dbStructure.get(
        `SELECT COUNT(*) as count FROM notifications WHERE recipient = ? AND is_read = 0`,
        [req.session.username],
        (err, row) => res.json({ count: Number(row?.count) || 0 })
    );
});

app.post('/api/notifications/read-all', (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Необходимо войти.' });
    dbStructure.run(
        `UPDATE notifications SET is_read = 1 WHERE recipient = ?`,
        [req.session.username],
        (err) => {
            if (err) return res.status(500).json({ error: 'Ошибка БД.' });
            res.json({ success: true });
        }
    );
});

app.post('/api/notifications/:id/read', (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Необходимо войти.' });
    const notifId = parseInt(req.params.id, 10);
    if (isNaN(notifId)) return res.status(400).json({ error: 'Некорректный ID.' });
    dbStructure.run(
        `UPDATE notifications SET is_read = 1 WHERE id = ? AND recipient = ?`,
        [notifId, req.session.username],
        (err) => {
            if (err) return res.status(500).json({ error: 'Ошибка БД.' });
            res.json({ success: true });
        }
    );
});


// ─── SPA CATCH-ALL ───────────────────────────────────────────────────────────
app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api/') || req.path.startsWith('/uploads/')) return next();
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
// ─── KEEP-ALIVE (Render free tier) ───────────────────────────────────────────
// Render усыпляет бесплатные сервисы после ~15 минут неактивности.
// Каждые 10 минут шлём GET на самих себя — это удерживает процесс живым.
// RENDER_EXTERNAL_URL автоматически выставляется Render'ом для всех сервисов.
// В development переменная не задана — блок просто не запускается.
const SELF_URL = process.env.RENDER_EXTERNAL_URL;
if (SELF_URL) {
    const https = require('https');
    const PING_INTERVAL_MS = 10 * 60 * 1000; // каждые 10 минут

    const selfPing = () => {
        const url = `${SELF_URL}/healthz`;
        https.get(url, (res) => {
            console.log(`[keep-alive] ping → ${res.statusCode}`);
            res.resume(); // сбрасываем тело ответа, чтобы не висел сокет
        }).on('error', (err) => {
            console.warn(`[keep-alive] ошибка пинга: ${err.message}`);
        });
    };

    // Первый пинг — через минуту после старта, дальше — каждые 10 минут
    setTimeout(() => {
        selfPing();
        setInterval(selfPing, PING_INTERVAL_MS);
    }, 60 * 1000);

    console.log(`[keep-alive] активирован → ${SELF_URL} (каждые 10 мин)`);
} else {
    console.log('[keep-alive] RENDER_EXTERNAL_URL не задан — keep-alive отключён (dev-режим)');
}

// ─── START ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => console.log(`Сервер запущен на порту ${PORT}`));

// SSE-соединения живут долго — без явного закрытия контейнер не остановится до SIGKILL.
const shutdown = (signal) => {
    console.log(`[${signal}] graceful shutdown...`);
    server.close(() => process.exit(0));
    try { chatClients.forEach(c => c.end()); } catch (e) { /* ignore */ }
    setTimeout(() => process.exit(0), 8000).unref();
};
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
