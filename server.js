import express from 'express';
import cors from 'cors';
import pkg from 'pg';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import fs from 'fs';
import mqtt from 'mqtt';
import layoutRouter from './layoutApi.js';
import ldap from 'ldapjs';

process.env.TZ = 'Asia/Ho_Chi_Minh';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const { Pool } = pkg;

// ===========================================================================
// 1. LOGGER
// ===========================================================================
const ts = () => new Date().toLocaleString();
const logger = {
    info: (msg, data = '') => console.log(`[${ts()}] ??  INFO: ${msg}`, data),
    success: (msg, data = '') => console.log(`[${ts()}] ? SUCCESS: ${msg}`, data),
    warn: (msg, data = '') => console.warn(`[${ts()}] ??  WARN: ${msg}`, data),
    error: (msg, err = '') => console.error(`[${ts()}] ? ERROR: ${msg}`, err)
};

// ===========================================================================
// 2. CONFIG
// ===========================================================================
let config;
try {
    config = JSON.parse(fs.readFileSync(path.join(__dirname, 'config.json'), 'utf8'));
    logger.success('Loaded config.json');
} catch (err) {
    logger.error('Could not read config.json', err.message);
    process.exit(1);
}

const Q = config.queries || {};
const TOPIC = config.mqtt?.baseTopic || 'wvn/security';      // ph?i kh?p v?i index.html
const MQTT_URL = process.env.MQTT_URL || config.mqtt?.url || 'mqtt://localhost:1883';
const SYNC_INTERVAL_MS = 30 * 1000;

// Các th? trên dashboard l?y tr?c ti?p t? config.queries.dashboard (thêm th? m?i ch? c?n s?a config).
// M?i th? có th? có nhi?u câu SQL, m?i câu tr? v? c?t "count":
//   camera: abnormal (offline, status='0'), normal (status='1'), covered (b? che, status='2')
const DASHBOARD_KEYS = Object.keys(Q.dashboard || {});

// Câu UPDATE ghi chú camera, có th? ghi dè trong config.queries.update
const UPDATE_SQL = {
    update_camera_abnormal: Q.update?.camera_abnormal ||
        'UPDATE itsec_camera_offline_test SET excludecamera = $1, excludeupdatedate = $2 WHERE nvr_ip = $3 AND nvr_cameraid = $4',
    update_exception: Q.update?.exception || null
};

// Ki?m tra config lúc kh?i d?ng d? phát hi?n thi?u SQL s?m
(function validateConfig() {
    if (!config.db) logger.warn('config.db is missing');
    if (!DASHBOARD_KEYS.length) logger.warn('config.queries.dashboard is empty');

    const cam = Q.dashboard?.camera || {};
    ['abnormal', 'normal', 'covered'].forEach(k => {
        if (!cam[k]) logger.warn(`dashboard.camera.${k} is missing (s? trên nút/vòng tròn camera s? không có)`);
    });
    ['camera', 'camera_offline', 'camera_covered'].forEach(k => {
        if (!Q.detail?.[k]) logger.warn(`detail.${k} is missing (nút l?c camera s? tr? b?ng tr?ng)`);
    });
    if (!config.auth?.users?.length) logger.warn('config.auth.users is empty -> dang nh?p s?a ghi chú s? b? t? ch?i');
})();

// ===========================================================================
// 3. DATABASE
// ===========================================================================
const pool = new Pool({
    ...config.db,
    options: '-c timezone=Asia/Ho_Chi_Minh'
});
pool.on('error', err => logger.error('Unexpected PG pool error', err.message));
function authenticateLDAP(username, password) {
    return new Promise((resolve) => {

        const client = ldap.createClient({
            url: 'ldap://10.69.22.12'
        });

        const userPrincipalName = `WIH\\${username}`;

        client.bind(userPrincipalName, password, (err) => {

            if (err) {
                console.error('LDAP Login Failed:', err.message);
                client.destroy();
                return resolve(false);
            }

            client.unbind();
            resolve(true);
        });
    });
}
// ===========================================================================
// 4. HTTP (static + API)
// ===========================================================================
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api/layout', layoutRouter(pool, logger, Q.getTimes?.camera));
app.get('/health', (req, res) => res.json({ ok: true, mqtt: mqttClient.connected, time: nowString() }));

// --- Ðang nh?p (dùng cho nút ?? s?a ghi chú) ---
// config.auth.users = [ { "username": "...", "password": "sha256:<hex>" } ]   (password ch? thu?ng cung du?c)
function safeEqual(a, b) {
    const ha = crypto.createHash('sha256').update(String(a)).digest();
    const hb = crypto.createHash('sha256').update(String(b)).digest();
    return crypto.timingSafeEqual(ha, hb);
}
function passwordMatches(stored, input) {
    if (typeof stored !== 'string') return false;
    if (stored.startsWith('sha256:')) {
        const hash = crypto.createHash('sha256').update(String(input)).digest('hex');
        return safeEqual(stored.slice(7).toLowerCase(), hash);
    }
    return safeEqual(stored, input);
}

const loginFails = new Map();   // ip -> { count, until }
// app.post('/api/login', (req, res) => {
//     const ip = req.ip;
//     const rec = loginFails.get(ip);
//     if (rec && rec.until > Date.now()) {
//         return res.status(429).json({ success: false, message: 'Too many attempts, try again later' });
//     }

//     const users = config.auth?.users || [];
//     if (!users.length) {
//         return res.status(503).json({ success: false, message: 'Login is not configured on server' });
//     }

//     const { username, password } = req.body || {};
//     const user = users.find(u => safeEqual(u.username, username ?? ''));
//     if (user && passwordMatches(user.password, password ?? '')) {
//         loginFails.delete(ip);
//         logger.info(`Login OK: ${username}`);
//         return res.json({ success: true });
//     }

//     const count = (rec?.count || 0) + 1;
//     loginFails.set(ip, { count, until: count >= 5 ? Date.now() + 60 * 1000 : 0 });
//     logger.warn(`Login failed: ${username}`);
//     return res.status(401).json({ success: false });
// });

// ===========================================================================
// 5. Ð?Y D? LI?U Ð?NH K? LÊN MQTT
// ===========================================================================
const pad = n => String(n).padStart(2, '0');
function nowString() {
    const d = new Date();
    return `${d.getFullYear()}/${pad(d.getMonth() + 1)}/${pad(d.getDate())} ` +
        `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

// Gói g?i di: { camera: { abnormal, normal, covered }, nvr: { abnormal, normal }, ..., updateTime }
let syncingDashboard = false;
async function syncDashboardData() {
    if (syncingDashboard) return;        // tránh ch?y ch?ng n?u DB ch?m
    syncingDashboard = true;
    try {
        const dashboardData = {};

        for (const key of DASHBOARD_KEYS) {
            const queries = Q.dashboard[key];
            try {
                const fields = Object.keys(queries);
                const results = await Promise.all(fields.map(f => pool.query(queries[f])));

                dashboardData[key] = {};
                fields.forEach((f, i) => {
                    dashboardData[key][f] = parseInt(results[i].rows[0]?.count || 0, 10);
                });
            } catch (err) {
                logger.error(`Dashboard query failed for [${key}]`, err.message);
            }
        }

        dashboardData.updateTime = nowString();
        mqttClient.publish(`${TOPIC}/dashboard`, JSON.stringify(dashboardData), { retain: true });
    } finally {
        syncingDashboard = false;
    }
}

async function syncContacts() {
    if (!Q.it_contact) return;
    try {
        const r = await pool.query(Q.it_contact);
        mqttClient.publish(`${TOPIC}/contacts`, JSON.stringify(r.rows), { retain: true });
    } catch (err) {
        logger.error('Contact query failed', err.message);
    }
}

// config.queries.getTimes = { camera: "select ... as updatedate ...", ... }
// G?i { camera: "2026-11-16 09:00:00", ... } d? index.html gán vào <key>-time-value
async function syncGettime() {
    const out = {};
    for (const [key, sql] of Object.entries(Q.getTimes || {})) {
        try {
            const r = await pool.query(sql);
            out[key] = r.rows[0]?.updatedate || 'N/A';
        } catch (err) {
            logger.error(`Get time query failed for [${key}]`, err.message);
        }
    }
    if (Object.keys(out).length) {
        mqttClient.publish(`${TOPIC}/gettimes`, JSON.stringify(out), { retain: true });
    }
}

const syncAll = () => Promise.allSettled([syncDashboardData(), syncContacts(), syncGettime()]);

// ===========================================================================
// 6. MQTT REQUEST / RESPONSE
// ===========================================================================
const mqttClient = mqtt.connect(MQTT_URL);
const REQUEST_ACTIONS = ['detail', 'subdetail', 'all_detail', 'gettime', 'update_camera_abnormal', 'update_exception'];

mqttClient.on('connect', () => {
    logger.success(`Backend connected to MQTT Broker (${MQTT_URL}) | base topic: ${TOPIC}`);
    REQUEST_ACTIONS.forEach(a => mqttClient.subscribe(`${TOPIC}/request/${a}`));
    syncAll();
});
mqttClient.on('error', err => logger.error('MQTT error', err.message));
mqttClient.on('reconnect', () => logger.warn('MQTT reconnecting...'));

setInterval(syncAll, SYNC_INTERVAL_MS);

// SQL ch? l?y t? config theo `type` (whitelist) -> client không th? chèn SQL
function resolveReadQuery(action, type, id) {
    switch (action) {
        case 'detail':     // c?p 1: danh sách l?i. camera / camera_offline / camera_covered ... d?u tra ? dây
            return { sql: Q.detail?.[type], params: [] };
        case 'subdetail':  // c?p 2: chi ti?t t?ng ngu?i / thi?t b?
            return { sql: Q.sub_detail?.[type], params: [id] };
        case 'all_detail': // nút View All
            return { sql: Q.allQueries?.[type], params: [] };
        default:
            return { sql: null, params: [] };
    }
}

async function handleUpdate(action, p) {
    const sql = UPDATE_SQL[action];
    if (!sql) return { success: false, error: `${action} is not configured` };
    const now = new Date();
    const { nvr_ip, nvr_cameraid, ipaddress, remark } = p;
    if (!nvr_ip || nvr_cameraid === undefined || nvr_cameraid === null || !ipaddress) {
        return { success: false, error: 'Missing nvr_ip / nvr_cameraid / ipaddress' };
    }
    console.log('remark=', remark);
    console.log('nvr_ip=', nvr_ip);
    console.log('nvr_cameraid=', nvr_cameraid);
    console.log('type=', typeof nvr_cameraid);
    const r = await pool.query(sql, [
    remark ?? null,
    now,
    nvr_ip,
    String(nvr_cameraid)
]);

console.log(
    'rowCount=',
    r.rowCount
);

const check = await pool.query(
`
select *
from itsec_camera_offline_test
where nvr_ip=$1
and nvr_cameraid=$2
`,
[
    nvr_ip,
    String(nvr_cameraid)
]
);

console.log(check.rows);
    return { success: true, rowCount: r.rowCount };
}

mqttClient.on('message', async (topic, message) => {
    const prefix = `${TOPIC}/request/`;
    if (!topic.startsWith(prefix)) return;
    const action = topic.slice(prefix.length);

    // Client yêu c?u làm m?i th?i gian c?p nh?t (không có requestId)
    if (action === 'gettime') {
        await syncGettime();
        return;
    }

    let payload;
    try {
        payload = JSON.parse(message.toString());
    } catch {
        return;
    }

    const { type, id, requestId } = payload;
    if (!requestId) return;
    const responseTopic = `${TOPIC}/response/${requestId}`;

    try {
        // --- Ghi chú camera ---
        if (action === 'update_camera_abnormal' || action === 'update_exception') {
            const result = await handleUpdate(action, payload);
            mqttClient.publish(responseTopic, JSON.stringify({ requestId, ...result }));
            logger.info(`${action} ${payload.nvr_ip}/${payload.nvr_cameraid} -> ${result.success ? 'OK' : result.error}`);
            return;
        }

        // --- Ð?c d? li?u chi ti?t ---
        const { sql, params } = resolveReadQuery(action, type, id);
        logger.info(`REQUEST => action=${action}, type=${type}`);

        if (!sql) {
            logger.warn(`No query configured for ${action} [${type}]`);
            mqttClient.publish(responseTopic, JSON.stringify({
                requestId, rows: [], success: false, error: `Missing SQL config for ${type}`
            }));
            return;
        }

        let rows = [];
        try {
            const res = await pool.query(sql, params);          // ch? ch?y 1 l?n
            rows = res.rows.map(o => Object.values(o));         // Object -> Array cho renderTable
            logger.info(`[${type}] returned ${rows.length} rows`);
            if (res.rows.length > 0) logger.info(`[${type}] sample row`, JSON.stringify(res.rows[0]));
        } catch (sqlErr) {
            logger.error(`SQL execution error [${type}]`, sqlErr.message);
            mqttClient.publish(responseTopic, JSON.stringify({
                requestId, rows: [], success: false, error: sqlErr.message
            }));
            return;
        }

        mqttClient.publish(responseTopic, JSON.stringify({ requestId, rows }));
        logger.info(`Replied ${action} [${type}] - Rows: ${rows.length}`);
    } catch (err) {
        logger.error(`Error handling ${action} [${type}]`, err.message);
        // Luôn tr? l?i d? giao di?n không b? treo
        mqttClient.publish(responseTopic, JSON.stringify({ requestId, rows: [], success: false, error: err.message }));
    }
});
// =================================================
// LDAP LOGIN API
// =================================================

app.post('/api/login', async (req, res) => {
    try {

        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Missing username or password'
            });
        }

        // Bu?c 1: Ki?m tra AD
        const isAuthenticated = await authenticateLDAP(
            username,
            password
        );

        if (!isAuthenticated) {
            return res.status(401).json({
                success: false,
                message: 'Sai tài kho?n ho?c m?t kh?u Domain'
            });
        }

        // Bu?c 2: Ki?m tra user trong DB
        const userResult = await pool.query(
            `
            SELECT *
            FROM itsec_itcontactlist
            WHERE LOWER(empid) = LOWER($1)
            AND emptype in ('admin','user_admin')
            `,
            [username]
        );
        console.log(userResult.rows[0]);
        if (userResult.rows.length === 0) {
            return res.status(403).json({
                success: false,
                message: 'Tài kho?n chua du?c c?p quy?n s? d?ng h? th?ng'
            });
        }

        const user = userResult.rows[0];

        // Bu?c 3: So sánh username
        if (
            user.empid.trim().toLowerCase() !==
            username.trim().toLowerCase()
        ) {
            return res.status(403).json({
                success: false,
                message: 'Thông tin tài kho?n không kh?p'
            });
        }

        return res.json({
            success: true,
            message: 'Ðang nh?p thành công',
            user: {
                username: user.username,
                fullname: user.fullname,
                department: user.department,
                role: user.role
            }
        });

    } catch (err) {

        console.error(err);

        return res.status(500).json({
            success: false,
            message: err.message
        });
    }
});

// ===========================================================================
// 7. KH?I CH?Y / T?T
// ===========================================================================
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
    console.log('\n' + '='.repeat(50));
    logger.success(`?? SERVER RUNNING ON http://localhost:${PORT}`);
    logger.info(`Múi gi? h? th?ng: ${process.env.TZ}`);
    console.log('='.repeat(50) + '\n');
});
server.on('error', err => { logger.error('HTTP server error', err.message); process.exit(1); });

process.on('unhandledRejection', err => logger.error('Unhandled rejection', err?.message || err));

async function shutdown() {
    logger.info('Shutting down...');
    server.close();
    mqttClient.end(true);
    await pool.end().catch(() => { });
    process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
