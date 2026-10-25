// 1min.ai 每日簽到
// 登入需要騰訊驗證碼，所以腳本不登入：
// - http-request 模式：從經過 Surge 的 app.1min.ai 請求擷取 token 與 team ID
// - cron 模式：token 剩不到 2 天時，有填密碼就以「重設為同一組密碼」換發新 token，沒填就提醒重新登入；再觸發每日獎勵

const TOKEN_KEY = '1min_jwt';
const TEAM_KEY = '1min_team_id';
const RENEW_BEFORE_MS = 2 * 24 * 60 * 60 * 1000;
const POLL_INTERVAL_MS = 5000;
const POLL_ATTEMPTS = 6;
const TITLE = '1min.ai 簽到';
const LOGIN_HINT = '請用經過 Surge 的瀏覽器登入 app.1min.ai 以重新取得 token';

function b64urlDecode(s) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    let bits = 0, value = 0, out = '';
    for (const c of s) {
        const i = chars.indexOf(c);
        if (i < 0) continue;
        value = ((value << 6) | i) & 0xffffff;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out += String.fromCharCode((value >> bits) & 0xff);
        }
    }
    return out;
}

// 只讀 payload，不驗簽章
function jwtPayload(token) {
    try {
        const payload = JSON.parse(b64urlDecode(token.split('.')[1] || ''));
        return typeof payload.exp === 'number' && typeof payload.iat === 'number' ? payload : null;
    } catch (e) {
        return null;
    }
}

// ===== http-request：擷取 token =====
function capture() {
    const headers = $request.headers || {};
    const auth = Object.keys(headers).find((k) => k.toLowerCase() === 'x-auth-token');
    const token = auth ? String(headers[auth]).replace(/^Bearer\s*/i, '').trim() : '';
    const payload = token && jwtPayload(token);

    const team = $request.url.match(/\/teams\/([0-9a-f-]{36})\//i);
    if (team && $persistentStore.read(TEAM_KEY) !== team[1]) {
        $persistentStore.write(team[1], TEAM_KEY);
        console.log(`已記錄 team ID: ${team[1]}`);
        $notification.post(TITLE, '已取得 team ID', team[1]);
    }

    if (payload) {
        const stored = $persistentStore.read(TOKEN_KEY);
        const storedPayload = stored && jwtPayload(stored);
        // 換發後瀏覽器仍會送出舊 token，只接受比現有更新的
        if (!storedPayload || payload.iat > storedPayload.iat) {
            $persistentStore.write(token, TOKEN_KEY);
            const until = new Date(payload.exp * 1000).toLocaleString('zh-TW');
            console.log(`已更新 token，有效至 ${until}`);
            $notification.post(TITLE, '已取得登入 token', `有效至 ${until}`);
        }
    }
    $done({});
}

// ===== cron：簽到 =====
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function api(method, path, token, body) {
    return new Promise((resolve, reject) => {
        const options = {
            url: `https://api.1min.ai${path}`,
            timeout: 10,
            headers: {
                'Content-Type': 'application/json',
                'X-Auth-Token': `Bearer ${token}`,
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
                Accept: 'application/json, text/plain, */*',
                Origin: 'https://app.1min.ai',
                Referer: 'https://app.1min.ai/',
            },
        };
        if (body) options.body = JSON.stringify(body);
        $httpClient[method](options, (error, response, data) => {
            if (error) return reject(new Error(`${path} 連線失敗: ${error}`));
            if (response.status === 401) return reject(new Error(`token 已失效。${LOGIN_HINT}`));
            let json = {};
            try {
                json = JSON.parse(data || '{}');
            } catch (e) {}
            resolve({ status: response.status, json });
        });
    });
}

async function renew(token, password) {
    const { status, json } = await api('post', '/auth/passwords', token, {
        current_password: password,
        new_password: password,
    });
    const next = json.user && json.user.token;
    if (status !== 200 || typeof next !== 'string') {
        throw new Error(`token 換發失敗: ${json.message || `HTTP ${status}`}`);
    }
    $persistentStore.write(next, TOKEN_KEY);
    return next;
}

// null 代表讀不到，不是 0
async function getCredits(teamId, token) {
    const { status, json } = await api('get', `/teams/${teamId}/credits`, token);
    return status === 200 && typeof json.credit === 'number' ? json.credit : null;
}

async function getTopups(teamId, token) {
    const { status, json } = await api('get', `/teams/${teamId}/topups?page=1&pageSize=10&orderBy=-createdAt`, token);
    return status === 200 && Array.isArray(json.topupList) ? json.topupList : null;
}

async function checkin(password) {
    let token = $persistentStore.read(TOKEN_KEY);
    const teamId = $persistentStore.read(TEAM_KEY);
    const payload = token && jwtPayload(token);
    if (!payload || !teamId) throw new Error(`尚未取得 token 或 team ID。${LOGIN_HINT}`);
    if (payload.exp * 1000 <= Date.now()) throw new Error(`token 已過期。${LOGIN_HINT}`);

    let renewed = '';
    if (payload.exp * 1000 - Date.now() < RENEW_BEFORE_MS) {
        if (password) {
            token = await renew(token, password);
            renewed = `\ntoken 已換發，有效至 ${new Date(jwtPayload(token).exp * 1000).toLocaleString('zh-TW')}`;
        } else {
            renewed = `\ntoken 將於 ${new Date(payload.exp * 1000).toLocaleString('zh-TW')} 到期。${LOGIN_HINT}`;
        }
    }

    const startedAt = Date.now();
    // 呼叫未讀通知 API 會觸發每日獎勵，幾秒後才出現在點數紀錄
    const unread = await api('get', '/notifications/unread', token);
    if (unread.status !== 200) throw new Error(`簽到請求失敗: HTTP ${unread.status}`);

    let readOnce = false;
    let latest = null;
    let reward = null;
    for (let i = 0; i < POLL_ATTEMPTS && reward === null; i++) {
        await sleep(POLL_INTERVAL_MS);
        const topups = await getTopups(teamId, token);
        if (!topups) continue;
        readOnce = true;
        latest = topups.find((t) => t.type === 'DAILY_FREE_CREDIT') || null;
        if (latest && Date.parse(latest.createdAt) >= startedAt) reward = latest.credit;
    }

    const credit = await getCredits(teamId, token);
    const lines = [];
    if (credit !== null) lines.push(`點數: ${credit.toLocaleString('zh-TW')}`);
    if (reward !== null) {
        lines.push(`獎勵: +${reward.toLocaleString('zh-TW')}`);
    } else if (readOnce) {
        const at = latest ? new Date(latest.createdAt).toLocaleString('zh-TW') : '今天稍早';
        lines.push(`獎勵: 今日已領取（${at}）`);
    } else {
        lines.push('獎勵: 無法讀取點數紀錄');
    }
    return lines.join('\n') + renewed;
}

if (typeof $request !== 'undefined') {
    capture();
} else {
    const raw = new URLSearchParams($argument || '').get('password');
    // 未填時模組帶入預設值 null
    const password = raw && raw !== 'null' ? raw : null;
    checkin(password)
        .then((message) => {
            console.log(message);
            $notification.post(TITLE, '簽到成功', message);
        })
        .catch((error) => {
            console.log(`❌ ${error.message}`);
            $notification.post(TITLE, '簽到失敗', error.message);
        })
        .finally(() => $done());
}
