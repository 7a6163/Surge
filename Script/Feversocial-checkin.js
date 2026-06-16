// Feversocial 每日簽到自動化（Whoscall TW 月度活動）
//
// 設計流程：
//   1. resolvePromotion: 用 $persistentStore 快取當月 promotion UUID
//      - 快取有效（未過期、status=1、是 Whoscall 簽到類型）→ 直接用
//      - 快取無效 → 從快取的 page ID 開始往前掃 +0..+10
//        每個候選頁面 GET HTML 解 promo UUID，再 GET /promotions/{uuid} 驗證
//   2. getBearer: 用 fv_lc cookie 換 Bearer token
//   3. getEntryUuid: 拿使用者 entry UUID
//   4. claimPrize: POST result 進行簽到
//
// Surge 模組參數：
//   - Cron（預設 `5 1 * * *` = UTC 01:05 = Taipei 09:05）
//   - Zines_Page_URL（種子 URL，例如 https://whoscall.feversocial.com/tw/53）
//   - fv_lc（長效登入 JWT cookie）

const params = new URLSearchParams($argument);
const zinesUrl = params.get('zines_url');
// fv_lc 優先讀 grabber 寫入的快取，fallback 用 Surge 參數（首次設定用）
const CACHE_FV_LC = 'fs_checkin_fv_lc';
const fvLc = $persistentStore.read(CACHE_FV_LC) || params.get('fv_lc');

const NOTI_TITLE = 'Whoscall 每日簽到';
const APP_ID = 'nC5GnijM6mK03FX1QSceqJ6S5tjmnwfv';
const FEVER_HOST = 'whoscall.feversocial.com';
const ORIGIN = `https://${FEVER_HOST}`;
const API_BASE = 'https://api.feversocial.com';
const UA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.5 Mobile/15E148 Safari/604.1';
const ACCEPT_API_V1 = 'application/x.api.v1+json';

const CACHE_UUID = 'fs_checkin_promo_uuid';
const CACHE_PAGE_ID = 'fs_checkin_page_id';

const WHOSCALL_TW_SPONSOR_UUID = '164f658e-43e6-45e7-9a8e-165b4150d1f4';
const SIGN_IN_PROMO_TYPE = 15;
const TAIPEI_TZ_OFFSET = '+08:00';
const MAX_SCAN_OFFSET = 10;

// ===== HTTP helpers =====

function httpGet(url, headers) {
    return new Promise((resolve) => {
        $httpClient.get({ url, headers: headers || {} }, (error, response, body) => {
            resolve({ error, response, body });
        });
    });
}

function httpPost(url, headers, body) {
    return new Promise((resolve) => {
        $httpClient.post({ url, headers: headers || {}, body }, (error, response, body) => {
            resolve({ error, response, body });
        });
    });
}

function parseJson(body) {
    try {
        return JSON.parse(body);
    } catch (e) {
        return null;
    }
}

// ===== Notification + exit =====

function notify(subtitle, message) {
    $notification.post(NOTI_TITLE, subtitle || '', message || '');
}

function finish(subtitle, message) {
    if (subtitle) {
        console.log(`📣 ${subtitle} | ${message || ''}`);
        notify(subtitle, message);
    }
    $done();
}

// ===== Zines URL parsing & promotion discovery =====

function parseZinesUrl(url) {
    // 例：https://whoscall.feversocial.com/tw/53 → {origin, sponsor:'tw', pageId:53}
    const m = (url || '').match(/^(https?:\/\/[^\/]+)\/([a-z]+)\/(\d+)\/?$/i);
    if (!m) throw new Error('Zines_Page_URL 格式異常（預期 https://host/<sponsor>/<pageId>）');
    return { origin: m[1], sponsor: m[2], pageId: Number(m[3]) };
}

async function discoverPromotionUuid(pageUrl) {
    const { error, response, body } = await httpGet(pageUrl, {
        'User-Agent': UA,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
    });
    if (error) throw new Error(`zines GET 失敗: ${error}`);
    if (!response || response.status !== 200) throw new Error(`zines 回應 ${response && response.status}`);

    const match = (body || '').match(/title="promotion-([0-9a-f-]+)"/i);
    if (!match) throw new Error('HTML 內無 promotion');
    return match[1];
}

async function fetchPromotionInfo(uuid) {
    const url = `${API_BASE}/promotions/${uuid}`;
    const { error, response, body } = await httpGet(url, {
        'User-Agent': UA,
        'Accept': ACCEPT_API_V1,
        'Content-Type': 'application/json; charset=utf-8',
        'Fever-Host': FEVER_HOST,
        'Origin': ORIGIN,
        'Referer': `${ORIGIN}/`,
    });
    if (error || !response || response.status !== 200) return null;
    return parseJson(body);
}

function isWhoscallSignIn(info) {
    const promo = info && info.data && info.data.promo;
    return !!promo && promo.sponsorUuid === WHOSCALL_TW_SPONSOR_UUID && promo.type === SIGN_IN_PROMO_TYPE;
}

function isActive(info) {
    const data = info && info.data;
    if (!data || !data.promo || !data.promoSetting || !data.promoSetting.Promotions) return false;
    if (data.promo.status !== 1) return false;
    const p = data.promoSetting.Promotions;
    if (!p.startDate || !p.endDate) return false;
    const now = new Date();
    const start = new Date(p.startDate.replace(' ', 'T') + TAIPEI_TZ_OFFSET);
    const end = new Date(p.endDate.replace(' ', 'T') + TAIPEI_TZ_OFFSET);
    if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) return false;
    return now >= start && now <= end;
}

async function resolvePromotion(seedUrl) {
    const seed = parseZinesUrl(seedUrl);

    // 1. 嘗試使用快取
    const cachedUuid = $persistentStore.read(CACHE_UUID);
    if (cachedUuid) {
        const info = await fetchPromotionInfo(cachedUuid);
        if (isWhoscallSignIn(info) && isActive(info)) {
            const pageId = Number($persistentStore.read(CACHE_PAGE_ID)) || seed.pageId;
            console.log(`📦 cached promotion still active: ${cachedUuid} @ /${seed.sponsor}/${pageId}`);
            return { uuid: cachedUuid, pageId };
        }
        console.log(`🔍 cached promotion ${cachedUuid} invalid, scanning forward...`);
    }

    // 2. 從快取/種子 page ID 往前掃
    const startPageId = Number($persistentStore.read(CACHE_PAGE_ID)) || seed.pageId;
    for (let offset = 0; offset <= MAX_SCAN_OFFSET; offset++) {
        const candidateId = startPageId + offset;
        const candidateUrl = `${seed.origin}/${seed.sponsor}/${candidateId}`;
        let promoUuid;
        try {
            promoUuid = await discoverPromotionUuid(candidateUrl);
        } catch (e) {
            console.log(`  - /${seed.sponsor}/${candidateId}: ${e.message}`);
            continue;
        }
        const info = await fetchPromotionInfo(promoUuid);
        if (isWhoscallSignIn(info) && isActive(info)) {
            $persistentStore.write(promoUuid, CACHE_UUID);
            $persistentStore.write(String(candidateId), CACHE_PAGE_ID);
            console.log(`✅ discovered /${seed.sponsor}/${candidateId} → ${promoUuid}`);
            return { uuid: promoUuid, pageId: candidateId };
        }
        console.log(`  - /${seed.sponsor}/${candidateId} promo ${promoUuid}: 非 Whoscall 簽到或已過期`);
    }

    throw new Error(`掃描 ${seed.sponsor}/${startPageId}~${startPageId + MAX_SCAN_OFFSET} 無有效活動`);
}

// ===== Auth + sign-in flow =====

async function getBearer(cookie) {
    const url = `${ORIGIN}/auth/client/token?app_id=${APP_ID}&login_type=enterprise`;
    const { error, response, body } = await httpGet(url, {
        'User-Agent': UA,
        'Accept': '*/*',
        'Cookie': `fv_lc=${cookie}`,
        'Referer': `${ORIGIN}/`,
    });
    if (error) throw new Error(`token GET 失敗: ${error}`);
    if (!response || response.status !== 200) throw new Error(`token 回應 ${response && response.status}`);

    const json = parseJson(body);
    if (!json || !json.token) throw new Error('token 回應格式異常');
    return json.token;
}

function apiHeaders(bearer) {
    return {
        'User-Agent': UA,
        'Accept': ACCEPT_API_V1,
        'Content-Type': 'application/json; charset=utf-8',
        'Authorization': `Bearer ${bearer}`,
        'Fever-Host': FEVER_HOST,
        'Origin': ORIGIN,
        'Referer': `${ORIGIN}/`,
    };
}

async function getEntryUuid(promoUuid, bearer) {
    const url = `${API_BASE}/promotions/${promoUuid}/entries?ts=${Date.now()}`;
    const { error, response, body } = await httpGet(url, apiHeaders(bearer));
    if (error) throw new Error(`entries GET 失敗: ${error}`);
    if (!response || response.status !== 200) throw new Error(`entries 回應 ${response && response.status}`);

    const json = parseJson(body);
    const items = json && json.data && json.data.items;
    if (!Array.isArray(items) || items.length === 0) {
        throw new Error('尚未建立 entry，請先用瀏覽器訪問活動頁一次');
    }
    return items[0].uuid;
}

async function claimPrize(promoUuid, entryUuid, bearer, referralUrl) {
    const url = `${API_BASE}/promotions/${promoUuid}/entries/${entryUuid}/result`;
    const payload = {
        system: {
            gaClientId: '',
            utmSource: '',
            utmCampaign: '',
            utmMedium: '',
            utmTerm: '',
            utmContent: '',
            referralUrl,
        },
        biz_tracking: {
            clientUserAgent: UA,
        },
    };
    const { error, response, body } = await httpPost(url, apiHeaders(bearer), JSON.stringify(payload));
    if (error) throw new Error(`result POST 失敗: ${error}`);

    const json = parseJson(body) || {};
    return {
        status: response && response.status,
        code: json.code,
        message: json.message,
        data: json.data,
    };
}

// ===== Main =====

async function run() {
    console.log('🎬 Whoscall 每日簽到');

    if (!zinesUrl || !fvLc) {
        return finish('參數缺失', '請設定 Zines_Page_URL 和 fv_lc');
    }

    let seed;
    try {
        seed = parseZinesUrl(zinesUrl);
    } catch (e) {
        return finish('Zines_Page_URL 異常', e.message);
    }

    let promoUuid, pageId;
    try {
        const resolved = await resolvePromotion(zinesUrl);
        promoUuid = resolved.uuid;
        pageId = resolved.pageId;
    } catch (e) {
        return finish('找不到當月活動', `${e.message}，請更新 Zines_Page_URL`);
    }

    let bearer;
    try {
        bearer = await getBearer(fvLc);
        console.log(`✅ bearer token 已取得`);
    } catch (e) {
        return finish('登入失敗', `${e.message}，fv_lc 可能過期`);
    }

    let entryUuid;
    try {
        entryUuid = await getEntryUuid(promoUuid, bearer);
        console.log(`✅ entry UUID: ${entryUuid}`);
    } catch (e) {
        return finish('Entry 取得失敗', e.message);
    }

    const referralUrl = `${seed.origin}/${seed.sponsor}/${pageId}`;

    let result;
    try {
        result = await claimPrize(promoUuid, entryUuid, bearer, referralUrl);
        console.log(`✅ result: ${JSON.stringify(result)}`);
    } catch (e) {
        return finish('簽到失敗', e.message);
    }

    if (result.code === 'ENT-C0-S0' && Array.isArray(result.data) && result.data[0] === true) {
        const days = result.data[1];
        return finish('簽到成功 +30 點', `本月已累積 ${days} 天 @ /${seed.sponsor}/${pageId}`);
    }

    return finish('簽到回應異常', `code=${result.code} status=${result.status} msg=${result.message || ''}`);
}

run().catch((e) => {
    finish('未預期錯誤', e && e.message ? e.message : String(e));
});
