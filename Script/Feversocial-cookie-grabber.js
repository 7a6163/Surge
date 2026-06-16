// Feversocial fv_lc 自動擷取
//
// 配合 Feversocial-checkin.js 使用。
// 監聽 whoscall.feversocial.com 的請求，從 Cookie header 取出 fv_lc 並快取到
// $persistentStore，讓 cron 簽到永遠用最新 token，避免手動複製貼上。

const CACHE_FV_LC = 'fs_checkin_fv_lc';

const headers = $request && $request.headers ? $request.headers : {};
const cookieHeader = headers.Cookie || headers.cookie || '';
const match = cookieHeader.match(/(?:^|;\s*)fv_lc=([^;]+)/);

if (match && match[1]) {
    const fvLc = match[1].trim();
    const cached = $persistentStore.read(CACHE_FV_LC);
    if (cached !== fvLc) {
        $persistentStore.write(fvLc, CACHE_FV_LC);
        console.log('🔑 Feversocial: captured fresh fv_lc');
        $notification.post(
            'Whoscall 每日簽到',
            'fv_lc 已更新',
            `長度 ${fvLc.length}，cron 會用最新 token 簽到`
        );
    }
}

$done({});
