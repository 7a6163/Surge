// 1min-login-simple.js - 簡化版 TOTP 登入

// 從參數中取得設定
const params = new URLSearchParams($argument);
const email = params.get('email');
const password = params.get('password');
const totpSecret = params.get('totp');
// 過濾無效的 TOTP 值（空字串、null 字串等）
const validTotpSecret = totpSecret && totpSecret !== 'null' && totpSecret.trim() !== '' ? totpSecret : null;

console.log("🎬 1min.ai 自動登入開始");
console.log(`📧 帳號: ${email ? email.substring(0, 3) + '***' + email.substring(email.indexOf('@')) : '未設定'}`);
console.log(`🔐 TOTP: ${validTotpSecret ? '已設定 (' + validTotpSecret.length + ' 字元)' : '未設定'}`);

if (!email || !password) {
    console.log("❌ 錯誤: 缺少 email 或 password 參數");
    $notification.post("1min 登入", "設定錯誤", "請檢查 email 和 password 參數");
    $done();
}

// ===== TOTP 庫動態加載 =====
let OTPAuth;

async function loadOTPAuth() {
    if (!OTPAuth) {
        try {
            const response = await fetch('https://cdn.jsdelivr.net/npm/otpauth@9.4.0/dist/otpauth.umd.min.js');
            const code = await response.text();
            eval(code);
            // 庫通常會掛載到全局對象上
            OTPAuth = this.OTPAuth || window.OTPAuth || global.OTPAuth;
            console.log("✅ OTPAuth 庫加載成功");
        } catch (error) {
            console.log('❌ 加載 OTPAuth 失敗:', error);
            throw error;
        }
    }
    return OTPAuth;
}

// ===== 隨機裝置 ID =====
const generateDeviceId = () => {
    const chars = '0123456789abcdef';
    const randomString = (length) =>
        Array.from({length}, () => chars[Math.floor(Math.random() * chars.length)]).join('');

    const part1 = randomString(16);
    const part2 = randomString(15);

    return `$device:${part1}-${part2}-17525636-16a7f0-${part1}`;
};

const deviceId = generateDeviceId();

// ===== 登入流程 =====
class LoginManager {
    constructor(email, password, totpSecret) {
        this.email = email;
        this.password = password;
        this.totpSecret = totpSecret;
    }

    // 執行登入
    async performLogin() {
        console.log("🚀 開始登入請求...");

        const loginUrl = "https://api.1min.ai/auth/login";
        const headers = {
            "Host": "api.1min.ai",
            "Content-Type": "application/json",
            "X-Auth-Token": "Bearer",
            "Mp-Identity": deviceId,
            "X-App-Version": "1.1.40",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
            "Accept": "application/json, text/plain, */*",
            "Origin": "https://app.1min.ai",
            "Referer": "https://app.1min.ai/"
        };

        const body = JSON.stringify({
            email: this.email,
            password: this.password
        });

        return new Promise((resolve, reject) => {
            $httpClient.post({
                url: loginUrl,
                headers,
                body
            }, (error, response, data) => {
                if (error) {
                    console.log(`❌ 登入請求失敗: ${error}`);
                    $notification.post("1min 登入", "網路錯誤", "請檢查網路連線");
                    reject(error);
                    return;
                }

                console.log(`📊 登入回應狀態: ${response.status}`);

                try {
                    const responseData = JSON.parse(data || '{}');

                    if (response.status === 200 && responseData.user) {
                        if (responseData.user.mfaRequired) {
                            console.log("🔐 需要 TOTP 驗證");

                            if (this.totpSecret) {
                                this.performMFAVerification(responseData.user.token)
                                    .then(resolve)
                                    .catch(reject);
                            } else {
                                console.log("❌ 需要 TOTP 但未提供金鑰");
                                $notification.post("1min 登入", "需要 TOTP", "請在模組參數中新增 totp 金鑰");
                                reject(new Error("Missing TOTP secret"));
                            }
                        } else {
                            console.log("✅ 登入成功（無需 TOTP）");
                            this.displayCreditInfo(responseData);
                            resolve(responseData);
                        }
                    } else {
                        console.log(`❌ 登入失敗 - 狀態: ${response.status}`);

                        let errorMsg = "登入失敗";
                        if (responseData.message) {
                            errorMsg = responseData.message;
                        } else if (response.status === 401) {
                            errorMsg = "帳號或密碼錯誤";
                        } else if (response.status === 429) {
                            errorMsg = "請求過於頻繁，請稍後再試";
                        }

                        $notification.post("1min 登入", "登入失敗", errorMsg);
                        reject(new Error(errorMsg));
                    }
                } catch (parseError) {
                    console.log(`❌ JSON 解析錯誤: ${parseError.message}`);
                    $notification.post("1min 登入", "回應錯誤", "伺服器回應格式異常");
                    reject(parseError);
                }
            });
        });
    }

    // TOTP 驗證（單次嘗試）
    async performMFAVerification(tempToken) {
        console.log("🔐 開始 TOTP 驗證流程...");

        // 動態加載 OTPAuth 庫
        const OTPAuth = await loadOTPAuth();

        // 創建 TOTP 實例並生成驗證碼
        const totp = new OTPAuth.TOTP({
            secret: this.totpSecret,
            digits: 6,
            period: 30,
            algorithm: 'SHA1'
        });

        const totpCode = totp.generate();
        console.log(`🎯 產生 TOTP 驗證碼`);

        const mfaUrl = "https://api.1min.ai/auth/mfa/verify";
        const headers = {
            "Host": "api.1min.ai",
            "Content-Type": "application/json",
            "X-Auth-Token": "Bearer",
            "Mp-Identity": deviceId,
            "X-App-Version": "1.1.40",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
            "Accept": "application/json, text/plain, */*",
            "Origin": "https://app.1min.ai",
            "Referer": "https://app.1min.ai/"
        };

        const body = JSON.stringify({
            code: totpCode,
            token: tempToken
        });

        return new Promise((resolve, reject) => {
            $httpClient.post({
                url: mfaUrl,
                headers,
                body
            }, (error, response, data) => {
                if (error) {
                    console.log(`❌ TOTP 驗證請求失敗: ${error}`);
                    $notification.post("1min 登入", "TOTP 網路錯誤", error);
                    reject(error);
                    return;
                }

                console.log(`📊 TOTP 驗證回應狀態: ${response.status}`);

                try {
                    const responseData = JSON.parse(data || '{}');

                    if (response.status === 200) {
                        console.log(`✅ TOTP 驗證成功！`);
                        this.displayCreditInfo(responseData);
                        resolve(responseData);
                    } else {
                        console.log(`❌ TOTP 驗證失敗 - 狀態: ${response.status}`);

                        const errorMsg = responseData.message || `HTTP ${response.status}`;
                        console.log(`📄 錯誤訊息: ${errorMsg}`);

                        $notification.post("1min 登入", "TOTP 失敗", errorMsg);
                        reject(new Error(errorMsg));
                    }
                } catch (parseError) {
                    console.log(`❌ TOTP 回應解析錯誤: ${parseError.message}`);
                    $notification.post("1min 登入", "TOTP 回應錯誤", "無法解析驗證回應");
                    reject(parseError);
                }
            });
        });
    }

    // 顯示 Credit 餘額資訊
    displayCreditInfo(responseData) {
        try {
            const user = responseData.user;
            if (user && user.teams && user.teams.length > 0) {
                const teamInfo = user.teams[0];
                const remainingCredit = teamInfo.team.credit || 0;  // API 回傳的是剩餘額度
                const usedCredit = teamInfo.usedCredit || 0;
                const totalCredit = remainingCredit + usedCredit;   // 真正的總額度

                // 格式化數字顯示
                const formatNumber = (num) => {
                    return num.toLocaleString('zh-TW');
                };

                const availablePercent = totalCredit > 0 ? ((remainingCredit / totalCredit) * 100).toFixed(1) : 0;

                console.log(`💰 Credit 資訊:`);
                console.log(`   可用額度: ${formatNumber(remainingCredit)}`);
                console.log(`   已使用: ${formatNumber(usedCredit)}`);
                console.log(`   可用比例: ${availablePercent}%`);

                // 顯示通知
                const userName = (user.teams && user.teams[0] && user.teams[0].userName) ?
                    user.teams[0].userName :
                    (user.email ? user.email.split('@')[0] : '用戶');
                $notification.post("1min 登入", "登入成功", `${userName} | 餘額: ${formatNumber(remainingCredit)} (${availablePercent}%)`);
            } else {
                console.log("⚠️ 無法取得 Credit 資訊");
                $notification.post("1min 登入", "登入成功", "歡迎回來！");
            }
        } catch (error) {
            console.log(`❌ 顯示 Credit 資訊時發生錯誤: ${error.message}`);
            $notification.post("1min 登入", "登入成功", "歡迎回來！");
        }
    }
}

// ===== 執行登入 =====
const loginManager = new LoginManager(email, password, validTotpSecret);

loginManager.performLogin()
    .then(() => {
        console.log("🎉 登入流程完成");
        $done();
    })
    .catch(error => {
        console.log(`💥 登入流程失敗: ${error.message}`);
        $done();
    });
