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
        Array.from({ length }, () => chars[Math.floor(Math.random() * chars.length)]).join('');

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
                            this.displayCreditInfo(responseData).then(() => resolve(responseData));
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
                        this.displayCreditInfo(responseData).then(() => resolve(responseData));
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
        return new Promise((resolve) => {
            try {
                const user = responseData.user;
                if (user && user.teams && user.teams.length > 0) {
                    const teamInfo = user.teams[0];
                    const teamId = teamInfo.teamId || teamInfo.team.uuid;
                    const authToken = responseData.token || responseData.user.token;

                    // 格式化數字顯示
                    const formatNumber = (num) => {
                        return num.toLocaleString('zh-TW');
                    };

                    const userName = (user.teams && user.teams[0] && user.teams[0].userName) ?
                        user.teams[0].userName :
                        (user.email ? user.email.split('@')[0] : '用戶');

                    // 發送額外的 GET 請求獲取最新 credit 資訊
                    if (teamId && authToken) {
                        // 傳遞原本的 usedCredit 資訊用於百分比計算
                        const usedCredit = teamInfo.usedCredit || 0;
                        this.fetchLatestCredit(teamId, authToken, userName, usedCredit, resolve);
                    } else {
                        // 如果沒有 teamId 或 token，使用原本的邏輯
                        const remainingCredit = teamInfo.team.credit || 0;
                        const usedCredit = teamInfo.usedCredit || 0;
                        const totalCredit = remainingCredit + usedCredit;
                        const availablePercent = totalCredit > 0 ? ((remainingCredit / totalCredit) * 100).toFixed(1) : 0;

                        console.log(`💰 Credit 資訊:`);
                        console.log(`   可用額度: ${formatNumber(remainingCredit)}`);
                        console.log(`   已使用: ${formatNumber(usedCredit)}`);
                        console.log(`   可用比例: ${availablePercent}%`);

                        $notification.post("1min 登入", "登入成功", `${userName} | 餘額: ${formatNumber(remainingCredit)} (${availablePercent}%)`);
                        resolve();
                    }
                } else {
                    console.log("⚠️ 無法取得 Credit 資訊");
                    $notification.post("1min 登入", "登入成功", "歡迎回來！");
                    resolve();
                }
            } catch (error) {
                console.log(`❌ 顯示 Credit 資訊時發生錯誤: ${error.message}`);
                $notification.post("1min 登入", "登入成功", "歡迎回來！");
                resolve();
            }
        });
    }

    // 獲取最新的 Credit 資訊並檢查簽到獎勵
    fetchLatestCredit(teamId, authToken, userName, usedCredit, resolve) {
        console.log(`🔄 開始 Credit 檢查流程 (Team ID: ${teamId})`);
        console.log(`🔑 使用 Token: ${authToken ? authToken.substring(0, 10) + '...' : 'null'}`);

        const headers = {
            "Host": "api.1min.ai",
            "Content-Type": "application/json",
            "X-Auth-Token": `Bearer ${authToken}`,
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
            "Accept": "application/json, text/plain, */*",
            "Origin": "https://app.1min.ai",
            "Referer": "https://app.1min.ai/"
        };

        // 步驟 1: 獲取初始 Credit
        this.getCredits(teamId, authToken, headers, (initialCredit) => {
            console.log(`💰 初始點數: ${this.formatNumber(initialCredit)}`);

            // 步驟 2: 檢查未讀通知
            this.checkUnreadNotifications(authToken, headers, () => {

                // 步驟 3: 再次獲取 Credit 檢查是否有變化
                setTimeout(() => {
                    this.getCredits(teamId, authToken, headers, (finalCredit) => {
                        console.log(`💰 最終點數: ${this.formatNumber(finalCredit)}`);

                        const creditDiff = finalCredit - initialCredit;
                        let notificationMessage = `${userName} | 餘額: ${this.formatNumber(finalCredit)}`;

                        if (creditDiff > 0) {
                            console.log(`🎉 獲得簽到獎勵: +${this.formatNumber(creditDiff)} 點數`);
                            notificationMessage += ` (+${this.formatNumber(creditDiff)})`;
                        } else if (creditDiff === 0) {
                            console.log(`ℹ️ 今日已簽到或無簽到獎勵`);
                        } else {
                            console.log(`⚠️ 點數減少: ${this.formatNumber(creditDiff)}`);
                        }

                        // 計算百分比
                        const totalCredit = finalCredit + usedCredit;
                        const availablePercent = totalCredit > 0 ? ((finalCredit / totalCredit) * 100).toFixed(1) : 0;
                        notificationMessage += ` (${availablePercent}%)`;

                        $notification.post("1min 登入", "登入成功", notificationMessage);
                        resolve();
                    });
                }, 1000); // 等待 1 秒後再檢查，確保簽到處理完成
            });
        });
    }

    // 獲取 Credit 的通用方法
    getCredits(teamId, authToken, headers, callback) {
        const creditUrl = `https://api.1min.ai/teams/${teamId}/credits`;
        console.log(`🌐 請求 Credit URL: ${creditUrl}`);

        const timeoutId = setTimeout(() => {
            console.log(`⏰ Credit API 請求超時`);
            callback(0); // 超時時返回 0
        }, 10000);

        $httpClient.get({
            url: creditUrl,
            headers
        }, (error, response, data) => {
            clearTimeout(timeoutId);

            if (error) {
                console.log(`❌ 獲取 Credit 失敗: ${error}`);
                callback(0);
                return;
            }

            console.log(`📊 Credit API 狀態: ${response.status}`);

            try {
                if (response.status === 200) {
                    const creditData = JSON.parse(data || '{}');
                    const credit = creditData.credit || 0;
                    callback(credit);
                } else {
                    console.log(`❌ Credit API 失敗 - 狀態: ${response.status}`);
                    callback(0);
                }
            } catch (parseError) {
                console.log(`❌ Credit API 解析錯誤: ${parseError.message}`);
                callback(0);
            }
        });
    }

    // 檢查未讀通知
    checkUnreadNotifications(authToken, headers, callback) {
        const notificationUrl = "https://api.1min.ai/notifications/unread";
        console.log(`🔔 檢查未讀通知: ${notificationUrl}`);

        const timeoutId = setTimeout(() => {
            console.log(`⏰ 通知 API 請求超時`);
            callback(); // 超時時也要繼續
        }, 10000);

        $httpClient.get({
            url: notificationUrl,
            headers
        }, (error, response, data) => {
            clearTimeout(timeoutId);

            if (error) {
                console.log(`❌ 獲取通知失敗: ${error}`);
                callback();
                return;
            }

            console.log(`📊 通知 API 狀態: ${response.status}`);

            try {
                if (response.status === 200) {
                    const notificationData = JSON.parse(data || '{}');
                    console.log(`📬 未讀通知數量: ${notificationData.count || 0}`);
                    console.log(`📄 通知回應: ${data ? data.substring(0, 200) : 'null'}`);
                } else {
                    console.log(`❌ 通知 API 失敗 - 狀態: ${response.status}`);
                }
            } catch (parseError) {
                console.log(`❌ 通知 API 解析錯誤: ${parseError.message}`);
            }

            callback(); // 無論成功或失敗都要繼續
        });
    }

    // 格式化數字顯示
    formatNumber(num) {
        return num.toLocaleString('zh-TW');
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
