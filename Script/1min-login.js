// 從參數中取得設定
const params = new URLSearchParams($argument);
const email = params.get('email');
const password = params.get('password');
const totpSecret = params.get('totp');
// 過濾無效的 TOTP 值（空字串、null 字串等）
const validTotpSecret = totpSecret && totpSecret !== 'null' && totpSecret.trim() !== '' ? totpSecret : null;

console.log("🎬 1min.ai 自動簽到");

if (!email || !password) {
    console.log("❌ 錯誤: 缺少 email 或 password 參數");
    $notification.post("1min 登入", "設定錯誤", "請檢查 email 和 password 參數");
    $done();
}

// ===== JWT 儲存管理 =====
const JWT_KEY = `1min_jwt_${email}`;
const USER_DATA_KEY = `1min_user_${email}`;

function saveJWT(token, userData) {
    try {
        $persistentStore.write(token, JWT_KEY);
        $persistentStore.write(JSON.stringify(userData), USER_DATA_KEY);
    } catch (error) {
        console.log(`❌ 儲存 JWT 失敗: ${error.message}`);
    }
}

function loadJWT() {
    try {
        const token = $persistentStore.read(JWT_KEY);
        const userDataStr = $persistentStore.read(USER_DATA_KEY);
        if (token && userDataStr) {
            const userData = JSON.parse(userDataStr);
            return { token, userData };
        }
    } catch (error) {
        console.log(`❌ 載入 JWT 失敗: ${error.message}`);
    }
    return null;
}

function clearJWT() {
    $persistentStore.write(null, JWT_KEY);
    $persistentStore.write(null, USER_DATA_KEY);
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
    const randomHex = (length) =>
        Array.from({ length }, () => chars[Math.floor(Math.random() * chars.length)]).join('');

    // 生成更真實的隨機組合
    const part1 = randomHex(16);
    const part2 = randomHex(15);
    const part3 = randomHex(8);  // 替代固定的 17525636
    const part4 = randomHex(6);  // 替代固定的 16a7f0
    const part5 = randomHex(16); // 替代重複的 part1

    return `$device:${part1}-${part2}-${part3}-${part4}-${part5}`;
};

const deviceId = generateDeviceId();

// ===== 登入流程 =====
class LoginManager {
    constructor(email, password, totpSecret) {
        this.email = email;
        this.password = password;
        this.totpSecret = totpSecret;
    }

    // 驗證 JWT 是否有效
    async validateJWT(token, userData) {
        const headers = this.buildApiHeaders(token);
        const teamId = userData.teams?.[0]?.teamId || userData.teams?.[0]?.team?.uuid;

        if (!teamId) {
            return false;
        }

        try {
            // 使用 credits API 來驗證 JWT 是否仍然有效
            const credit = await this.apiGetCredits(teamId, headers);
            if (credit > 0) {
                return true;
            }
        } catch (error) {
            // JWT 已失效
        }

        return false;
    }

    // 執行登入
    async performLogin() {

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

                try {
                    const responseData = JSON.parse(data || '{}');

                    if (response.status === 200 && responseData.user) {
                        if (responseData.user.mfaRequired) {
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
                            // 儲存 JWT
                            const token = responseData.token || responseData.user?.token;
                            if (token) {
                                saveJWT(token, responseData.user);
                            }
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

                try {
                    const responseData = JSON.parse(data || '{}');

                    if (response.status === 200) {
                        // 儲存 JWT
                        const token = responseData.token || responseData.user?.token;
                        if (token) {
                            saveJWT(token, responseData.user);
                        }
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
    async displayCreditInfo(responseData) {
        try {
            const user = responseData.user;
            if (!user?.teams || user.teams.length === 0) {
                console.log("⚠️ 無法取得 Credit 資訊");
                $notification.post("1min 登入", "登入成功", "歡迎回來！");
                return;
            }

            const authToken = responseData.token || responseData.user?.token;
            const userUuid = user.uuid;

            // 找到對應的 team (subscription.userId 符合當前用戶 uuid)
            let targetTeam = null;

            for (const team of user.teams) {
                const subscriptionUserId = team.team?.subscription?.userId;
                if (subscriptionUserId === userUuid) {
                    targetTeam = team;
                    break;
                }
            }

            // 如果沒找到對應的 team，使用第一個 team 作為後備
            if (!targetTeam && user.teams.length > 0) {
                targetTeam = user.teams[0];
            }

            if (!targetTeam) {
                console.log("❌ 無法找到任何 team");
                $notification.post("1min 登入", "登入成功", "歡迎回來！");
                return;
            }

            const teamInfo = targetTeam;
            const teamId = teamInfo.teamId || teamInfo.team?.uuid;
            const userName = teamInfo.userName || user.email?.split('@')[0] || '用戶';
            const usedCredit = teamInfo.usedCredit || 0;
            const initialCredit = teamInfo.team?.credit || 0;


            if (!teamId || !authToken) {
                const percent = this.calculatePercent(initialCredit, usedCredit);
                this.showCreditNotification(userName, initialCredit, percent);
                return;
            }

            // 檢查簽到獎勵
            await this.checkDailyBonus(teamId, authToken, userName, usedCredit, initialCredit);
        } catch (error) {
            console.log(`❌ 顯示 Credit 資訊時發生錯誤: ${error.message}`);
            $notification.post("1min 登入", "登入成功", "歡迎回來！");
        }
    }

    // 檢查每日簽到獎勵
    async checkDailyBonus(teamId, authToken, userName, usedCredit, initialCredit) {
        const headers = this.buildApiHeaders(authToken);

        try {
            // 1. 呼叫未讀通知 API 觸發簽到獎勵
            await this.apiCheckNotifications(headers);

            // 2. 直接獲取初步 credit
            const firstCredit = await this.apiGetCredits(teamId, headers);
            const firstBonus = firstCredit - initialCredit;

            // 3. 等待 3 秒後獲取最終 credit
            await new Promise(resolve => setTimeout(resolve, 3000));
            const finalCredit = await this.apiGetCredits(teamId, headers);

            // 4. 顯示最終結果
            const totalBonus = finalCredit - initialCredit;
            const percent = this.calculatePercent(finalCredit, usedCredit);
            this.showCreditNotification(userName, finalCredit, percent, totalBonus);

        } catch (error) {
            console.log(`❌ 簽到檢查失敗: ${error.message}`);
            // 如果簽到檢查失敗，就用初始 credit 顯示
            const percent = this.calculatePercent(initialCredit, usedCredit);
            this.showCreditNotification(userName, initialCredit, percent);
        }
    }

    // API: 獲取 Credit
    apiGetCredits(teamId, headers) {
        return new Promise((resolve) => {
            const url = `https://api.1min.ai/teams/${teamId}/credits`;
            const timeout = setTimeout(() => {
                resolve(0);
            }, 10000);

            $httpClient.get({ url, headers }, (error, response, data) => {
                clearTimeout(timeout);

                if (error || response.status !== 200) {
                    resolve(0);
                    return;
                }

                try {
                    const result = JSON.parse(data || '{}');
                    resolve(result.credit || 0);
                } catch (e) {
                    resolve(0);
                }
            });
        });
    }

    // API: 檢查未讀通知 (觸發簽到獎勵)
    apiCheckNotifications(headers) {
        return new Promise((resolve) => {
            const url = "https://api.1min.ai/notifications/unread";
            const timeout = setTimeout(() => {
                resolve();
            }, 10000);

            $httpClient.get({ url, headers }, (error, response, data) => {
                clearTimeout(timeout);

                if (error || response.status !== 200) {
                    resolve();
                    return;
                }

                resolve();
            });
        });
    }

    // 工具方法
    buildApiHeaders(authToken) {
        return {
            "Host": "api.1min.ai",
            "Content-Type": "application/json",
            "X-Auth-Token": `Bearer ${authToken}`,
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
            "Accept": "application/json, text/plain, */*",
            "Origin": "https://app.1min.ai",
            "Referer": "https://app.1min.ai/"
        };
    }

    formatNumber(num) {
        return num.toLocaleString('zh-TW');
    }

    calculatePercent(remainingCredit, usedCredit) {
        const total = remainingCredit + usedCredit;
        return total > 0 ? ((remainingCredit / total) * 100).toFixed(1) : 0;
    }

    showCreditNotification(userName, credit, percent, bonus = 0) {
        let message = `${userName} | 點數: ${this.formatNumber(credit)} (${percent}%)`;

        if (bonus > 0) {
            message += ` (+${this.formatNumber(bonus)})`;
        }

        $notification.post("1min 登入", "登入成功", message);
    }
}

// ===== 執行流程 =====
async function main() {
    const loginManager = new LoginManager(email, password, validTotpSecret);

    // 嘗試使用儲存的 JWT
    const savedData = loadJWT();
    if (savedData) {
        // 驗證 JWT 是否仍有效
        const isValid = await loginManager.validateJWT(savedData.token, savedData.userData);

        if (isValid) {

            // 先獲取最新的團隊資訊和點數
            const headers = loginManager.buildApiHeaders(savedData.token);
            const userUuid = savedData.userData.uuid;

            // 找到對應的 team
            let targetTeam = null;
            for (const team of savedData.userData.teams) {
                const subscriptionUserId = team.team?.subscription?.userId;
                if (subscriptionUserId === userUuid) {
                    targetTeam = team;
                    break;
                }
            }

            if (!targetTeam && savedData.userData.teams.length > 0) {
                targetTeam = savedData.userData.teams[0];
            }

            if (targetTeam) {
                const teamId = targetTeam.teamId || targetTeam.team?.uuid;

                // 獲取最新的點數
                const currentCredit = await loginManager.apiGetCredits(teamId, headers);
                if (currentCredit > 0) {
                    // 更新儲存資料中的點數
                    targetTeam.team.credit = currentCredit;
                }
            }

            // 建構完整的 responseData 格式
            const responseData = {
                user: savedData.userData,
                token: savedData.token
            };

            // 執行簽到流程
            await loginManager.displayCreditInfo(responseData);
            $done();
            return;
        } else {
            clearJWT();
        }
    }

    // 如果沒有有效的 JWT，執行正常登入流程
    loginManager.performLogin()
        .then(() => {
            $done();
        })
        .catch(error => {
            console.log(`❌ 登入失敗: ${error.message}`);
            $done();
        });
}

// 開始執行
main();
