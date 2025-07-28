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
            console.log(`🔍 尋找用戶 ${userUuid} 所屬的 team`);
            let targetTeam = null;

            for (const team of user.teams) {
                const subscriptionUserId = team.team?.subscription?.userId;
                if (subscriptionUserId === userUuid) {
                    targetTeam = team;
                    console.log(`✅ 找到所屬 team: ${team.team?.name || 'Unknown'}`);
                    break;
                }
            }

            // 如果沒找到對應的 team，使用第一個 team 作為後備
            if (!targetTeam && user.teams.length > 0) {
                targetTeam = user.teams[0];
                console.log(`⚠️ 未找到對應 team，使用第一個 team`);
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

            console.log(`💰 登入回應中的點數: ${this.formatNumber(initialCredit)}`);

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
        console.log(`🔄 開始簽到檢查`);

        const headers = this.buildApiHeaders(authToken);

        try {
            // 1. 呼叫未讀通知 API 觸發簽到獎勵
            await this.apiCheckNotifications(headers);

            // 2. 等待並獲取最新 credit
            await new Promise(resolve => setTimeout(resolve, 10000));
            const finalCredit = await this.apiGetCredits(teamId, headers);
            console.log(`💰 最終點數: ${this.formatNumber(finalCredit)}`);

            // 3. 顯示結果
            const bonus = finalCredit - initialCredit;
            const percent = this.calculatePercent(finalCredit, usedCredit);
            this.showCreditNotification(userName, finalCredit, percent, bonus);

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
            console.log(`🌐 請求 Credit: ${teamId}`);

            const timeout = setTimeout(() => {
                console.log(`⏰ Credit API 超時`);
                resolve(0);
            }, 10000);

            $httpClient.get({ url, headers }, (error, response, data) => {
                clearTimeout(timeout);

                if (error || response.status !== 200) {
                    console.log(`❌ Credit API 失敗: ${error || response.status}`);
                    resolve(0);
                    return;
                }

                try {
                    const result = JSON.parse(data || '{}');
                    resolve(result.credit || 0);
                } catch (e) {
                    console.log(`❌ Credit API 解析失敗: ${e.message}`);
                    resolve(0);
                }
            });
        });
    }

    // API: 檢查未讀通知 (觸發簽到獎勵)
    apiCheckNotifications(headers) {
        return new Promise((resolve) => {
            const url = "https://api.1min.ai/notifications/unread";
            console.log(`🔔 檢查未讀通知`);

            const timeout = setTimeout(() => {
                console.log(`⏰ 通知 API 超時`);
                resolve();
            }, 10000);

            $httpClient.get({ url, headers }, (error, response, data) => {
                clearTimeout(timeout);

                if (error || response.status !== 200) {
                    console.log(`❌ 通知 API 失敗: ${error || response.status}`);
                    resolve();
                    return;
                }

                try {
                    const result = JSON.parse(data || '{}');
                    console.log(`📬 未讀通知: ${result.count || 0} 個`);
                } catch (e) {
                    console.log(`❌ 通知 API 解析失敗: ${e.message}`);
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
            console.log(`🎉 獲得簽到獎勵: +${this.formatNumber(bonus)} 點數`);
            message += ` (+${this.formatNumber(bonus)})`;
        } else if (bonus === 0) {
            console.log(`ℹ️ 今日已簽到或無簽到獎勵`);
        }

        $notification.post("1min 登入", "登入成功", message);
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
