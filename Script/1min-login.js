// 1min-login-simple.js - 簡化版 TOTP 登入

// 從參數中取得設定
const params = new URLSearchParams($argument);
const email = params.get('email');
const password = params.get('password');
const totpSecret = params.get('totp');

console.log("🎬 1Min.ai 自動登入開始");
console.log(`📧 帳號: ${email ? email.substring(0, 3) + '***' + email.substring(email.indexOf('@')) : '未設定'}`);
console.log(`🔐 TOTP: ${totpSecret ? '已設定 (' + totpSecret.length + ' 字元)' : '未設定'}`);

if (!email || !password) {
    console.log("❌ 錯誤: 缺少 email 或 password 參數");
    $notification.post("1Min 登入", "設定錯誤", "請檢查 email 和 password 參數");
    $done();
}

// ===== 簡化 TOTP 類別 =====
class TOTP {
    constructor(key, digit = 6) {
        this.key = key;
        this.digit = digit;
    }

    // 產生當前 TOTP
    genOTP() {
        const timestamp = Math.floor(Date.now() / 1000 / 30);
        return this._generateHOTP(timestamp);
    }

    // 核心 HOTP 產生邏輯
    _generateHOTP(counter) {
        const key = this._base32Decode(this.key);
        const counterBytes = this._intToBytes(counter);
        const hmac = this._hmacSha1(key, counterBytes);
        return this._truncate(hmac);
    }

    // Base32 解碼
    _base32Decode(base32) {
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        const cleanInput = base32.replace(/\s/g, '').replace(/=+$/, '').toUpperCase();

        let bits = '';
        for (let i = 0; i < cleanInput.length; i++) {
            const val = alphabet.indexOf(cleanInput[i]);
            if (val === -1) throw new Error(`Invalid Base32 character: ${cleanInput[i]}`);
            bits += val.toString(2).padStart(5, '0');
        }

        const bytes = [];
        for (let i = 0; i + 8 <= bits.length; i += 8) {
            bytes.push(parseInt(bits.substr(i, 8), 2));
        }

        return new Uint8Array(bytes);
    }

    // 將數字轉為 8 位元組大端序
    _intToBytes(number) {
        const bytes = new Uint8Array(8);
        for (let i = 7; i >= 0; i--) {
            bytes[i] = number & 0xff;
            number >>= 8;
        }
        return bytes;
    }

    // SHA-1 實作
    _sha1(data) {
        const rotateLeft = (n, b) => (n << b) | (n >>> (32 - b));

        // 初始雜湊值
        let h0 = 0x67452301;
        let h1 = 0xEFCDAB89;
        let h2 = 0x98BADCFE;
        let h3 = 0x10325476;
        let h4 = 0xC3D2E1F0;

        // 前處理
        const originalLength = data.length * 8;
        const message = Array.from(data);
        message.push(0x80);

        while (message.length % 64 !== 56) {
            message.push(0);
        }

        // 附加原始長度（64位元大端序）
        for (let i = 0; i < 8; i++) {
            message.push((originalLength >>> ((7 - i) * 8)) & 0xff);
        }

        // 處理每個 512 位元區塊
        for (let chunkStart = 0; chunkStart < message.length; chunkStart += 64) {
            const w = new Array(80);

            // 將區塊分解為 16 個 32 位元字
            for (let i = 0; i < 16; i++) {
                w[i] = (message[chunkStart + i * 4] << 24) |
                       (message[chunkStart + i * 4 + 1] << 16) |
                       (message[chunkStart + i * 4 + 2] << 8) |
                       message[chunkStart + i * 4 + 3];
            }

            // 擴展為 80 個字
            for (let i = 16; i < 80; i++) {
                w[i] = rotateLeft(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
            }

            // 初始化雜湊值
            let a = h0, b = h1, c = h2, d = h3, e = h4;

            // 80 輪主迴圈
            for (let i = 0; i < 80; i++) {
                let f, k;
                if (i < 20) {
                    f = (b & c) | (~b & d);
                    k = 0x5A827999;
                } else if (i < 40) {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1;
                } else if (i < 60) {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDC;
                } else {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6;
                }

                const temp = (rotateLeft(a, 5) + f + e + k + w[i]) & 0xffffffff;
                e = d;
                d = c;
                c = rotateLeft(b, 30);
                b = a;
                a = temp;
            }

            h0 = (h0 + a) & 0xffffffff;
            h1 = (h1 + b) & 0xffffffff;
            h2 = (h2 + c) & 0xffffffff;
            h3 = (h3 + d) & 0xffffffff;
            h4 = (h4 + e) & 0xffffffff;
        }

        // 產生最終雜湊值
        const result = new Uint8Array(20);
        [h0, h1, h2, h3, h4].forEach((h, i) => {
            result[i * 4] = (h >>> 24) & 0xff;
            result[i * 4 + 1] = (h >>> 16) & 0xff;
            result[i * 4 + 2] = (h >>> 8) & 0xff;
            result[i * 4 + 3] = h & 0xff;
        });

        return result;
    }

    // HMAC-SHA1 實作
    _hmacSha1(key, message) {
        const blockSize = 64;

        if (key.length > blockSize) {
            key = this._sha1(key);
        }

        const keyPadded = new Uint8Array(blockSize);
        keyPadded.set(key);

        const ipadKey = new Uint8Array(blockSize);
        const opadKey = new Uint8Array(blockSize);

        for (let i = 0; i < blockSize; i++) {
            ipadKey[i] = keyPadded[i] ^ 0x36;
            opadKey[i] = keyPadded[i] ^ 0x5C;
        }

        // 內部雜湊
        const innerData = new Uint8Array(blockSize + message.length);
        innerData.set(ipadKey);
        innerData.set(message, blockSize);
        const innerHash = this._sha1(innerData);

        // 外部雜湊
        const outerData = new Uint8Array(blockSize + innerHash.length);
        outerData.set(opadKey);
        outerData.set(innerHash, blockSize);

        return this._sha1(outerData);
    }

    // 動態截取
    _truncate(hmac) {
        const offset = hmac[hmac.length - 1] & 0x0f;
        const code = ((hmac[offset] & 0x7f) << 24) |
                     ((hmac[offset + 1] & 0xff) << 16) |
                     ((hmac[offset + 2] & 0xff) << 8) |
                     (hmac[offset + 3] & 0xff);

        return String(code % (10 ** this.digit)).padStart(this.digit, '0');
    }
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
        this.totp = totpSecret ? new TOTP(totpSecret) : null;
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
                    $notification.post("1Min 登入", "網路錯誤", "請檢查網路連線");
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
                                $notification.post("1Min 登入", "需要 TOTP", "請在模組參數中新增 totp 金鑰");
                                reject(new Error("Missing TOTP secret"));
                            }
                        } else {
                            console.log("✅ 登入成功（無需 TOTP）");
                            $notification.post("1Min 登入", "成功", `歡迎 ${responseData.user.email || '用戶'}`);
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

                        $notification.post("1Min 登入", "登入失敗", errorMsg);
                        reject(new Error(errorMsg));
                    }
                } catch (parseError) {
                    console.log(`❌ JSON 解析錯誤: ${parseError.message}`);
                    $notification.post("1Min 登入", "回應錯誤", "伺服器回應格式異常");
                    reject(parseError);
                }
            });
        });
    }

    // TOTP 驗證（單次嘗試）
    async performMFAVerification(tempToken) {
        console.log("🔐 開始 TOTP 驗證流程...");

        const totpCode = this.totp.genOTP();
        console.log(`🎯 產生 TOTP: ${totpCode}`);

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
                    $notification.post("1Min 登入", "TOTP 網路錯誤", error);
                    reject(error);
                    return;
                }

                console.log(`📊 TOTP 驗證回應狀態: ${response.status}`);

                try {
                    const responseData = JSON.parse(data || '{}');

                    if (response.status === 200) {
                        console.log(`✅ TOTP 驗證成功！驗證碼: ${totpCode}`);
                        $notification.post("1Min 登入", "成功", `每日登入完成！TOTP: ${totpCode}`);
                        resolve(responseData);
                    } else {
                        console.log(`❌ TOTP 驗證失敗 - 狀態: ${response.status}`);

                        const errorMsg = responseData.message || `HTTP ${response.status}`;
                        console.log(`📄 錯誤訊息: ${errorMsg}`);

                        $notification.post("1Min 登入", "TOTP 失敗", errorMsg);
                        reject(new Error(errorMsg));
                    }
                } catch (parseError) {
                    console.log(`❌ TOTP 回應解析錯誤: ${parseError.message}`);
                    $notification.post("1Min 登入", "TOTP 回應錯誤", "無法解析驗證回應");
                    reject(parseError);
                }
            });
        });
    }
}

// ===== 執行登入 =====
const loginManager = new LoginManager(email, password, totpSecret);

loginManager.performLogin()
    .then(() => {
        console.log("🎉 登入流程完成");
        $done();
    })
    .catch(error => {
        console.log(`💥 登入流程失敗: ${error.message}`);
        $done();
    });
