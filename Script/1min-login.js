// 1min-login-fixed.js - 修正版本（加入時間容錯）

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

// ===== 修正版 TOTP 產生器（加入時間容錯） =====
function generateTOTP(secret, timeOffset = 0) {
    if (!secret) {
        console.log("⚠️ 未提供 TOTP 金鑰");
        return null;
    }

    try {
        // Base32 解碼
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        const clean = secret.replace(/\s/g, '').replace(/=+$/, '').toUpperCase();

        let bits = '';
        for (let i = 0; i < clean.length; i++) {
            const val = alphabet.indexOf(clean[i]);
            if (val === -1) {
                console.log(`❌ 無效字元 '${clean[i]}' 在位置 ${i}`);
                return null;
            }
            bits += val.toString(2).padStart(5, '0');
        }

        const bytes = [];
        for (let i = 0; i + 8 <= bits.length; i += 8) {
            bytes.push(parseInt(bits.substr(i, 8), 2));
        }

        const key = new Uint8Array(bytes);

        // 計算時間步數（加入偏移）
        const timestamp = Math.floor(Date.now() / 1000) + timeOffset;
        const timeStep = Math.floor(timestamp / 30);

        // SHA-1 實作
        function sha1(data) {
            function rotateLeft(n, b) {
                return (n << b) | (n >>> (32 - b));
            }

            let h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;

            const msgLength = data.length;
            const paddedData = Array.from(data);
            paddedData.push(0x80);

            while ((paddedData.length % 64) !== 56) {
                paddedData.push(0);
            }

            // 修正：使用 BigInt 確保正確的長度處理
            const bitLength = BigInt(msgLength * 8);
            for (let i = 7; i >= 0; i--) {
                paddedData.push(Number((bitLength >> BigInt(i * 8)) & 0xffn));
            }

            for (let chunk = 0; chunk < paddedData.length; chunk += 64) {
                const w = new Array(80);

                for (let i = 0; i < 16; i++) {
                    w[i] = (paddedData[chunk + i * 4] << 24) |
                           (paddedData[chunk + i * 4 + 1] << 16) |
                           (paddedData[chunk + i * 4 + 2] << 8) |
                           paddedData[chunk + i * 4 + 3];
                }

                for (let i = 16; i < 80; i++) {
                    w[i] = rotateLeft(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
                }

                let a = h0, b = h1, c = h2, d = h3, e = h4;

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
                    e = d; d = c; c = rotateLeft(b, 30); b = a; a = temp;
                }

                h0 = (h0 + a) & 0xffffffff;
                h1 = (h1 + b) & 0xffffffff;
                h2 = (h2 + c) & 0xffffffff;
                h3 = (h3 + d) & 0xffffffff;
                h4 = (h4 + e) & 0xffffffff;
            }

            const result = new Uint8Array(20);
            [h0, h1, h2, h3, h4].forEach((h, i) => {
                result[i * 4] = (h >>> 24) & 0xff;
                result[i * 4 + 1] = (h >>> 16) & 0xff;
                result[i * 4 + 2] = (h >>> 8) & 0xff;
                result[i * 4 + 3] = h & 0xff;
            });

            return result;
        }

        // HMAC-SHA1
        function hmacSha1(key, message) {
            const blockSize = 64;

            if (key.length > blockSize) key = sha1(key);

            const keyPadded = new Uint8Array(blockSize);
            keyPadded.set(key);

            const ipadKey = new Uint8Array(blockSize + message.length);
            const opadKey = new Uint8Array(blockSize + 20);

            for (let i = 0; i < blockSize; i++) {
                ipadKey[i] = keyPadded[i] ^ 0x36;
                opadKey[i] = keyPadded[i] ^ 0x5C;
            }

            ipadKey.set(message, blockSize);
            const innerHash = sha1(ipadKey);

            opadKey.set(innerHash, blockSize);
            return sha1(opadKey);
        }

        // 修正：使用正確的大端序時間計數器
        const counter = new Uint8Array(8);
        const timeStepBig = BigInt(timeStep);
        for (let i = 0; i < 8; i++) {
            counter[7 - i] = Number((timeStepBig >> BigInt(i * 8)) & 0xffn);
        }

        // 計算 HMAC
        const hmac = hmacSha1(key, counter);

        // 動態截取
        const offset = hmac[19] & 0x0f;
        const code = ((hmac[offset] & 0x7f) << 24) |
                     ((hmac[offset + 1] & 0xff) << 16) |
                     ((hmac[offset + 2] & 0xff) << 8) |
                     (hmac[offset + 3] & 0xff);

        const totp = String(code % 1000000).padStart(6, '0');

        return {
            code: totp,
            timeStep: timeStep,
            offset: offset,
            timestamp: timestamp
        };

    } catch (error) {
        console.log(`❌ TOTP 錯誤: ${error.message}`);
        return null;
    }
}

// ===== 嘗試多個時間窗的 TOTP =====
function generateTOTPWithTolerance(secret) {
    console.log("🔐 開始產生 TOTP（含時間容錯）...");

    const candidates = [];

    // 嘗試當前時間及前後各 30 秒的時間窗
    for (let offset = -30; offset <= 30; offset += 30) {
        const result = generateTOTP(secret, offset);
        if (result) {
            const timeDesc = offset === 0 ? '當前' : (offset > 0 ? `+${offset}s` : `${offset}s`);
            console.log(`⏰ ${timeDesc}: ${result.code} (步數: ${result.timeStep})`);

            candidates.push({
                code: result.code,
                offset: offset,
                timeStep: result.timeStep,
                description: timeDesc
            });
        }
    }

    return candidates;
}

// ===== 隨機裝置 ID =====
function generateDeviceId() {
    const chars = '0123456789abcdef';
    let part1 = '', part2 = '';

    for (let i = 0; i < 16; i++) {
        part1 += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    for (let i = 0; i < 15; i++) {
        part2 += chars.charAt(Math.floor(Math.random() * chars.length));
    }

    return `$device:${part1}-${part2}-17525636-16a7f0-${part1}`;
}

const deviceId = generateDeviceId();

// ===== 登入流程 =====

// 第一步：登入
function performLogin() {
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
        "email": email,
        "password": password
    });

    $httpClient.post({
        url: loginUrl,
        headers: headers,
        body: body
    }, function(error, response, data) {
        if (error) {
            console.log(`❌ 登入請求失敗: ${error}`);
            $notification.post("1Min 登入", "網路錯誤", "請檢查網路連線");
            $done();
            return;
        }

        console.log(`📊 登入回應狀態: ${response.status}`);

        try {
            const responseData = JSON.parse(data || '{}');

            if (response.status === 200 && responseData.user) {
                if (responseData.user.mfaRequired) {
                    console.log("🔐 需要 TOTP 驗證");

                    if (totpSecret) {
                        performMFAVerification(responseData.user.token);
                    } else {
                        console.log("❌ 需要 TOTP 但未提供金鑰");
                        $notification.post("1Min 登入", "需要 TOTP", "請在模組參數中新增 totp 金鑰");
                        $done();
                    }
                } else {
                    console.log("✅ 登入成功（無需 TOTP）");
                    $notification.post("1Min 登入", "成功", `歡迎 ${responseData.user.email || '用戶'}`);
                    $done();
                }
            } else {
                console.log(`❌ 登入失敗 - 狀態: ${response.status}`);
                console.log(`📄 錯誤詳情: ${data.substring(0, 200)}...`);

                let errorMsg = "登入失敗";
                if (responseData.message) {
                    errorMsg = responseData.message;
                } else if (response.status === 401) {
                    errorMsg = "帳號或密碼錯誤";
                } else if (response.status === 429) {
                    errorMsg = "請求過於頻繁";
                }

                $notification.post("1Min 登入", "登入失敗", errorMsg);
                $done();
            }
        } catch (parseError) {
            console.log(`❌ JSON 解析錯誤: ${parseError.message}`);
            $notification.post("1Min 登入", "回應錯誤", "伺服器回應格式異常");
            $done();
        }
    });
}

// 第二步：TOTP 驗證（支援多次嘗試）
function performMFAVerification(tempToken) {
    console.log("🔐 開始 TOTP 驗證...");

    const totpCandidates = generateTOTPWithTolerance(totpSecret);

    if (!totpCandidates || totpCandidates.length === 0) {
        console.log("❌ TOTP 產生失敗");
        $notification.post("1Min 登入", "TOTP 錯誤", "無法產生驗證碼，請檢查金鑰");
        $done();
        return;
    }

    // 嘗試第一個候選碼（通常是當前時間）
    let currentIndex = 0;

    function tryTOTPVerification() {
        if (currentIndex >= totpCandidates.length) {
            console.log("❌ 所有 TOTP 候選碼都失敗");
            $notification.post("1Min 登入", "TOTP 失敗", "所有時間窗的驗證碼都被拒絕");
            $done();
            return;
        }

        const candidate = totpCandidates[currentIndex];
        console.log(`🎯 嘗試驗證碼 ${currentIndex + 1}/${totpCandidates.length}: ${candidate.code} (${candidate.description})`);

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
            "code": candidate.code,
            "token": tempToken
        });

        $httpClient.post({
            url: mfaUrl,
            headers: headers,
            body: body
        }, function(error, response, data) {
            if (error) {
                console.log(`❌ TOTP 驗證請求失敗: ${error}`);
                $notification.post("1Min 登入", "TOTP 網路錯誤", "請檢查網路連線");
                $done();
            } else {
                console.log(`📊 TOTP 驗證回應狀態: ${response.status}`);

                try {
                    const responseData = JSON.parse(data || '{}');

                    if (response.status === 200) {
                        console.log(`✅ TOTP 驗證成功！使用了 ${candidate.description} 的驗證碼: ${candidate.code}`);
                        $notification.post("1Min 登入", "成功", `每日登入完成 (TOTP: ${candidate.code})`);
                        $done();
                    } else {
                        console.log(`❌ TOTP 驗證失敗 - 狀態: ${response.status}`);
                        console.log(`📄 錯誤詳情: ${responseData.message || 'Unknown error'}`);

                        // 如果是無效驗證碼，嘗試下一個候選碼
                        if (response.status === 400 && responseData.message && responseData.message.includes('Invalid MFA code')) {
                            console.log(`⏭️ 嘗試下一個驗證碼...`);
                            currentIndex++;
                            setTimeout(tryTOTPVerification, 1000); // 等待 1 秒後重試
                        } else {
                            // 其他錯誤，停止嘗試
                            let errorMsg = "TOTP 驗證失敗";
                            if (responseData.message) {
                                errorMsg = responseData.message;
                            }

                            $notification.post("1Min 登入", "TOTP 失敗", errorMsg);
                            $done();
                        }
                    }
                } catch (parseError) {
                    console.log(`❌ TOTP 回應解析錯誤: ${parseError.message}`);
                    $notification.post("1Min 登入", "TOTP 回應錯誤", "無法解析驗證回應");
                    $done();
                }
            }
        });
    }

    // 開始第一次嘗試
    tryTOTPVerification();
}

// 開始執行
performLogin();
