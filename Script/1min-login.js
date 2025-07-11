// 1min-login-correct.js - 使用正確的標準 TOTP 實作

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

// ===== 修正版 TOTP 實作（完全按照你提供的標準版本） =====
function generateTOTP(secret, timeOffset = 0) {
    if (!secret) return null;

    try {
        console.log(`🔐 開始產生 TOTP (偏移: ${timeOffset}s)...`);

        // 標準 Base32 解碼（完全按照你的版本）
        function base32ToBytes(base32) {
            const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

            // 移除空格和填充，轉大寫
            base32 = base32.replace(/\s/g, '').replace(/=+$/, '').toUpperCase();

            let bits = '';
            for (let i = 0; i < base32.length; i++) {
                const val = alphabet.indexOf(base32[i]);
                if (val === -1) throw new Error(`Invalid Base32 character: ${base32[i]}`);
                bits += val.toString(2).padStart(5, '0');
            }

            const bytes = [];
            for (let i = 0; i + 8 <= bits.length; i += 8) {
                bytes.push(parseInt(bits.substr(i, 8), 2));
            }

            return new Uint8Array(bytes);
        }

        // 簡化但正確的 SHA-1 實作
        function sha1(data) {
            function rotl(n, b) {
                return (n << b) | (n >>> (32 - b));
            }

            // 初始雜湊值
            let h0 = 0x67452301;
            let h1 = 0xEFCDAB89;
            let h2 = 0x98BADCFE;
            let h3 = 0x10325476;
            let h4 = 0xC3D2E1F0;

            // 前處理
            const ml = data.length * 8;
            const msg = Array.from(data);
            msg.push(0x80);

            while (msg.length % 64 !== 56) {
                msg.push(0);
            }

            // 附加長度（64位元大端序）
            for (let i = 0; i < 8; i++) {
                msg.push((ml >>> ((7 - i) * 8)) & 0xff);
            }

            // 處理每個 512 位元區塊
            for (let i = 0; i < msg.length; i += 64) {
                const w = new Array(80);

                // 將區塊分解為 16 個 32 位元字
                for (let j = 0; j < 16; j++) {
                    w[j] = (msg[i + j * 4] << 24) |
                           (msg[i + j * 4 + 1] << 16) |
                           (msg[i + j * 4 + 2] << 8) |
                           msg[i + j * 4 + 3];
                }

                // 擴展為 80 個字
                for (let j = 16; j < 80; j++) {
                    w[j] = rotl(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
                }

                // 初始化
                let a = h0, b = h1, c = h2, d = h3, e = h4;

                // 80 輪主迴圈
                for (let j = 0; j < 80; j++) {
                    let f, k;
                    if (j < 20) {
                        f = (b & c) | (~b & d);
                        k = 0x5A827999;
                    } else if (j < 40) {
                        f = b ^ c ^ d;
                        k = 0x6ED9EBA1;
                    } else if (j < 60) {
                        f = (b & c) | (b & d) | (c & d);
                        k = 0x8F1BBCDC;
                    } else {
                        f = b ^ c ^ d;
                        k = 0xCA62C1D6;
                    }

                    const temp = (rotl(a, 5) + f + e + k + w[j]) & 0xffffffff;
                    e = d;
                    d = c;
                    c = rotl(b, 30);
                    b = a;
                    a = temp;
                }

                h0 = (h0 + a) & 0xffffffff;
                h1 = (h1 + b) & 0xffffffff;
                h2 = (h2 + c) & 0xffffffff;
                h3 = (h3 + d) & 0xffffffff;
                h4 = (h4 + e) & 0xffffffff;
            }

            // 產生最終雜湊
            const result = new Uint8Array(20);
            [h0, h1, h2, h3, h4].forEach((h, i) => {
                result[i * 4] = (h >>> 24) & 0xff;
                result[i * 4 + 1] = (h >>> 16) & 0xff;
                result[i * 4 + 2] = (h >>> 8) & 0xff;
                result[i * 4 + 3] = h & 0xff;
            });

            return result;
        }

        // HMAC-SHA1（標準實作）
        function hmacSha1(key, message) {
            const blockSize = 64;

            if (key.length > blockSize) {
                key = sha1(key);
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
            const innerHash = sha1(innerData);

            // 外部雜湊
            const outerData = new Uint8Array(blockSize + innerHash.length);
            outerData.set(opadKey);
            outerData.set(innerHash, blockSize);

            return sha1(outerData);
        }

        // 使用當前時間或指定時間
        const timestamp = Math.floor(Date.now() / 1000) + timeOffset;
        const timeStep = Math.floor(timestamp / 30);

        console.log(`⏰ 時間戳: ${timestamp}`);
        console.log(`📊 時間步: ${timeStep}`);
        console.log(`🕒 時間: ${new Date(timestamp * 1000).toLocaleString()}`);

        // 解碼 Base32 金鑰
        const key = base32ToBytes(secret);
        console.log(`🔑 金鑰長度: ${key.length} bytes`);

        // 建立 8 bytes 的時間 counter (big-endian) - 完全按照標準版本
        const counter = new Uint8Array(8);
        const high = Math.floor(timeStep / 0x100000000);
        const low = timeStep & 0xffffffff;

        // 寫入高 32 位元（大端序）
        counter[0] = (high >>> 24) & 0xff;
        counter[1] = (high >>> 16) & 0xff;
        counter[2] = (high >>> 8) & 0xff;
        counter[3] = high & 0xff;

        // 寫入低 32 位元（大端序）
        counter[4] = (low >>> 24) & 0xff;
        counter[5] = (low >>> 16) & 0xff;
        counter[6] = (low >>> 8) & 0xff;
        counter[7] = low & 0xff;

        console.log(`🔢 Counter: ${Array.from(counter).map(b => b.toString(16).padStart(2, '0')).join('')}`);

        // 計算 HMAC-SHA1
        const hmac = hmacSha1(key, counter);
        console.log(`🔐 HMAC: ${Array.from(hmac).map(b => b.toString(16).padStart(2, '0')).join('')}`);

        // Dynamic Truncation - 完全按照標準版本
        const offset = hmac[hmac.length - 1] & 0x0f;
        console.log(`📍 Offset: ${offset}`);

        const code = ((hmac[offset] & 0x7f) << 24) |
                     ((hmac[offset + 1] & 0xff) << 16) |
                     ((hmac[offset + 2] & 0xff) << 8) |
                     (hmac[offset + 3] & 0xff);

        console.log(`🔢 Code: ${code}`);

        const totp = String(code % 1000000).padStart(6, '0');
        console.log(`🎯 TOTP: ${totp}`);

        return {
            code: totp,
            timeStep: timeStep,
            offset: offset,
            timestamp: timestamp
        };

    } catch (error) {
        console.log(`❌ TOTP 產生錯誤: ${error.message}`);
        return null;
    }
}

// ===== 生成多個時間窗的候選碼 =====
function generateTOTPCandidates(secret) {
    console.log("🔄 產生多時間窗 TOTP 候選碼...");

    const candidates = [];

    // 嘗試前後各一個時間窗（30秒）
    for (let offset = -30; offset <= 30; offset += 30) {
        const result = generateTOTP(secret, offset);
        if (result) {
            const description = offset === 0 ? '當前' :
                              offset > 0 ? `+${offset}s` :
                              `${offset}s`;

            candidates.push({
                code: result.code,
                offset: offset,
                description: description,
                timeStep: result.timeStep
            });

            console.log(`⏱️ ${description}: ${result.code} (步數: ${result.timeStep})`);
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

                let errorMsg = "登入失敗";
                if (responseData.message) {
                    errorMsg = responseData.message;
                } else if (response.status === 401) {
                    errorMsg = "帳號或密碼錯誤";
                } else if (response.status === 429) {
                    errorMsg = "請求過於頻繁，請稍後再試";
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

// 第二步：TOTP 驗證（嘗試多個候選碼）
function performMFAVerification(tempToken) {
    console.log("🔐 開始 TOTP 驗證流程...");

    const totpCandidates = generateTOTPCandidates(totpSecret);

    if (!totpCandidates || totpCandidates.length === 0) {
        console.log("❌ 無法產生 TOTP 候選碼");
        $notification.post("1Min 登入", "TOTP 錯誤", "無法產生驗證碼");
        $done();
        return;
    }

    let currentIndex = 0;

    function attemptVerification() {
        if (currentIndex >= totpCandidates.length) {
            console.log("❌ 所有 TOTP 候選碼都失敗");
            $notification.post("1Min 登入", "TOTP 失敗", "所有驗證碼都被拒絕");
            $done();
            return;
        }

        const candidate = totpCandidates[currentIndex];
        console.log(`🎯 嘗試第 ${currentIndex + 1}/${totpCandidates.length} 個: ${candidate.code} (${candidate.description})`);

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
                $notification.post("1Min 登入", "TOTP 網路錯誤", error);
                $done();
            } else {
                console.log(`📊 TOTP 驗證回應狀態: ${response.status}`);

                try {
                    const responseData = JSON.parse(data || '{}');

                    if (response.status === 200) {
                        console.log(`✅ TOTP 驗證成功！使用了: ${candidate.code} (${candidate.description})`);
                        $notification.post("1Min 登入", "成功", `每日登入完成！TOTP: ${candidate.code}`);
                        $done();
                    } else {
                        console.log(`❌ TOTP 驗證失敗 - 狀態: ${response.status}`);

                        if (responseData.message) {
                            console.log(`📄 錯誤訊息: ${responseData.message}`);
                        }

                        // 如果是驗證碼錯誤且還有其他候選碼，繼續嘗試
                        if (response.status === 400 &&
                            responseData.message &&
                            responseData.message.includes('Invalid MFA code') &&
                            currentIndex < totpCandidates.length - 1) {

                            console.log(`⏭️ 嘗試下一個驗證碼...`);
                            currentIndex++;
                            setTimeout(attemptVerification, 1500); // 等待1.5秒後重試
                        } else {
                            let errorMsg = responseData.message || `HTTP ${response.status}`;
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
    attemptVerification();
}

// 開始執行
performLogin();
