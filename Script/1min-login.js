// 1min-login-standard.js - 完全標準的 TOTP 實作

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

// ===== 完全標準的 TOTP 實作 =====
function generateTOTP(secret, timeOffset = 0) {
    if (!secret) return null;

    try {
        console.log(`🔐 開始產生 TOTP (偏移: ${timeOffset}s)...`);

        // 標準 Base32 解碼
        function base32Decode(encoded) {
            const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
            let cleanInput = encoded.replace(/\s/g, '').replace(/=+$/, '').toUpperCase();

            console.log(`📏 清理後金鑰長度: ${cleanInput.length}`);

            let bits = '';
            for (let i = 0; i < cleanInput.length; i++) {
                const char = cleanInput[i];
                const index = alphabet.indexOf(char);
                if (index === -1) {
                    throw new Error(`無效的 Base32 字元: ${char}`);
                }
                bits += index.toString(2).padStart(5, '0');
            }

            console.log(`🔢 總位元數: ${bits.length}`);

            const bytes = [];
            for (let i = 0; i < bits.length - 7; i += 8) {
                const byte = bits.substr(i, 8);
                if (byte.length === 8) {
                    bytes.push(parseInt(byte, 2));
                }
            }

            console.log(`🔑 解碼後位元組數: ${bytes.length}`);
            return new Uint8Array(bytes);
        }

        // 標準 SHA-1 實作（完全按照 RFC 3174）
        function sha1Hash(data) {
            // 初始雜湊值
            let h0 = 0x67452301;
            let h1 = 0xEFCDAB89;
            let h2 = 0x98BADCFE;
            let h3 = 0x10325476;
            let h4 = 0xC3D2E1F0;

            // 左旋轉
            function leftRotate(value, amount) {
                return (value << amount) | (value >>> (32 - amount));
            }

            // 預處理
            const originalLength = data.length;
            const message = Array.from(data);

            // 附加單一 '1' 位元
            message.push(0x80);

            // 填充到 512 位元的倍數減 64 位元
            while ((message.length % 64) !== 56) {
                message.push(0x00);
            }

            // 附加原始長度（以位元為單位，大端序 64 位元）
            const lengthInBits = originalLength * 8;
            for (let i = 7; i >= 0; i--) {
                message.push((lengthInBits >>> (i * 8)) & 0xFF);
            }

            // 處理 512 位元區塊
            for (let chunkStart = 0; chunkStart < message.length; chunkStart += 64) {
                const w = new Array(80);

                // 將區塊分解為 16 個 32 位元大端序字
                for (let i = 0; i < 16; i++) {
                    w[i] = (message[chunkStart + i * 4] << 24) |
                           (message[chunkStart + i * 4 + 1] << 16) |
                           (message[chunkStart + i * 4 + 2] << 8) |
                           message[chunkStart + i * 4 + 3];
                }

                // 擴展為 80 個字
                for (let i = 16; i < 80; i++) {
                    w[i] = leftRotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
                }

                // 初始化雜湊值
                let a = h0, b = h1, c = h2, d = h3, e = h4;

                // 主迴圈
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

                    const temp = (leftRotate(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF;
                    e = d;
                    d = c;
                    c = leftRotate(b, 30);
                    b = a;
                    a = temp;
                }

                // 加入到雜湊值
                h0 = (h0 + a) & 0xFFFFFFFF;
                h1 = (h1 + b) & 0xFFFFFFFF;
                h2 = (h2 + c) & 0xFFFFFFFF;
                h3 = (h3 + d) & 0xFFFFFFFF;
                h4 = (h4 + e) & 0xFFFFFFFF;
            }

            // 產生最終雜湊值（大端序）
            const hash = new Uint8Array(20);
            const hashValues = [h0, h1, h2, h3, h4];

            for (let i = 0; i < 5; i++) {
                const h = hashValues[i];
                hash[i * 4] = (h >>> 24) & 0xFF;
                hash[i * 4 + 1] = (h >>> 16) & 0xFF;
                hash[i * 4 + 2] = (h >>> 8) & 0xFF;
                hash[i * 4 + 3] = h & 0xFF;
            }

            return hash;
        }

        // 標準 HMAC-SHA1 實作
        function hmacSha1(key, message) {
            const blockSize = 64;

            // 如果金鑰比區塊大小長，就雜湊它
            if (key.length > blockSize) {
                key = sha1Hash(key);
            }

            // 如果金鑰比區塊大小短，就用零填充
            const keyPadded = new Uint8Array(blockSize);
            keyPadded.set(key);

            // 建立內部和外部填充金鑰
            const innerKeyPad = new Uint8Array(blockSize);
            const outerKeyPad = new Uint8Array(blockSize);

            for (let i = 0; i < blockSize; i++) {
                innerKeyPad[i] = keyPadded[i] ^ 0x36;
                outerKeyPad[i] = keyPadded[i] ^ 0x5C;
            }

            // 計算內部雜湊
            const innerData = new Uint8Array(blockSize + message.length);
            innerData.set(innerKeyPad);
            innerData.set(message, blockSize);
            const innerHash = sha1Hash(innerData);

            // 計算外部雜湊
            const outerData = new Uint8Array(blockSize + innerHash.length);
            outerData.set(outerKeyPad);
            outerData.set(innerHash, blockSize);

            return sha1Hash(outerData);
        }

        // 解碼 Base32 金鑰
        const key = base32Decode(secret);

        // 計算時間步數
        const currentTime = Math.floor(Date.now() / 1000) + timeOffset;
        const timeStep = Math.floor(currentTime / 30);

        console.log(`⏰ 當前時間: ${new Date((currentTime) * 1000).toLocaleTimeString()}`);
        console.log(`📊 時間步數: ${timeStep}`);

        // 將時間步數轉換為 8 位元組大端序
        const timeBytes = new Uint8Array(8);
        for (let i = 7; i >= 0; i--) {
            timeBytes[7 - i] = (timeStep >>> (i * 8)) & 0xFF;
        }

        console.log(`🕒 時間位元組: [${Array.from(timeBytes).map(b => '0x' + b.toString(16).padStart(2, '0')).join(', ')}]`);

        // 計算 HMAC-SHA1
        const hmac = hmacSha1(key, timeBytes);

        console.log(`🔐 HMAC 長度: ${hmac.length}`);
        console.log(`🔐 HMAC 前10位元組: [${Array.from(hmac.slice(0, 10)).map(b => '0x' + b.toString(16).padStart(2, '0')).join(', ')}]`);
        console.log(`🔐 HMAC 後10位元組: [${Array.from(hmac.slice(-10)).map(b => '0x' + b.toString(16).padStart(2, '0')).join(', ')}]`);

        // 動態截取
        const offset = hmac[hmac.length - 1] & 0x0F;
        console.log(`📍 動態偏移: ${offset}`);

        // 計算 TOTP 值
        const code = ((hmac[offset] & 0x7F) << 24) |
                     ((hmac[offset + 1] & 0xFF) << 16) |
                     ((hmac[offset + 2] & 0xFF) << 8) |
                     (hmac[offset + 3] & 0xFF);

        console.log(`🔢 31位元整數: ${code} (0x${code.toString(16)})`);

        const totp = String(code % 1000000).padStart(6, '0');
        console.log(`🎯 最終 TOTP: ${totp}`);

        return {
            code: totp,
            timeStep: timeStep,
            offset: offset,
            timestamp: currentTime
        };

    } catch (error) {
        console.log(`❌ TOTP 產生錯誤: ${error.message}`);
        return null;
    }
}

// ===== 嘗試多個時間窗 =====
function generateTOTPCandidates(secret) {
    console.log("🔄 產生多個時間窗的 TOTP...");

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
                $notification.post("1Min 登入", "登入失敗", `HTTP ${response.status}`);
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
        console.log(`🎯 嘗試第 ${currentIndex + 1}/${totpCandidates.length} 個驗證碼: ${candidate.code} (${candidate.description})`);

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
                        console.log(`✅ TOTP 驗證成功！成功的驗證碼: ${candidate.code} (${candidate.description})`);
                        $notification.post("1Min 登入", "成功", `每日登入完成！TOTP: ${candidate.code}`);
                        $done();
                    } else {
                        console.log(`❌ TOTP 驗證失敗 - 狀態: ${response.status}`);

                        if (responseData.message) {
                            console.log(`📄 錯誤訊息: ${responseData.message}`);
                        }

                        // 如果是無效驗證碼且還有其他候選碼，繼續嘗試
                        if (response.status === 400 && currentIndex < totpCandidates.length - 1) {
                            console.log(`⏭️ 嘗試下一個驗證碼...`);
                            currentIndex++;
                            setTimeout(attemptVerification, 1500); // 等待1.5秒後重試
                        } else {
                            $notification.post("1Min 登入", "TOTP 失敗", responseData.message || `HTTP ${response.status}`);
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
