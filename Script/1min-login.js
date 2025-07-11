// 1Min.ai 自動登入腳本 - Surge Module 版本
// 支援 TOTP 兩步驗證

// 從參數中取得設定
const params = new URLSearchParams($argument);
const email = params.get('email');
const password = params.get('password');
const totpSecret = params.get('totp'); // TOTP 金鑰（可選）

if (!email || !password) {
    console.log("❌ 錯誤: 缺少必要參數");
    $notification.post("1Min 登入", "設定錯誤", "請檢查 email 和 password 參數");
    $done();
}

// ===== TOTP 產生器 =====
function generateTOTP(secret) {
    if (!secret) return null;

    try {
        console.log("🔐 開始產生 TOTP...");

        // Base32 解碼
        function base32ToBytes(base32) {
            const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
            base32 = base32.replace(/\s/g, '').replace(/=+$/, '').toUpperCase();

            let bits = '';
            for (let i = 0; i < base32.length; i++) {
                const val = alphabet.indexOf(base32[i]);
                if (val === -1) throw new Error(`無效字元: ${base32[i]}`);
                bits += val.toString(2).padStart(5, '0');
            }

            const bytes = [];
            for (let i = 0; i + 8 <= bits.length; i += 8) {
                bytes.push(parseInt(bits.substr(i, 8), 2));
            }

            return new Uint8Array(bytes);
        }

        // SHA-1 實作
        function sha1(data) {
            function rotateLeft(n, b) {
                return (n << b) | (n >>> (32 - b));
            }

            let h0 = 0x67452301;
            let h1 = 0xEFCDAB89;
            let h2 = 0x98BADCFE;
            let h3 = 0x10325476;
            let h4 = 0xC3D2E1F0;

            const msgLength = data.length;
            const bitLength = msgLength * 8;

            const paddedData = Array.from(data);
            paddedData.push(0x80);

            while ((paddedData.length % 64) !== 56) {
                paddedData.push(0);
            }

            for (let i = 7; i >= 0; i--) {
                paddedData.push((bitLength >>> (i * 8)) & 0xff);
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

            const result = new Uint8Array(20);
            const hashes = [h0, h1, h2, h3, h4];
            for (let i = 0; i < 5; i++) {
                const h = hashes[i];
                result[i * 4] = (h >>> 24) & 0xff;
                result[i * 4 + 1] = (h >>> 16) & 0xff;
                result[i * 4 + 2] = (h >>> 8) & 0xff;
                result[i * 4 + 3] = h & 0xff;
            }

            return result;
        }

        // HMAC-SHA1 實作
        function hmacSha1(key, message) {
            const blockSize = 64;

            if (key.length > blockSize) {
                key = sha1(key);
            }

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

        // 計算 TOTP
        const timestamp = Math.floor(Date.now() / 1000);
        const timeStep = Math.floor(timestamp / 30);

        console.log(`⏰ 時間步: ${timeStep}`);

        const key = base32ToBytes(secret);
        console.log(`🔑 金鑰長度: ${key.length} bytes`);

        // 建立 8 bytes 的時間 counter (big-endian)
        const counter = new Uint8Array(8);
        counter[0] = (timeStep >>> 56) & 0xFF;
        counter[1] = (timeStep >>> 48) & 0xFF;
        counter[2] = (timeStep >>> 40) & 0xFF;
        counter[3] = (timeStep >>> 32) & 0xFF;
        counter[4] = (timeStep >>> 24) & 0xFF;
        counter[5] = (timeStep >>> 16) & 0xFF;
        counter[6] = (timeStep >>> 8) & 0xFF;
        counter[7] = timeStep & 0xFF;

        // 計算 HMAC-SHA1
        const hmac = hmacSha1(key, counter);

        // Dynamic Truncation
        const offset = hmac[hmac.length - 1] & 0xf;
        const code = ((hmac[offset] & 0x7f) << 24) |
                     ((hmac[offset + 1] & 0xff) << 16) |
                     ((hmac[offset + 2] & 0xff) << 8) |
                     (hmac[offset + 3] & 0xff);

        const totp = String(code % 1000000).padStart(6, '0');
        console.log(`🎯 產生 TOTP: ${totp}`);

        return totp;

    } catch (error) {
        console.log(`❌ TOTP 錯誤: ${error.message}`);
        return null;
    }
}

// ===== 登入流程 =====

// 產生隨機裝置 ID
function generateDeviceId() {
    const chars = '0123456789abcdef';
    let result = '';
    for (let i = 0; i < 16; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    const part1 = result;

    result = '';
    for (let i = 0; i < 15; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    const part2 = result;

    return `$device:${part1}-${part2}-17525636-16a7f0-${part1}`;
}

const deviceId = generateDeviceId();
console.log(`📱 裝置 ID: ${deviceId}`);

// 第一步：登入
function performLogin() {
    console.log("🚀 開始第一步登入...");

    const loginUrl = "https://api.1min.ai/auth/login";
    const headers = {
        "Host": "api.1min.ai",
        "Content-Type": "application/json",
        "X-Auth-Token": "Bearer",
        "Sec-Ch-Ua-Platform": "\"macOS\"",
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-Ch-Ua": "\"Not)A;Brand\";v=\"8\", \"Chromium\";v=\"138\"",
        "Mp-Identity": deviceId,
        "Sec-Ch-Ua-Mobile": "?0",
        "X-App-Version": "1.1.40",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "Origin": "https://app.1min.ai",
        "Sec-Fetch-Site": "same-site",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": "https://app.1min.ai/",
        "Accept-Encoding": "gzip, deflate, br",
        "Priority": "u=1, i"
    };

    const body = JSON.stringify({
        "email": email,
        "password": password
    });

    const request = {
        url: loginUrl,
        method: "POST",
        headers: headers,
        body: body
    };

    $httpClient.post(request, function(error, response, data) {
        if (error) {
            console.log(`❌ 登入請求失敗: ${error}`);
            $notification.post("1Min 登入", "網路錯誤", error);
            $done();
            return;
        }

        console.log(`📊 登入回應狀態: ${response.status}`);
        console.log(`📄 登入回應內容: ${data}`);

        try {
            const responseData = JSON.parse(data || '{}');

            if (response.status === 200 && responseData.user) {
                if (responseData.user.mfaRequired) {
                    console.log("🔐 需要 TOTP 驗證");
                    if (totpSecret) {
                        performMFAVerification(responseData.user.token);
                    } else {
                        console.log("❌ 需要 TOTP 但未提供金鑰");
                        $notification.post("1Min 登入", "需要 TOTP", "請在參數中新增 totp 金鑰");
                        $done();
                    }
                } else {
                    console.log("✅ 登入成功（無需 TOTP）");
                    $notification.post("1Min 登入", "成功", "每日登入完成");
                    $done();
                }
            } else {
                console.log(`❌ 登入失敗: ${data}`);
                $notification.post("1Min 登入", "登入失敗", `狀態: ${response.status}`);
                $done();
            }
        } catch (parseError) {
            console.log(`❌ JSON 解析錯誤: ${parseError}`);
            $notification.post("1Min 登入", "回應錯誤", "無法解析伺服器回應");
            $done();
        }
    });
}

// 第二步：TOTP 驗證
function performMFAVerification(tempToken) {
    console.log("🔐 開始 TOTP 驗證...");

    const totpCode = generateTOTP(totpSecret);

    if (!totpCode) {
        console.log("❌ TOTP 產生失敗");
        $notification.post("1Min 登入", "TOTP 錯誤", "無法產生驗證碼");
        $done();
        return;
    }

    console.log(`🎯 使用 TOTP 驗證碼: ${totpCode}`);

    const mfaUrl = "https://api.1min.ai/auth/mfa/verify";
    const headers = {
        "Host": "api.1min.ai",
        "Content-Type": "application/json",
        "X-Auth-Token": "Bearer",
        "Sec-Ch-Ua-Platform": "\"macOS\"",
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-Ch-Ua": "\"Not)A;Brand\";v=\"8\", \"Chromium\";v=\"138\"",
        "Mp-Identity": deviceId,
        "Sec-Ch-Ua-Mobile": "?0",
        "X-App-Version": "1.1.40",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "Origin": "https://app.1min.ai",
        "Sec-Fetch-Site": "same-site",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": "https://app.1min.ai/",
        "Accept-Encoding": "gzip, deflate, br",
        "Priority": "u=1, i"
    };

    const body = JSON.stringify({
        "code": totpCode,
        "token": tempToken
    });

    const request = {
        url: mfaUrl,
        method: "POST",
        headers: headers,
        body: body
    };

    $httpClient.post(request, function(error, response, data) {
        if (error) {
            console.log(`❌ TOTP 驗證請求失敗: ${error}`);
            $notification.post("1Min 登入", "TOTP 錯誤", error);
        } else {
            console.log(`📊 TOTP 驗證回應狀態: ${response.status}`);
            console.log(`📄 TOTP 驗證回應內容: ${data}`);

            if (response.status === 200) {
                console.log("✅ 完整登入成功");
                $notification.post("1Min 登入", "成功", "每日登入完成（含 TOTP）");
            } else {
                console.log(`❌ TOTP 驗證失敗: ${data}`);
                $notification.post("1Min 登入", "TOTP 失敗", "驗證碼可能不正確");
            }
        }
        $done();
    });
}

// 開始執行
console.log("🎬 1Min.ai 自動登入開始");
console.log(`📧 帳號: ${email}`);
console.log(`🔐 TOTP: ${totpSecret ? '已設定' : '未設定'}`);

performLogin();
