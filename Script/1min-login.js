// 1min.ai 每日自動登入腳本（含完整 TOTP 實作）
// 從參數中取得帳號密碼和可選的 TOTP 金鑰
const params = new URLSearchParams($argument);
const email = params.get('email');
const password = params.get('password');
const totpSecret = params.get('totp'); // 可選

if (!email || !password) {
    console.log("錯誤: 缺少帳號或密碼參數");
    $notification.post("1Min 登入", "設定錯誤", "請檢查帳號密碼設定");
    $done();
} else {
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
    console.log("使用裝置 ID: " + deviceId);

    // Base32 解碼函式
    function base32Decode(base32) {
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        let bits = '';

        // 移除空格並轉換為大寫
        base32 = base32.replace(/\s/g, '').toUpperCase();

        // 轉換每個字元為5位元二進位
        for (let i = 0; i < base32.length; i++) {
            const char = base32.charAt(i);
            const index = alphabet.indexOf(char);
            if (index === -1) {
                if (char === '=') break; // 遇到填充字元就停止
                continue; // 跳過無效字元
            }
            bits += index.toString(2).padStart(5, '0');
        }

        // 轉換為位元組陣列
        const bytes = [];
        for (let i = 0; i < bits.length; i += 8) {
            const byte = bits.substr(i, 8);
            if (byte.length === 8) {
                bytes.push(parseInt(byte, 2));
            }
        }

        return new Uint8Array(bytes);
    }

    // SHA-1 實作
    function sha1(data) {
        function rotateLeft(n, s) {
            return (n << s) | (n >>> (32 - s));
        }

        function addUnsigned(x, y) {
            return ((x & 0x7FFFFFFF) + (y & 0x7FFFFFFF)) ^ (x & 0x80000000) ^ (y & 0x80000000);
        }

        // 轉換為32位元字詞陣列
        let message = [];
        for (let i = 0; i < data.length; i += 4) {
            message.push(
                ((data[i] || 0) << 24) |
                ((data[i + 1] || 0) << 16) |
                ((data[i + 2] || 0) << 8) |
                (data[i + 3] || 0)
            );
        }

        // 加入填充
        let messageBitLength = data.length * 8;
        message.push(0x80000000);

        while ((message.length % 16) != 14) {
            message.push(0);
        }

        message.push(messageBitLength >>> 32);
        message.push(messageBitLength & 0xFFFFFFFF);

        // 初始化雜湊值
        let h0 = 0x67452301;
        let h1 = 0xEFCDAB89;
        let h2 = 0x98BADCFE;
        let h3 = 0x10325476;
        let h4 = 0xC3D2E1F0;

        // 處理每個512位元區塊
        for (let i = 0; i < message.length; i += 16) {
            let w = message.slice(i, i + 16);

            // 擴展到80個字詞
            for (let j = 16; j < 80; j++) {
                w[j] = rotateLeft(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
            }

            let a = h0, b = h1, c = h2, d = h3, e = h4;

            for (let j = 0; j < 80; j++) {
                let f, k;
                if (j < 20) {
                    f = (b & c) | ((~b) & d);
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

                let temp = addUnsigned(addUnsigned(rotateLeft(a, 5), f), addUnsigned(addUnsigned(e, w[j]), k));
                e = d;
                d = c;
                c = rotateLeft(b, 30);
                b = a;
                a = temp;
            }

            h0 = addUnsigned(h0, a);
            h1 = addUnsigned(h1, b);
            h2 = addUnsigned(h2, c);
            h3 = addUnsigned(h3, d);
            h4 = addUnsigned(h4, e);
        }

        // 轉換為位元組陣列
        const result = new Uint8Array(20);
        for (let i = 0; i < 5; i++) {
            const h = [h0, h1, h2, h3, h4][i];
            result[i * 4] = (h >>> 24) & 0xFF;
            result[i * 4 + 1] = (h >>> 16) & 0xFF;
            result[i * 4 + 2] = (h >>> 8) & 0xFF;
            result[i * 4 + 3] = h & 0xFF;
        }

        return result;
    }

    // HMAC-SHA1 實作
    function hmacSha1(key, message) {
        const blockSize = 64;

        // 若金鑰長度超過區塊大小，先進行雜湊
        if (key.length > blockSize) {
            key = sha1(key);
        }

        // 建立填充後的金鑰
        const keyPadded = new Uint8Array(blockSize);
        keyPadded.set(key);

        // 建立內外填充
        const ipad = new Uint8Array(blockSize);
        const opad = new Uint8Array(blockSize);

        for (let i = 0; i < blockSize; i++) {
            ipad[i] = keyPadded[i] ^ 0x36;
            opad[i] = keyPadded[i] ^ 0x5C;
        }

        // 計算 HMAC
        const innerHash = sha1(new Uint8Array([...ipad, ...message]));
        return sha1(new Uint8Array([...opad, ...innerHash]));
    }

    // TOTP 產生函式
    function generateTOTP(secret, timeStep = 30, digits = 6) {
        try {
            // 解碼 Base32 金鑰
            const key = base32Decode(secret);

            // 計算時間步數
            const time = Math.floor(Date.now() / 1000 / timeStep);

            // 轉換時間為 8 位元組大端序
            const timeBytes = new Uint8Array(8);
            for (let i = 7; i >= 0; i--) {
                timeBytes[i] = time & 0xFF;
                time >>>= 8;
            }

            // 計算 HMAC-SHA1
            const hash = hmacSha1(key, timeBytes);

            // 動態截取
            const offset = hash[hash.length - 1] & 0x0F;
            const code = ((hash[offset] & 0x7F) << 24) |
                        ((hash[offset + 1] & 0xFF) << 16) |
                        ((hash[offset + 2] & 0xFF) << 8) |
                        (hash[offset + 3] & 0xFF);

            // 產生最終驗證碼
            const otp = code % Math.pow(10, digits);
            return otp.toString().padStart(digits, '0');

        } catch (error) {
            console.log("TOTP 產生錯誤: " + error.message);
            return null;
        }
    }

    // 第一步：登入
    function performLogin() {
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
                console.log("登入失敗: " + error);
                $notification.post("1Min 登入", "失敗", error);
                $done();
            } else {
                console.log("第一步登入回應: " + response.status);
                console.log("回應內容: " + data);

                try {
                    const responseData = JSON.parse(data || '{}');

                    if (response.status == 200 && responseData.user) {
                        // 檢查是否需要 TOTP 驗證
                        if (responseData.user.mfaRequired && totpSecret) {
                            console.log("需要 TOTP 驗證，開始第二步");
                            performMFAVerification(responseData.user.token);
                        } else if (responseData.user.mfaRequired && !totpSecret) {
                            console.log("需要 TOTP 但未提供金鑰");
                            $notification.post("1Min 登入", "需要 TOTP", "請在參數中新增 totp 金鑰");
                            $done();
                        } else {
                            // 不需要 TOTP 或已完成登入
                            console.log("登入成功，無需 TOTP: " + data);
                            $notification.post("1Min 登入", "成功", "每日登入完成");
                            $done();
                        }
                    } else {
                        console.log("登入失敗: " + data);
                        $notification.post("1Min 登入", "失敗", "狀態碼: " + response.status);
                        $done();
                    }
                } catch (parseError) {
                    console.log("JSON 解析錯誤: " + parseError);
                    $notification.post("1Min 登入", "解析錯誤", "回應格式異常");
                    $done();
                }
            }
        });
    }

    // 第二步：TOTP 驗證
    function performMFAVerification(tempToken) {
        if (!totpSecret) {
            console.log("未提供 TOTP 金鑰");
            $notification.post("1Min 登入", "TOTP 錯誤", "未提供 TOTP 金鑰");
            $done();
            return;
        }

        const totpCode = generateTOTP(totpSecret);

        if (!totpCode) {
            console.log("TOTP 產生失敗");
            $notification.post("1Min 登入", "TOTP 失敗", "無法產生驗證碼");
            $done();
            return;
        }

        console.log("產生的 TOTP 驗證碼: " + totpCode);

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
                console.log("TOTP 驗證失敗: " + error);
                $notification.post("1Min 登入", "TOTP 失敗", error);
            } else {
                console.log("TOTP 驗證回應: " + response.status);
                console.log("TOTP 驗證回應內容: " + data);

                if (response.status == 200) {
                    console.log("完整登入成功: " + data);
                    $notification.post("1Min 登入", "成功", "每日登入完成 (含 TOTP)");
                } else {
                    console.log("TOTP 驗證失敗: " + data);
                    $notification.post("1Min 登入", "TOTP 失敗", "驗證碼可能過期");
                }
            }
            $done();
        });
    }

    // 開始登入流程
    performLogin();
}
