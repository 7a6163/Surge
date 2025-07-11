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

    // 完整的 TOTP 實作（從巴哈姆特腳本移植）
    function TOTP(token) {
        function t(e, a, d) {
            var g = 0,
                c = [],
                b = 0,
                f, k, l, h, m, w, n, y, p = !1,
                q = [],
                t = [],
                v, u = !1;
            d = d || {};
            f = d.encoding || "UTF8";
            v = d.numRounds || 1;
            l = z(a, f);
            if (v !== parseInt(v, 10) || 1 > v) throw Error("numRounds must a integer >= 1");
            if ("SHA-1" === e) m = 512, w = A, n = H, h = 160, y = function(a) {
                return a.slice()
            };
            else throw Error("Chosen SHA variant is not supported");
            k = x(e);
            this.setHMACKey = function(a, b, c) {
                var d;
                if (!0 === p) throw Error("HMAC key already set");
                if (!0 === u) throw Error("Cannot set HMAC key after calling update");
                f = (c || {}).encoding || "UTF8";
                b = z(b, f)(a);
                a = b.binLen;
                b = b.value;
                d = m >>> 3;
                c = d / 4 - 1;
                if (d < a / 8) {
                    for (b = n(b, a, 0, x(e), h); b.length <= c;) b.push(0);
                    b[c] &= 4294967040
                } else if (d > a / 8) {
                    for (; b.length <= c;) b.push(0);
                    b[c] &= 4294967040
                }
                for (a = 0; a <= c; a += 1) q[a] = b[a] ^ 909522486, t[a] = b[a] ^ 1549556828;
                k = w(q, k);
                g = m;
                p = !0
            };
            this.update = function(a) {
                var d, e, f, h = 0,
                    n = m >>> 5;
                d = l(a, c, b);
                a = d.binLen;
                e = d.value;
                d = a >>> 5;
                for (f = 0; f < d; f += n) h + m <= a && (k = w(e.slice(f, f + n), k), h += m);
                g += h;
                c = e.slice(h >>> 5);
                b = a % m;
                u = !0
            };
            this.getHash = function(a, d) {
                var f, l, m, r;
                if (!0 === p) throw Error("Cannot call getHash after setting HMAC key");
                m = B(d);
                switch (a) {
                    case "HEX":
                        f = function(a) {
                            return C(a, h, m)
                        };
                        break;
                    case "B64":
                        f = function(a) {
                            return D(a, h, m)
                        };
                        break;
                    case "BYTES":
                        f = function(a) {
                            return E(a, h)
                        };
                        break;
                    case "ARRAYBUFFER":
                        try {
                            l = new ArrayBuffer(0)
                        } catch (I) {
                            throw Error("ARRAYBUFFER not supported by this environment");
                        }
                        f = function(a) {
                            return F(a, h)
                        };
                        break;
                    default:
                        throw Error("format must be HEX, B64, BYTES, or ARRAYBUFFER");
                }
                r = n(c.slice(), b, g, y(k), h);
                for (l = 1; l < v; l += 1) r = n(r, h, 0, x(e), h);
                return f(r)
            };
            this.getHMAC = function(a, d) {
                var f, l, q, r;
                if (!1 === p) throw Error("Cannot call getHMAC without first setting HMAC key");
                q = B(d);
                switch (a) {
                    case "HEX":
                        f = function(a) {
                            return C(a, h, q)
                        };
                        break;
                    case "B64":
                        f = function(a) {
                            return D(a, h, q)
                        };
                        break;
                    case "BYTES":
                        f = function(a) {
                            return E(a, h)
                        };
                        break;
                    case "ARRAYBUFFER":
                        try {
                            f = new ArrayBuffer(0)
                        } catch (I) {
                            throw Error("ARRAYBUFFER not supported by this environment");
                        }
                        f = function(a) {
                            return F(a, h)
                        };
                        break;
                    default:
                        throw Error("outputFormat must be HEX, B64, BYTES, or ARRAYBUFFER");
                }
                l = n(c.slice(), b, g, y(k), h);
                r = w(t, x(e));
                r = n(l, h, m, r, h);
                return f(r)
            }
        }

        function J(e, a, d) {
            var g = e.length,
                c, b, f, k, l;
            a = a || [0];
            d = d || 0;
            l = d >>> 3;
            if (0 !== g % 2) throw Error("String of HEX type must be in byte increments");
            for (c = 0; c < g; c += 2) {
                b = parseInt(e.substr(c, 2), 16);
                if (isNaN(b)) throw Error("String of HEX type contains invalid characters");
                k = (c >>> 1) + l;
                for (f = k >>> 2; a.length <= f;) a.push(0);
                a[f] |= b << 8 * (3 - k % 4)
            }
            return {
                value: a,
                binLen: 4 * g + d
            }
        }

        function K(e, a, d) {
            var g = [],
                c, b, f, k, g = a || [0];
            d = d || 0;
            b = d >>> 3;
            for (c = 0; c < e.length; c += 1) a = e.charCodeAt(c), k = c + b, f = k >>> 2, g.length <= f && g.push(0), g[f] |= a << 8 * (3 - k % 4);
            return {
                value: g,
                binLen: 8 * e.length + d
            }
        }

        function L(e, a, d) {
            var g = [],
                c = 0,
                b, f, k, l, h, m, g = a || [0];
            d = d || 0;
            a = d >>> 3;
            if (-1 === e.search(/^[a-zA-Z0-9=+\/]+$/)) throw Error("Invalid character in base-64 string");
            f = e.indexOf("=");
            e = e.replace(/\=/g, "");
            if (-1 !== f && f < e.length) throw Error("Invalid '=' found in base-64 string");
            for (f = 0; f < e.length; f += 4) {
                h = e.substr(f, 4);
                for (k = l = 0; k < h.length; k += 1) b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".indexOf(h[k]), l |= b << 18 - 6 * k;
                for (k = 0; k < h.length - 1; k += 1) {
                    m = c + a;
                    for (b = m >>> 2; g.length <= b;) g.push(0);
                    g[b] |= (l >>> 16 - 8 * k & 255) << 8 * (3 - m % 4);
                    c += 1
                }
            }
            return {
                value: g,
                binLen: 8 * c + d
            }
        }

        function M(e, a, d) {
            var g = [],
                c, b, f, g = a || [0];
            d = d || 0;
            c = d >>> 3;
            for (a = 0; a < e.byteLength; a += 1) f = a + c, b = f >>> 2, g.length <= b && g.push(0), g[b] |= e[a] << 8 * (3 - f % 4);
            return {
                value: g,
                binLen: 8 * e.byteLength + d
            }
        }

        function C(e, a, d) {
            var g = "";
            a /= 8;
            var c, b;
            for (c = 0; c < a; c += 1) b = e[c >>> 2] >>> 8 * (3 - c % 4), g += "0123456789abcdef".charAt(b >>> 4 & 15) + "0123456789abcdef".charAt(b & 15);
            return d.outputUpper ? g.toUpperCase() : g
        }

        function D(e, a, d) {
            var g = "",
                c = a / 8,
                b, f, k;
            for (b = 0; b < c; b += 3)
                for (f = b + 1 < c ? e[b + 1 >>> 2] : 0, k = b + 2 < c ? e[b + 2 >>> 2] : 0, k = (e[b >>> 2] >>> 8 * (3 - b % 4) & 255) << 16 | (f >>> 8 * (3 - (b + 1) % 4) & 255) << 8 | k >>> 8 * (3 - (b + 2) % 4) & 255, f = 0; 4 > f; f += 1) 8 * b + 6 * f <= a ? g += "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt(k >>> 6 * (3 - f) & 63) : g += d.b64Pad;
            return g
        }

        function E(e, a) {
            var d = "",
                g = a / 8,
                c, b;
            for (c = 0; c < g; c += 1) b = e[c >>> 2] >>> 8 * (3 - c % 4) & 255, d += String.fromCharCode(b);
            return d
        }

        function F(e, a) {
            var d = a / 8,
                g, c = new ArrayBuffer(d);
            for (g = 0; g < d; g += 1) c[g] = e[g >>> 2] >>> 8 * (3 - g % 4) & 255;
            return c
        }

        function B(e) {
            var a = {
                outputUpper: !1,
                b64Pad: "=",
                shakeLen: -1
            };
            e = e || {};
            a.outputUpper = e.outputUpper || !1;
            !0 === e.hasOwnProperty("b64Pad") && (a.b64Pad = e.b64Pad);
            if ("boolean" !== typeof a.outputUpper) throw Error("Invalid outputUpper formatting option");
            if ("string" !== typeof a.b64Pad) throw Error("Invalid b64Pad formatting option");
            return a
        }

        function z(e, a) {
            var d;
            switch (a) {
                case "UTF8":
                case "UTF16BE":
                case "UTF16LE":
                    break;
                default:
                    throw Error("encoding must be UTF8, UTF16BE, or UTF16LE");
            }
            switch (e) {
                case "HEX":
                    d = J;
                    break;
                case "TEXT":
                    d = function(d, c, b) {
                        var f = [],
                            e = [],
                            l = 0,
                            h, m, q, n, p, f = c || [0];
                        c = b || 0;
                        q = c >>> 3;
                        if ("UTF8" === a)
                            for (h = 0; h < d.length; h += 1)
                                for (b = d.charCodeAt(h), e = [], 128 > b ? e.push(b) : 2048 > b ? (e.push(192 | b >>> 6), e.push(128 | b & 63)) : 55296 > b || 57344 <= b ? e.push(224 | b >>> 12, 128 | b >>> 6 & 63, 128 | b & 63) : (h += 1, b = 65536 + ((b & 1023) << 10 | d.charCodeAt(h) & 1023), e.push(240 | b >>> 18, 128 | b >>> 12 & 63, 128 | b >>> 6 & 63, 128 | b & 63)), m = 0; m < e.length; m += 1) {
                                    p = l + q;
                                    for (n = p >>> 2; f.length <= n;) f.push(0);
                                    f[n] |= e[m] << 8 * (3 - p % 4);
                                    l += 1
                                } else if ("UTF16BE" === a || "UTF16LE" === a)
                                for (h = 0; h < d.length; h += 1) {
                                    b = d.charCodeAt(h);
                                    "UTF16LE" === a && (m = b & 255, b = m << 8 | b >>> 8);
                                    p = l + q;
                                    for (n = p >>> 2; f.length <= n;) f.push(0);
                                    f[n] |= b << 8 * (2 - p % 4);
                                    l += 2
                                }
                        return {
                            value: f,
                            binLen: 8 * l + c
                        }
                    };
                    break;
                case "B64":
                    d = L;
                    break;
                case "BYTES":
                    d = K;
                    break;
                case "ARRAYBUFFER":
                    try {
                        d = new ArrayBuffer(0)
                    } catch (g) {
                        throw Error("ARRAYBUFFER not supported by this environment");
                    }
                    d = M;
                    break;
                default:
                    throw Error("format must be HEX, TEXT, B64, BYTES, or ARRAYBUFFER");
            }
            return d
        }

        function p(e, a) {
            return e << a | e >>> 32 - a
        }

        function q(e, a) {
            var d = (e & 65535) + (a & 65535);
            return ((e >>> 16) + (a >>> 16) + (d >>> 16) & 65535) << 16 | d & 65535
        }

        function u(e, a, d, g, c) {
            var b = (e & 65535) + (a & 65535) + (d & 65535) + (g & 65535) + (c & 65535);
            return ((e >>> 16) + (a >>> 16) + (d >>> 16) + (g >>> 16) + (c >>> 16) + (b >>> 16) & 65535) << 16 | b & 65535
        }

        function x(e) {
            var a = [];
            if ("SHA-1" === e) a = [1732584193, 4023233417, 2562383102, 271733878, 3285377520];
            else throw Error("No SHA variants supported");
            return a
        }

        function A(e, a) {
            var d = [],
                g, c, b, f, k, l, h;
            g = a[0];
            c = a[1];
            b = a[2];
            f = a[3];
            k = a[4];
            for (h = 0; 80 > h; h += 1) d[h] = 16 > h ? e[h] : p(d[h - 3] ^ d[h - 8] ^ d[h - 14] ^ d[h - 16], 1), l = 20 > h ? u(p(g, 5), c & b ^ ~c & f, k, 1518500249, d[h]) : 40 > h ? u(p(g, 5), c ^ b ^ f, k, 1859775393, d[h]) : 60 > h ? u(p(g, 5), c & b ^ c & f ^ b & f, k, 2400959708, d[h]) : u(p(g, 5), c ^ b ^ f, k, 3395469782, d[h]), k = f, f = b, b = p(c, 30), c = g, g = l;
            a[0] = q(g, a[0]);
            a[1] = q(c, a[1]);
            a[2] = q(b, a[2]);
            a[3] = q(f, a[3]);
            a[4] = q(k, a[4]);
            return a
        }

        function H(e, a, d, g) {
            var c;
            for (c = (a + 65 >>> 9 << 4) + 15; e.length <= c;) e.push(0);
            e[a >>> 5] |= 128 << 24 - a % 32;
            a += d;
            e[c] = a & 4294967295;
            e[c - 1] = a / 4294967296 | 0;
            a = e.length;
            for (c = 0; c < a; c += 16) g = A(e.slice(c, c + 16), g);
            return g
        }

        function dec2hex(s) {
            return (s < 15.5 ? '0' : '') + Math.round(s).toString(16)
        }

        function hex2dec(s) {
            return parseInt(s, 16)
        }

        function base32tohex(base32) {
            var base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            var bits = "";
            var hex = "";
            for (var i = 0; i < base32.length; i++) {
                var val = base32chars.indexOf(base32.charAt(i).toUpperCase());
                bits += leftpad(val.toString(2), 5, '0')
            }
            for (var i = 0; i + 4 <= bits.length; i += 4) {
                var chunk = bits.substr(i, 4);
                hex = hex + parseInt(chunk, 2).toString(16)
            }
            return hex
        }

        function leftpad(str, len, pad) {
            if (len + 1 >= str.length) {
                str = Array(len + 1 - str.length).join(pad) + str
            }
            return str
        }

        function getCode(secret) {
            var key = base32tohex(secret);
            var epoch = Math.round(new Date().getTime() / 1000.0);
            var time = leftpad(dec2hex(Math.floor(epoch / 30)), 16, '0');
            var shaObj = new t("SHA-1", "HEX");
            shaObj.setHMACKey(key, "HEX");
            shaObj.update(time);
            var hmac = shaObj.getHMAC("HEX");
            var offset = hex2dec(hmac.substring(hmac.length - 1));
            var otp = (hex2dec(hmac.substr(offset * 2, 8)) & hex2dec('7fffffff')) + '';
            otp = (otp).substr(otp.length - 6, 6);
            return otp
        };
        const res = getCode(token);
        return res
    };

    // TOTP 產生函式
    function generateTOTP(secret) {
        try {
            if (!secret) return null;
            return TOTP(secret);
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
