// 1min.ai 每日自動登入腳本
// 從參數中獲取帳號密碼
const params = new URLSearchParams($argument);
const email = params.get('email');
const password = params.get('password');

if (!email || !password) {
    console.log("錯誤: 缺少帳號或密碼參數");
    $notification.post("1min.ai 登入", "設定錯誤", "請檢查帳號密碼設定");
    $done();
    return;
}

const url = "https://api.1min.ai/auth/login";
const headers = {
    "Host": "api.1min.ai",
    "Content-Type": "application/json",
    "X-Auth-Token": "Bearer",
    "Sec-Ch-Ua-Platform": "\"macOS\"",
    "Accept-Language": "en-US,en;q=0.9",
    "Sec-Ch-Ua": "\"Not)A;Brand\";v=\"8\", \"Chromium\";v=\"138\"",
    "Mp-Identity": "$device:197f8012d19258-0fae27400ab0828-17525636-16a7f0-197f8012d19258",
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
    url: url,
    method: "POST",
    headers: headers,
    body: body
};

$httpClient.post(request, function(error, response, data) {
    if (error) {
        console.log("登入失敗: " + error);
        $notification.post("1min.ai 登入", "失敗", error);
    } else {
        console.log("登入回應: " + response.status);
        const responseData = JSON.parse(data || '{}');

        if (response.status == 200) {
            console.log("登入成功: " + data);
            $notification.post("1min.ai 登入", "成功", "每日登入完成");
        } else {
            console.log("登入失敗: " + data);
            $notification.post("1min.ai 登入", "失敗", "狀態碼: " + response.status);
        }
    }
    $done();
});
