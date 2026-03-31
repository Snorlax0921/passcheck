import hashlib
import math
import os
import re

import requests
from flask import Flask, render_template, request

app = Flask(__name__)


# 計算密碼的熵值（entropy）
# 熵值越高，代表密碼越難被猜到
def password_entropy(password):
    charset = 0
    if re.search(r'[a-z]', password):
        charset += 26  # 小寫字母有 26 種
    if re.search(r'[A-Z]', password):
        charset += 26  # 大寫字母有 26 種
    if re.search(r'\d', password):
        charset += 10  # 數字有 10 種
    if re.search(r'[^A-Za-z0-9]', password):
        charset += 32  # 特殊符號約 32 種
    if charset == 0:
        return 0
    return round(len(password) * math.log2(charset), 2)


# 預估破解時間（假設攻擊者每秒可以嘗試 10 億次）
def estimate_crack_time(entropy_bits):
    guesses_per_second = 10**9  # 每秒 10 億次猜測
    if entropy_bits == 0:
        return '立刻被破解'
    seconds = (2 ** entropy_bits) / guesses_per_second
    if seconds < 60:
        return '幾秒內'
    if seconds < 3600:
        return f'約 {int(seconds // 60)} 分鐘'
    if seconds < 86400:
        return f'約 {int(seconds // 3600)} 小時'
    if seconds < 365 * 86400:
        return f'約 {int(seconds // 86400)} 天'
    if seconds < 100 * 365 * 86400:
        return f'約 {int(seconds // (365 * 86400))} 年'
    return '非常非常久（幾乎無法破解）'


# 常見的弱密碼清單
COMMON_PASSWORDS = {
    '123456', 'password', 'qwerty', '111111', 'abc123',
    '12345678', 'admin', 'letmein', 'welcome', 'iloveyou'
}


# 把密碼丟進去分析，算出分數和給使用者的建議
def analyze_password(password):
    score = 0
    tips = []  # 給使用者的改善建議

    # 長度檢查
    if len(password) >= 8:
        score += 20
    else:
        tips.append('長度太短，至少要 8 個字元')

    if len(password) >= 12:
        score += 15
    else:
        tips.append('建議長度至少 12 個字元會更安全')

    # 字元種類檢查
    if re.search(r'[a-z]', password):
        score += 15
    else:
        tips.append('加入小寫字母（a-z）')

    if re.search(r'[A-Z]', password):
        score += 15
    else:
        tips.append('加入大寫字母（A-Z）')

    if re.search(r'\d', password):
        score += 15
    else:
        tips.append('加入數字（0-9）')

    if re.search(r'[^A-Za-z0-9]', password):
        score += 20
    else:
        tips.append('加入特殊符號（如 !@#$%）')

    # 弱密碼扣分
    if password.lower() in COMMON_PASSWORDS:
        score -= 30
        tips.append('這是常見的弱密碼，請換一個')

    # 重複字元扣分
    if re.search(r'(.)\1\1', password):
        score -= 10
        tips.append('避免連續重複同一個字元（如 aaa、111）')

    # 分數限制在 0~100
    score = max(0, min(100, score))

    # 決定等級
    if score >= 80:
        level = '強'
    elif score >= 50:
        level = '中'
    else:
        level = '弱'

    entropy = password_entropy(password)
    crack_time = estimate_crack_time(entropy)

    return {
        'score': score,
        'level': level,
        'entropy': entropy,
        'crack_time': crack_time,
        'tips': tips if tips else ['密碼設計不錯！'],
    }


# 查詢密碼有沒有外洩過，用 HaveIBeenPwned API
# 只傳 SHA-1 雜湊的前 5 碼，剩下本地比對，密碼不會傳出去
def check_pwned(password):
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1[:5]   # 只傳前 5 碼給 API
    suffix = sha1[5:]   # 剩下的在本地比對
    try:
        resp = requests.get(
            f'https://api.pwnedpasswords.com/range/{prefix}',
            timeout=5
        )
        for line in resp.text.splitlines():
            h, count = line.split(':')
            if h == suffix:
                return int(count)  # 回傳外洩次數
    except Exception:
        return None  # 網路問題或 API 無法連線時回傳 None
    return 0  # 0 代表未在外洩資料庫中找到


@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    password = ''
    if request.method == 'POST':
        password = request.form.get('password', '')
        if password:
            result = analyze_password(password)
            result['pwned'] = check_pwned(password)
    return render_template('index.html', result=result, password=password)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)
