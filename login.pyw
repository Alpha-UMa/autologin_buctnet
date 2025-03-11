import requests
import time
import sys
import json
from win10toast import ToastNotifier

# 配置参数
# 用户登录凭证
username = 'username'  # 请修改为自己的账号
password = 'password'  # 请修改为自己的密码
MAX_RETRIES = 13  # 最大重试次数
RETRY_INTERVAL = 5  # 重试等待时间
AUTH_BASE_URL = 'https://tree.buct.edu.cn'  # 校园网认证地址
INTERNET_CHECK_URL = 'https://www.baidu.com'  # 网络状态检测地址

# ================ 复刻网站js的加密算法 ================
import hmac
import hashlib

def custom_md5(password, token):
    md5_hash = hmac.new(token.encode('utf-8'), password.encode('utf-8'), hashlib.md5).hexdigest()
    return md5_hash  # 使用token作为密钥，通过HMAC生成密码MD5哈希

def sha1(data):
    return hashlib.sha1(data.encode('utf-8')).hexdigest()  # 生成SHA1哈希


def s(a, b):
    c = len(a)
    v = []
    for i in range(0, c, 4):
        idx = i >> 2
        while len(v) <= idx:
            v.append(0)
        char_at_i = ord(a[i]) if i < c else 0
        char_at_i_plus_1 = ord(a[i + 1]) if i + 1 < c else 0
        char_at_i_plus_2 = ord(a[i + 2]) if i + 2 < c else 0
        char_at_i_plus_3 = ord(a[i + 3]) if i + 3 < c else 0
        value = char_at_i | (char_at_i_plus_1 << 8) | (char_at_i_plus_2 << 16) | (char_at_i_plus_3 << 24)
        if value > 0x7FFFFFFF:
            value = value - 0x100000000
        v[idx] = value
    if b:
        v.append(c)
    return v  # 生成数组v

def ss(a, b):
    v = []
    for i in range(0, len(a), 4):
        val = 0
        for j in range(4):
            if i + j < len(a):
                val |= ord(a[i + j]) << (j * 8)
        v.append(val & 0xFFFFFFFF)
    if b:
        v.append(len(a) & 0xFFFFFFFF)
    return v  # 生成数组k

def l(a, b):
    result = []
    for x in a:
        x = x & 0xFFFFFFFF
        bytes_part = [
            x & 0xFF,
            (x >> 8) & 0xFF,
            (x >> 16) & 0xFF,
            (x >> 24) & 0xFF,
        ]
        chars = ''.join([chr(b) for b in bytes_part if b != 0])
        result.append(chars)
    s_joined = ''.join(result)
    if b:
        if not a:
            return ''
        c = (len(a) - 1) * 4
        m = a[-1]
        if m > c:
            return s_joined[:c]
        return s_joined[:m]
    return s_joined

def encode(s_str, s_key):
    if s_str == '':
        return '', []
    v = s(s_str, True)
    k = ss(s_key, False)
    if len(k) < 4:
        k = k + [0] * (4 - len(k))
    n = len(v) - 1
    z = v[n]
    y = v[0]
    c = 0x86014019 | 0x183639A0
    q = int(6 + 52 / (n + 1))
    d = 0
    while q > 0:
        q -= 1
        d = (d + c) & (0x8CE0D9BF | 0x731F2640)
        e = (d >> 2) & 3
        for p in range(n):
            y = v[p + 1]
            m = (z >> 5) ^ (y << 2)
            m += (y >> 3) ^ (z << 4) ^ (d ^ y)
            m += k[(p & 3) ^ e] ^ z
            z = v[p] = (v[p] + m) & (0xEFB8D130 | 0x10472ECF)
        y = v[0]
        m = (z >> 5) ^ (y << 2)
        m += (y >> 3) ^ (z << 4) ^ (d ^ y)
        m += k[(p + 1) & 3 ^ e] ^ z
        z = v[n] = (v[n] + m) & (0xBB390742 | 0x44C6F8BD)
    return l(v, False)

class CustomBase64:
    # Base64 编码与解码函数
    def __init__(self):
        self._PADCHAR = "="
        # 自定义 Base64 字符集
        self._ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
    
    def _getbyte64(self, s, i):
        idx = self._ALPHA.find(s[i])
        if idx == -1:
            raise ValueError("Cannot decode base64")
        return idx  # 获取字符对应的索引
    
    def decode(self, s):
        pads = 0
        imax = len(s)
        x = []
        s = str(s)
        if imax == 0:
            return s
        if imax % 4 != 0:
            raise ValueError("Cannot decode base64")
        if s[imax - 1] == self._PADCHAR:
            pads = 1
            if s[imax - 2] == self._PADCHAR:
                pads = 2
            imax -= 4
        i = 0
        while i < imax:
            b10 = (self._getbyte64(s, i) << 18) | (self._getbyte64(s, i + 1) << 12) | \
                  (self._getbyte64(s, i + 2) << 6) | self._getbyte64(s, i + 3)
            x.append(chr(b10 >> 16))
            x.append(chr((b10 >> 8) & 255))
            x.append(chr(b10 & 255))
            i += 4
        if pads == 1:
            b10 = (self._getbyte64(s, i) << 18) | (self._getbyte64(s, i + 1) << 12) | \
                  (self._getbyte64(s, i + 2) << 6)
            x.append(chr(b10 >> 16))
            x.append(chr((b10 >> 8) & 255))
        elif pads == 2:
            b10 = (self._getbyte64(s, i) << 18) | (self._getbyte64(s, i + 1) << 12)
            x.append(chr(b10 >> 16))
        return "".join(x)
    
    def _getbyte(self, s, i):
        x = ord(s[i])
        if x > 255:
            raise ValueError("INVALID_CHARACTER_ERR")
        return x
    
    def encode(self, s):
        s = str(s)
        x = []
        imax = len(s) - (len(s) % 3)
        if len(s) == 0:
            return s
        i = 0
        while i < imax:
            b10 = (self._getbyte(s, i) << 16) | (self._getbyte(s, i + 1) << 8) | self._getbyte(s, i + 2)
            x.append(self._ALPHA[b10 >> 18])
            x.append(self._ALPHA[(b10 >> 12) & 63])
            x.append(self._ALPHA[(b10 >> 6) & 63])
            x.append(self._ALPHA[b10 & 63])
            i += 3
        remainder = len(s) - imax
        if remainder == 1:
            b10 = self._getbyte(s, i) << 16
            x.append(self._ALPHA[b10 >> 18])
            x.append(self._ALPHA[(b10 >> 12) & 63])
            x.append(self._PADCHAR)
            x.append(self._PADCHAR)
        elif remainder == 2:
            b10 = (self._getbyte(s, i) << 16) | (self._getbyte(s, i + 1) << 8)
            x.append(self._ALPHA[b10 >> 18])
            x.append(self._ALPHA[(b10 >> 12) & 63])
            x.append(self._ALPHA[(b10 >> 6) & 63])
            x.append(self._PADCHAR)
        return "".join(x)

def encode_user_info(info, token):
    # 手动将所有数值字段转换为字符串，确保一致性
    info = {k: str(v) for k, v in info.items()}
    info_json = json.dumps(info, ensure_ascii=False, separators=(',', ':'))
    encrypted = encode(info_json, token)
    base64 = CustomBase64()
    if not encrypted:
        return '{SRBX1}' + base64.encode('')
    base64_str = base64.encode(encrypted)
    return '{SRBX1}' + base64_str
# ================ 加密算法结束 ================

def get_client_ip():
    """获取客户端IP并同时检测校园网连接"""
    try:
        ts = int(time.time() * 1000)
        response = requests.get(
            f'{AUTH_BASE_URL}/cgi-bin/get_challenge',
            params={
                'callback': f'jQuery{ts}_{ts+6}',
                'username': 'dummy',
                'ip': '0.0.0.0',
                '_': ts  # 时间戳
            },  # 服务器端不会校验信息，可使用虚拟信息获取客户端IP
            verify=False,
            timeout=3
        )
        if response.status_code == 200:
            data = json.loads(response.text[response.text.find('{'):-1])
            return data.get('client_ip')
        return None
    except:
        return None

def check_internet():
    """检测互联网连接"""
    try:
        response = requests.head(INTERNET_CHECK_URL, timeout=2)
        return response.status_code == 200
    except:
        return False

def campus_login(username, password):
    """执行登录流程"""
    try:
        # 获取客户端IP（同时检测校园网连接）
        client_ip = get_client_ip()
        if not client_ip:
            return False
        
        # 获取Challenge Token
        ts = int(time.time() * 1000)
        callback = f'jQuery{ts}_{ts+6}'
        token_response = requests.get(
            f'{AUTH_BASE_URL}/cgi-bin/get_challenge',
            params={
                'callback': callback,
                'username': username,
                'ip': client_ip,
                '_': ts
            },
            verify=False,
            timeout=3
        )
        token_data = json.loads(token_response.text[token_response.text.find('{'):-1])
        token = token_data['challenge']

        # 构造登录参数
        md5_password = custom_md5(password, token)
        info_dict = {
            "username": username,
            "password": password,
            "ip": client_ip,
            "acid": "1",
            "enc_ver": "srun_bx1"
        }
        info = encode_user_info(info_dict, token)
        
        # 发送登录请求
        login_response = requests.get(
            f'{AUTH_BASE_URL}/cgi-bin/srun_portal',
            params={
                'callback': callback,
                'action': 'login',
                'username': username,
                'password': f'{{MD5}}{md5_password}',
                'os': 'Windows 10',
                'name': 'Windows',
                'double_stack': '0',  # 未开启双栈认证时，参数为 0
                'chksum': sha1(f"{token}{username}{token}{md5_password}{token}1{token}{client_ip}{token}200{token}1{token}{info}"),  # 计算校验值
                'info': info,
                'ac_id': '1',
                'ip': client_ip,
                'n': '200',  # 定值
                'type': '1', # 定值
                '_': ts + 1
            },
            verify=False,
            timeout=3
        )
        return 'login_ok' in login_response.text
    except Exception as e:
        print(f"登录异常: {str(e)}")
        return False

def main():
    toaster = ToastNotifier()
    
    retry_count = 0
    has_shown_retry = False
    
    while retry_count < MAX_RETRIES:
        # 步骤1：检测校园网连接
        if not get_client_ip():
            if not has_shown_retry:
                toaster.show_toast("校园网状态", "连接不可用", duration=3)
                has_shown_retry = True
            retry_count += 1
            time.sleep(RETRY_INTERVAL)
            continue
        
        # 步骤2：检测互联网访问
        if check_internet():
            toaster.show_toast("网络状态", "已连接到互联网", duration=3)
            break
        
        # 步骤3：尝试登录
        if campus_login(username, password):
            toaster.show_toast("认证成功", "已登录到校园网", duration=3)
            break
        
        # 登录失败处理
        retry_count += 1
        if retry_count == 1:
            toaster.show_toast("认证失败", "正在自动重试...", duration=3)
        time.sleep(RETRY_INTERVAL)
    else:
        toaster.show_toast("错误", "连接超时", duration=3)

if __name__ == "__main__":
    # 隐藏控制台窗口（仅当打包为exe时生效）
    if sys.executable.endswith("pythonw.exe"):
        import ctypes
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    
    main()
