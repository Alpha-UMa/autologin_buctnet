# login.pyw
# -*- coding: utf-8 -*-
import requests
import time
import sys
import os
import json
from win10toast import ToastNotifier

os.chdir(os.path.dirname(os.path.abspath(__file__)))  # 计划任务默认运行在 %SystemRoot%\System32 ，该句将切换至脚本所在目录，以免相对路径引用错误

# 配置参数
# 用户登录凭证
username = 'username'  # 请修改为自己的账号
password = 'password'  # 请修改为自己的密码
MAX_RETRIES = 9  # 最大重试次数
RETRY_INTERVAL = 5  # 重试等待时间
AUTH_BASE_URL = 'https://tree.buct.edu.cn'  # 校园网认证地址
INTERNET_CHECK_URL = 'https://www.baidu.com'  # 网络状态检测地址

# ================ 网站js加密算法 ================
import hmac
import hashlib
import subprocess

def custom_md5(password, token):
    md5_hash = hmac.new(token.encode('utf-8'), password.encode('utf-8'), hashlib.md5).hexdigest()
    return md5_hash  # 使用token作为密钥，通过HMAC生成密码MD5哈希

def sha1(data):
    return hashlib.sha1(data.encode('utf-8')).hexdigest()  # 生成SHA1哈希

def call_js_function(func_name, *args):
    """外部JS函数调用"""
    startupinfo = None
    if sys.platform.startswith('win'):
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        
    args_json = [json.dumps(arg) for arg in args]
    result = subprocess.run(
        ['node', 'encode.js', func_name] + args_json,
        capture_output=True,
        text=True,
        encoding='utf-8',
        startupinfo=startupinfo,  # 使用隐藏窗口选项，避免控制台窗口弹出
        creationflags=subprocess.CREATE_NO_WINDOW  # Windows 专用 flag
    )
    if result.stderr:
        raise RuntimeError(f"JS错误: {result.stderr.strip()}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return result.stdout  # 返回原始字符串

def encode_user_info(info, token):
    # 手动将所有数值字段转换为字符串，确保一致性
    info = {k: str(v) for k, v in info.items()}
    info_json = json.dumps(info, ensure_ascii=False, separators=(',', ':'))
    encrypted = call_js_function('encode',info_json, token) # 调用 JS 函数计算 info 字段值
    return '{SRBX1}' + encrypted
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
                toaster.show_toast("校园网状态", "连接不可用", duration=2)
                has_shown_retry = True
            retry_count += 1
            time.sleep(RETRY_INTERVAL)
            continue
        
        # 步骤2：检测互联网访问
        if check_internet():
            toaster.show_toast("网络状态", "已连接到互联网", duration=2)
            break
        
        # 步骤3：尝试登录
        if campus_login(username, password):
            toaster.show_toast("认证成功", "已登录到校园网", duration=2)
            break
        
        # 登录失败处理
        retry_count += 1
        if retry_count == 1:
            toaster.show_toast("认证失败", "正在自动重试...", duration=2)
        time.sleep(RETRY_INTERVAL)
    else:
        toaster.show_toast("错误", "连接超时", duration=2)

if __name__ == "__main__":
    # 隐藏控制台窗口（仅当打包为exe时生效）
    if sys.executable.endswith("pythonw.exe"):
        import ctypes
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    
    main()
