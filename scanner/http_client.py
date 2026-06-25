"""
LightScanner - 轻量级 Web 漏洞扫描器
HTTP 请求引擎模块

封装 requests 库，提供统一的 HTTP 请求接口。
支持 GET/POST、超时控制、错误处理、UA伪装。

课程设计信息：
    作者：孙振
    日期：2026年6月
"""

import requests
import time
import re

# 伪装成正常浏览器，避免被 WAF 拦截
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
}


class HttpClient:
    """HTTP 请求客户端"""

    def __init__(self, timeout=10, delay=0.5):
        """
        初始化 HTTP 客户端
        timeout: 单次请求超时时间（秒）
        delay: 两次请求之间的间隔（秒），避免太快被封
        """
        self.timeout = timeout
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)

    def get(self, url, params=None, **kwargs):
        """发送 GET 请求"""
        time.sleep(self.delay)
        try:
            resp = self.session.get(
                url, params=params,
                timeout=kwargs.get("timeout", self.timeout),
                allow_redirects=kwargs.get("allow_redirects", True)
            )
            return resp
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.ConnectionError:
            return None
        except requests.exceptions.RequestException as e:
            print(f"[!] 请求异常: {e}")
            return None

    def post(self, url, data=None, **kwargs):
        """发送 POST 请求"""
        time.sleep(self.delay)
        try:
            resp = self.session.post(
                url, data=data,
                timeout=kwargs.get("timeout", self.timeout),
                allow_redirects=kwargs.get("allow_redirects", True)
            )
            return resp
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.ConnectionError:
            return None
        except requests.exceptions.RequestException as e:
            print(f"[!] 请求异常: {e}")
            return None

    def get_baseline(self, url, params=None):
        """
        获取基准响应 —— 正常请求的响应内容。
        后续扫描中用于对比，判断 payload 是否引起了异常。
        """
        resp = self.get(url, params=params)
        if resp is None:
            return None, None, 0
        return resp.status_code, resp.text, len(resp.text)

    # ---- DVWA 支持 ---- 

    def login_dvwa(self, base_url="http://localhost/DVWA"):
        """
        登录 DVWA 靶场并设置安全等级为 Low。
        DVWA 使用 CSRF token (user_token)，必须先从页面提取。
        """
        # Step 1: 获取登录页 + 提取 CSRF token
        login_url = f"{base_url}/login.php"
        r0 = self.session.get(login_url, timeout=self.timeout)
        if r0 is None:
            print("[!] DVWA 无法访问，请确认 PHPStudy 已启动")
            return False

        match = re.search(r"name=['\"]user_token['\"].*?value=['\"]([^'\"]+)['\"]", r0.text)
        if not match:
            print("[!] 无法提取 DVWA 登录页 CSRF token")
            return False
        token = match.group(1)

        # Step 2: 带 token 登录
        login_data = {
            "username": "admin",
            "password": "password",
            "Login": "Login",
            "user_token": token,
        }
        resp = self.session.post(login_url, data=login_data, timeout=self.timeout)

        if resp is None:
            print("[!] DVWA 登录失败")
            return False

        # Step 3: 获取 security 页 token + 设置为 Low
        security_url = f"{base_url}/security.php"
        r_sec = self.session.get(security_url, timeout=self.timeout)
        match_sec = re.search(r"name=['\"]user_token['\"].*?value=['\"]([^'\"]+)['\"]", r_sec.text)
        if match_sec:
            self.session.post(security_url, data={
                "security": "low",
                "seclev_submit": "Submit",
                "user_token": match_sec.group(1),
            }, timeout=self.timeout)

        # Step 4: 验证
        test_resp = self.session.get(f"{base_url}/index.php", timeout=self.timeout)
        if test_resp and "Damn Vulnerable" in test_resp.text:
            return True

        print("[!] DVWA 登录验证失败")
        return False

    def close(self):
        """关闭会话"""
        self.session.close()


# ---- 快速测试 ----
if __name__ == "__main__":
    client = HttpClient(delay=0)

    # 测试 DVWA 连接
    print("[*] 测试 DVWA 连接...")
    if client.login_dvwa():
        print("    DVWA 登录成功！")
    else:
        print("    DVWA 不可用，切换到外部靶场...")
        target = "http://testphp.vulnweb.com"
        print(f"[*] 测试目标: {target}")
        status, text, length = client.get_baseline(target)
        if status:
            print(f"    状态码: {status}")
            print(f"    响应长度: {length} 字符")
            print("    连接成功！HTTP引擎工作正常。")
        else:
            print("    连接失败，请检查网络。")

    client.close()
