"""
LightScanner - 目录爆破模块

基于字典的敏感路径探测。将字典中的路径逐个拼接至目标 URL，
根据 HTTP 状态码判断该路径是否存在。

状态码含义：
    200 → 路径存在且可访问
    301/302 → 重定向（路径存在但需要登录或跳转）
    403 → 路径存在但禁止访问
    404 → 不存在（或已被隐藏处理的404页面）
    500 → 服务器错误（也可能是存在但触发了错误）
"""

import os
import time
from urllib.parse import urljoin

try:
    from .http_client import HttpClient
except ImportError:
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from scanner.http_client import HttpClient


class DirBruteScanner:
    """目录爆破扫描器"""

    # 有意义的 HTTP 状态码（404 通常忽略）
    INTERESTING_CODES = {200, 301, 302, 403, 401, 500, 503}

    def __init__(self, http_client: HttpClient):
        self.client = http_client
        self.wordlist = self._load_wordlist()
        self.results = []

    def _load_wordlist(self):
        """加载目录字典"""
        dict_file = os.path.join(os.path.dirname(__file__), "..", "payloads", "common_dirs.txt")
        words = []
        try:
            with open(dict_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        words.append(line)
        except FileNotFoundError:
            print(f"[!] 字典文件未找到: {dict_file}")
        return words

    def _ensure_scheme(self, url):
        """确保 URL 有协议头"""
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url
        return url.rstrip("/")

    def scan(self, target_url):
        """
        对目标 URL 进行目录爆破扫描。
        target_url: 如 http://127.0.0.1:5000 或 127.0.0.1:5000
        """
        target_url = self._ensure_scheme(target_url)

        print(f"\n[*] 开始目录爆破: {target_url}")
        print(f"    共加载 {len(self.wordlist)} 条字典\n")

        self.results = []

        for i, path in enumerate(self.wordlist):
            full_url = urljoin(target_url + "/", path)

            resp = self.client.get(full_url, allow_redirects=False)

            if resp and resp.status_code in self.INTERESTING_CODES:
                code = resp.status_code
                label = self._code_label(code)
                self.results.append((path, code, label, full_url))
                print(f"  [{code}] {label:8s} {full_url}")

            # 进度
            if (i + 1) % 20 == 0:
                print(f"    进度: {i+1}/{len(self.wordlist)}")

        print(f"\n[+] 扫描完成，发现 {len(self.results)} 个可访问路径\n")
        return self.results

    def _code_label(self, code):
        """状态码 → 人类可读标签"""
        labels = {
            200: "可访问",
            301: "重定向",
            302: "重定向",
            403: "禁止访问",
            401: "需认证",
            500: "服务器错误",
            503: "不可用",
        }
        return labels.get(code, f"HTTP {code}")

    def report(self):
        """打印扫描报告"""
        if not self.results:
            print("[✓] 未发现可访问的隐藏路径。")
            return

        print("=" * 60)
        print("  目录爆破报告")
        print("=" * 60)
        for path, code, label, url in self.results:
            sym = "!" if code == 200 else "?"
            print(f"  [{sym}] [{code}] {path}")
            print(f"      {url}")
            print("-" * 60)
        print(f"  总计: {len(self.results)} 个路径\n")


# ---- 快速测试 ----
if __name__ == "__main__":
    client = HttpClient(delay=0.1)

    scanner = DirBruteScanner(client)

    # 测试本地靶场
    scanner.scan("127.0.0.1:5000")
    scanner.report()

    client.close()
