"""
LightScanner - XSS 检测模块

反射型 XSS（跨站脚本攻击）漏洞扫描器。
原理：向目标 URL 参数注入 XSS payload，检查响应 HTML 中是否原样回显了 payload。
如果 payload 未被编码或过滤就出现在页面中，说明存在 XSS 漏洞。

检测要点：
    - 基础检测：payload 原样出现在响应中 → 高危
    - 编码绕过：对 URL 编码后的 payload 也做检查
    - 事件触发型：onerror/onload 等即使被部分过滤也可能被触发
"""

import os
import html as html_module
from urllib.parse import urlparse, parse_qs, urlencode, unquote, urlunparse

try:
    from .http_client import HttpClient
except ImportError:
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from scanner.http_client import HttpClient


class XSSScanner:
    """XSS 扫描器"""

    def __init__(self, http_client: HttpClient):
        self.client = http_client
        self.payloads = self._load_payloads()
        self.results = []

    def _load_payloads(self):
        """加载 XSS payload 字典"""
        payload_file = os.path.join(os.path.dirname(__file__), "..", "payloads", "xss_payloads.txt")
        payloads = []
        try:
            with open(payload_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        payloads.append(line)
        except FileNotFoundError:
            print(f"[!] Payload 文件未找到: {payload_file}")
        return payloads

    def _is_reflected(self, response_text, payload):
        """
        检查 payload 是否被反射回响应中。
        策略：
        1. 直接搜索 payload 原文
        2. 搜索 payload 去除 tag 后的核心内容（绕过简单 WAF）
        3. 搜索 URL 解码后的 payload
        """
        if not response_text:
            return False

        # 方法1：原文匹配
        if payload in response_text:
            return True

        # 方法2：提取 payload 核心内容（括号内的触发代码）
        # 例如 <script>alert(1)</script> → alert(1)
        import re
        # 提取标签内容
        inner_match = re.search(r'>([^<]*)<', payload)
        if inner_match:
            core = inner_match.group(1)
            if len(core) > 3 and core in response_text:
                return True

        # 方法3：URL 解码后匹配
        try:
            decoded = unquote(payload)
            if decoded != payload and decoded in response_text:
                return True
        except Exception:
            pass

        return False

    def _inject_payload(self, url, payload):
        """向 URL 每个参数注入 payload"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return []

        responses = []
        for param_name in params:
            injected_params = {k: v[:] for k, v in params.items()}
            injected_params[param_name] = [payload]

            new_query = urlencode(injected_params, doseq=True)
            injected_url = urlunparse(parsed._replace(query=new_query))

            resp = self.client.get(injected_url)
            if resp:
                responses.append({
                    "param": param_name,
                    "payload": payload,
                    "url": injected_url,
                    "status": resp.status_code,
                    "text": resp.text,
                })
        return responses

    def scan(self, url):
        """扫描 XSS 漏洞"""
        print(f"\n[*] 开始 XSS 扫描: {url}")
        print(f"    共加载 {len(self.payloads)} 条 payload\n")

        self.results = []

        # 先测试连通性
        test_resp = self.client.get(url)
        if test_resp is None:
            print("[!] 目标不可达，扫描终止。")
            return self.results

        found_params = set()

        for i, payload in enumerate(self.payloads):
            responses = self._inject_payload(url, payload)

            for r in responses:
                param = r["param"]
                text = r["text"]

                if self._is_reflected(text, payload):
                    key = f"{param}_{payload[:20]}"
                    if key not in found_params:
                        found_params.add(key)
                        severity = "高危" if "<script>" in payload.lower() else "中危"
                        self.results.append((param, payload, r["url"], severity))
                        print(f"  [!] XSS! 参数[{param}] payload=[{payload[:40]}] → 反射成功")

            if (i + 1) % 5 == 0:
                print(f"    进度: {i+1}/{len(self.payloads)}")

        print(f"\n[+] 扫描完成，发现 {len(self.results)} 个 XSS 漏洞\n")
        return self.results

    def report(self):
        """打印扫描报告"""
        if not self.results:
            print("[✓] 未发现 XSS 漏洞。")
            return

        print("=" * 60)
        print("  XSS 扫描报告")
        print("=" * 60)
        for param, payload, url, severity in self.results:
            tag = "[!!!]" if severity == "高危" else "[?]"
            print(f"  {tag} 参数: {param} | 等级: {severity}")
            print(f"  Payload: {payload}")
            print(f"  URL: {url}")
            print("-" * 60)
        print(f"  总计: {len(self.results)} 个 XSS 漏洞\n")


# ---- 快速测试 ----
if __name__ == "__main__":
    client = HttpClient(delay=0.1)

    scanner = XSSScanner(client)

    # 测试本地靶场
    print("[*] 测试本地靶场 XSS...")
    target = "http://127.0.0.1:5000/xss?input=hello"
    scanner.scan(target)
    scanner.report()

    client.close()
