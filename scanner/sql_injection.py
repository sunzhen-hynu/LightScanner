"""
LightScanner - SQL 注入检测模块

基于规则匹配的 SQL 注入漏洞扫描器。
原理：对目标 URL 的每个参数注入 payload，通过比对响应差异判定漏洞。

检测方法：
    1. 错误回显检测：响应中出现数据库错误关键词
    2. 布尔盲注检测：永真条件导致响应长度显著变化
    3. UNION注入检测：UNION SELECT 拼接导致内容增加
"""

import os
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

try:
    from .http_client import HttpClient
except ImportError:
    # 直接运行时的导入方式
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from scanner.http_client import HttpClient

# 数据库错误特征词（出现任意一个即判定高危）
DB_ERROR_PATTERNS = [
    # MySQL / MariaDB
    r"SQL syntax.*MySQL",
    r"MySQLSyntaxErrorException",
    r"check the manual that corresponds to your (MySQL|MariaDB)",
    r"You have an error in your SQL syntax",
    r"mysql_fetch",
    r"mysql_num_rows",
    r"mysqli_fetch",
    r"Warning.*mysql_",
    r"valid MySQL result",
    # PostgreSQL
    r"PostgreSQL.*ERROR",
    r"psql.",
    r"SQLSTATE\[",
    # SQL Server
    r"Microsoft OLE DB Provider.*SQL Server",
    r"ODBC.*SQL Server",
    r"Unclosed quotation mark",
    r"Incorrect syntax near",
    r"SqlException",
    # Oracle
    r"ORA-\d{5}",
    r"Oracle error",
    # SQLite
    r"SQLite/JDBCDriver",
    r"SQLiteException",
    # 通用
    r"SQL syntax error",
    r"database error",
    r"unclosed quotation",
    r"quoted string not properly terminated",
    r"supplied argument is not a valid",
    r"Fatal error.*on line",
]


class SQLInjectionScanner:
    """SQL 注入扫描器"""

    def __init__(self, http_client: HttpClient):
        self.client = http_client
        self.payloads = self._load_payloads()
        self.results = []

    def _load_payloads(self):
        """加载 SQL 注入 payload 字典"""
        payload_file = os.path.join(os.path.dirname(__file__), "..", "payloads", "sql_injection.txt")
        payloads = []
        try:
            with open(payload_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):  # 跳过注释和空行
                        payloads.append(line)
        except FileNotFoundError:
            print(f"[!] Payload 文件未找到: {payload_file}")
        return payloads

    def _check_error_based(self, response_text):
        """检测响应中是否包含数据库错误信息"""
        for pattern in DB_ERROR_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False

    def _check_boolean_blind(self, baseline_length, payload_length):
        """布尔盲注检测：响应长度变化超过阈值"""
        if baseline_length == 0:
            return False
        ratio = abs(payload_length - baseline_length) / baseline_length
        # 长度变化超过 20% 视为可疑
        return ratio > 0.2

    def _check_union_based(self, response_text):
        """UNION 注入检测：响应中是否出现预期注入的数值"""
        # UNION SELECT 1,2,3 如果成功，页面可能显示数字
        union_indicators = ["UNION", "union select"]
        for indicator in union_indicators:
            if indicator.lower() in response_text.lower():
                return True
        return False

    def _inject_payload(self, url, payload):
        """向 URL 的每个 GET 参数注入 payload，返回请求结果列表"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return []  # 无 GET 参数，无法注入

        responses = []
        for param_name in params:
            # 构造注入后的 URL：只修改一个参数
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
                    "length": len(resp.text),
                    "text": resp.text,
                })
        return responses

    def scan(self, url):
        """
        扫描目标 URL 的 SQL 注入漏洞。
        返回检测到的漏洞列表。
        """
        print(f"\n[*] 开始 SQL 注入扫描: {url}")
        print(f"    共加载 {len(self.payloads)} 条 payload\n")

        self.results = []

        # Step 1: 获取基准响应
        base_status, base_text, base_len = self.client.get_baseline(url)
        if base_status is None:
            print("[!] 无法获取基准响应，扫描终止。")
            return self.results

        print(f"[+] 基准响应: 状态码={base_status}, 长度={base_len}")

        # Step 2: 逐个参数注入 payload
        vulnerable_params = set()  # 去重，同一参数只报告一次

        for i, payload in enumerate(self.payloads):
            responses = self._inject_payload(url, payload)

            for r in responses:
                param = r["param"]
                text = r["text"]
                length = r["length"]

                # 检测 1：错误回显
                if self._check_error_based(text):
                    if param not in (p[0] for p in self.results if p[0] == "error"):
                        self.results.append(("error", param, payload, r["url"], "高危", "数据库错误信息泄露"))
                        print(f"  [!] 错误注入 参数[{param}] payload=[{payload}] → 数据库错误泄露")

                # 检测 2：布尔盲注
                if self._check_boolean_blind(base_len, length):
                    if param not in (p[1] for p in self.results if p[0] == "blind"):
                        self.results.append(("blind", param, payload, r["url"], "中危", f"响应长度异常变化(基准{base_len} → {length})"))
                        print(f"  [?] 布尔盲注 参数[{param}] payload=[{payload}] → 长度 {base_len}→{length}")

                # 检测 3：HTTP 500 错误
                if r["status"] >= 500:
                    if param not in (p[1] for p in self.results if p[0] == "error500"):
                        self.results.append(("error500", param, payload, r["url"], "中危", "服务器500错误"))
                        print(f"  [!] 服务端错误 参数[{param}] payload=[{payload}] → HTTP {r['status']}")

            # 进度提示
            if (i + 1) % 10 == 0:
                print(f"    进度: {i+1}/{len(self.payloads)}")

        # Step 3: 汇总
        print(f"\n[+] 扫描完成，发现 {len(self.results)} 个可疑点\n")
        return self.results

    def report(self):
        """打印扫描报告"""
        if not self.results:
            print("[✓] 未发现 SQL 注入漏洞。")
            return

        print("=" * 60)
        print("  SQL 注入扫描报告")
        print("=" * 60)
        for vuln_type, param, payload, url, severity, detail in self.results:
            print(f"  类型: {vuln_type} | 参数: {param} | 等级: {severity}")
            print(f"  Payload: {payload}")
            print(f"  详情: {detail}")
            print(f"  URL: {url}")
            print("-" * 60)
        print(f"  总计: {len(self.results)} 个可疑注入点\n")


# ---- 快速测试 ----
if __name__ == "__main__":
    client = HttpClient(delay=0.3)

    # 登录 DVWA
    if client.login_dvwa():
        print("[+] DVWA 登录成功，开始扫描...\n")
        scanner = SQLInjectionScanner(client)

        # 扫描 DVWA 的 SQL 注入页面
        target = "http://localhost/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit"
        results = scanner.scan(target)
        scanner.report()

    else:
        print("[!] DVWA 登录失败，尝试本地靶场...")
        scanner = SQLInjectionScanner(client)
        target = "http://127.0.0.1:5000/sqli?id=1"
        results = scanner.scan(target)
        scanner.report()

    client.close()
