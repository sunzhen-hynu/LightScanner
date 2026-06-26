"""
LightScanner - 端口扫描模块

基于 socket 的 TCP 端口扫描器。对目标主机尝试连接指定端口列表，
根据连接是否成功判断端口是否开放。

常见端口对照：
    21   FTP
    22   SSH
    23   Telnet
    25   SMTP
    53   DNS
    80   HTTP
    110  POP3
    143  IMAP
    443  HTTPS
    445  SMB
    1433 MS SQL
    1521 Oracle
    3306 MySQL
    3389 RDP
    5432 PostgreSQL
    6379 Redis
    8080 HTTP-Alt
    8888 HTTP-Alt
    27017 MongoDB
"""

import socket
import time

try:
    from .http_client import HttpClient
except ImportError:
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from scanner.http_client import HttpClient


# 常见端口及其服务名称
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1080: "SOCKS",
    1433: "MS SQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9090: "Web-Alt",
    27017: "MongoDB",
}


class PortScanner:
    """TCP 端口扫描器"""

    def __init__(self, timeout=2):
        self.timeout = timeout
        self.results = []

    def _scan_port(self, host, port):
        """扫描单个端口，返回是否开放"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0  # 0 = 连接成功
        except socket.gaierror:
            print(f"[!] 无法解析主机名: {host}")
            return None  # None 表示中止
        except Exception as e:
            return False

    def scan(self, host, ports=None):
        """
        扫描目标主机的端口。
        host: 目标 IP 或域名（如 127.0.0.1）
        ports: 要扫描的端口列表，默认扫描常见端口
        """
        if ports is None:
            ports = list(COMMON_PORTS.keys())

        print(f"\n[*] 开始端口扫描: {host}")
        print(f"    共 {len(ports)} 个端口\n")

        self.results = []

        for port in ports:
            sys.stdout.write(f"    扫描 {port:5d} （{COMMON_PORTS.get(port, '?')}）... ")
            sys.stdout.flush()

            is_open = self._scan_port(host, port)

            if is_open is None:
                print("\n[!] 扫描中止")
                return self.results
            elif is_open:
                service = COMMON_PORTS.get(port, "未知")
                self.results.append((port, service))
                print("开放")
            else:
                print("关闭")

            time.sleep(0.05)  # 避免扫太快

        print(f"\n[+] 扫描完成，发现 {len(self.results)} 个开放端口\n")
        return self.results

    def scan_custom(self, host, start_port, end_port):
        """自定义端口范围扫描"""
        ports = list(range(start_port, end_port + 1))
        return self.scan(host, ports)

    def report(self):
        """打印扫描报告"""
        if not self.results:
            print("[✓] 未发现开放端口。")
            return

        print("=" * 60)
        print("  端口扫描报告")
        print("=" * 60)
        print(f"  {'端口':<8} {'服务':<15} 状态")
        print("-" * 60)
        for port, service in self.results:
            print(f"  {port:<8} {service:<15} 开放")
        print("-" * 60)
        print(f"  总计: {len(self.results)} 个开放端口\n")


# ---- 快速测试 ----
if __name__ == "__main__":
    scanner = PortScanner(timeout=1)

    # 扫描本地常用端口
    scanner.scan("127.0.0.1", ports=[80, 443, 3306, 5000, 8080, 1433])
    scanner.report()
