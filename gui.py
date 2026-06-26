"""
LightScanner - 图形用户界面 (Tkinter)

集成所有扫描模块，提供可视化操作。
"""

import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

# 导入扫描模块
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from scanner.http_client import HttpClient
from scanner.sql_injection import SQLInjectionScanner
from scanner.xss_scanner import XSSScanner
from scanner.dir_brute import DirBruteScanner
from scanner.port_scanner import PortScanner
from scanner.reporter import generate_report


class LightScannerGUI:
    """LightScanner 图形界面"""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("LightScanner - Web 漏洞扫描器")
        self.root.geometry("720x600")
        self.root.configure(bg="#f5f6fa")
        self.root.resizable(True, True)

        self.client = HttpClient(delay=0.2)
        self.scanning = False

        self._build_ui()

    def _build_ui(self):
        # 标题
        title_frame = tk.Frame(self.root, bg="#2c3e50", height=60)
        title_frame.pack(fill=tk.X)
        title_frame.pack_propagate(False)
        tk.Label(title_frame, text="LightScanner", fg="#fff", bg="#2c3e50",
                 font=("Segoe UI", 18, "bold")).pack(side=tk.LEFT, padx=20, pady=12)
        tk.Label(title_frame, text="轻量级 Web 漏洞扫描器", fg="#bdc3c7", bg="#2c3e50",
                 font=("Segoe UI", 11)).pack(side=tk.RIGHT, padx=20, pady=16)

        # 目标区域
        input_frame = tk.Frame(self.root, bg="#f5f6fa", padx=20, pady=10)
        input_frame.pack(fill=tk.X)
        tk.Label(input_frame, text="目标 URL:", bg="#f5f6fa",
                 font=("Microsoft YaHei", 11)).pack(side=tk.LEFT)
        self.url_entry = tk.Entry(input_frame, font=("Consolas", 12), width=50)
        self.url_entry.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
        self.url_entry.insert(0, "http://127.0.0.1:5000")

        # 扫描模块选择
        module_frame = tk.Frame(self.root, bg="#f5f6fa", padx=20, pady=5)
        module_frame.pack(fill=tk.X)
        tk.Label(module_frame, text="扫描模块:", bg="#f5f6fa",
                 font=("Microsoft YaHei", 11)).pack(side=tk.LEFT)

        self.var_sql = tk.BooleanVar(value=True)
        self.var_xss = tk.BooleanVar(value=True)
        self.var_dir = tk.BooleanVar(value=True)
        self.var_port = tk.BooleanVar(value=True)

        for text, var in [("SQL注入", self.var_sql), ("XSS", self.var_xss),
                           ("目录爆破", self.var_dir), ("端口扫描", self.var_port)]:
            cb = tk.Checkbutton(module_frame, text=text, variable=var,
                                bg="#f5f6fa", font=("Microsoft YaHei", 10),
                                selectcolor="#f5f6fa")
            cb.pack(side=tk.LEFT, padx=5)

        # DVWA 选项
        self.var_dvwa = tk.BooleanVar(value=False)
        tk.Checkbutton(module_frame, text="DVWA模式", variable=self.var_dvwa,
                       bg="#f5f6fa", font=("Microsoft YaHei", 10),
                       selectcolor="#f5f6fa").pack(side=tk.LEFT, padx=15)

        # 按钮区域
        btn_frame = tk.Frame(self.root, bg="#f5f6fa", padx=20, pady=8)
        btn_frame.pack(fill=tk.X)

        style = {"font": ("Microsoft YaHei", 11), "width": 12, "height": 1}

        self.btn_scan = tk.Button(btn_frame, text="开始扫描", command=self._start_scan,
                                  bg="#3498db", fg="#fff", **style)
        self.btn_scan.pack(side=tk.LEFT, padx=4)

        self.btn_report = tk.Button(btn_frame, text="生成报告", command=self._gen_report,
                                    bg="#27ae60", fg="#fff", **style)
        self.btn_report.pack(side=tk.LEFT, padx=4)

        self.btn_stop = tk.Button(btn_frame, text="停止", command=self._stop_scan,
                                  bg="#e74c3c", fg="#fff", state=tk.DISABLED, **style)
        self.btn_stop.pack(side=tk.LEFT, padx=4)

        # 进度条
        self.progress = ttk.Progressbar(btn_frame, mode="indeterminate", length=200)
        self.progress.pack(side=tk.RIGHT, padx=10)

        # 输出区域
        output_frame = tk.Frame(self.root, padx=20, pady=10, bg="#f5f6fa")
        output_frame.pack(fill=tk.BOTH, expand=True)
        self.output = scrolledtext.ScrolledText(output_frame, font=("Consolas", 10),
                                                 bg="#1e1e1e", fg="#d4d4d4",
                                                 insertbackground="#fff", wrap=tk.WORD)
        self.output.pack(fill=tk.BOTH, expand=True)

        # 状态栏
        self.status_bar = tk.Label(self.root, text="就绪", bg="#ecf0f1", fg="#7f8c8d",
                                    anchor=tk.W, font=("Microsoft YaHei", 9), padx=10)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)

    def _log(self, text):
        """输出日志到界面"""
        self.output.insert(tk.END, text + "\n")
        self.output.see(tk.END)
        self.root.update_idletasks()

    def _start_scan(self):
        """开始扫描（在新线程中运行）"""
        if self.scanning:
            return

        target = self.url_entry.get().strip()
        if not target:
            messagebox.showwarning("提示", "请输入目标 URL")
            return

        self.scanning = True
        self.btn_scan.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.progress.start(10)
        self.status_bar.config(text="扫描中...")
        self.output.delete(1.0, tk.END)
        self.last_results = {"sql": [], "xss": [], "dir": [], "port": []}

        thread = threading.Thread(target=self._run_scan, args=(target,), daemon=True)
        thread.start()

    def _run_scan(self, target):
        """执行扫描的主逻辑"""
        try:
            # DVWA 模式：先登录
            if self.var_dvwa.get():
                self._log("[*] DVWA 模式：正在登录...")
                if not self.client.login_dvwa():
                    self._log("[!] DVWA 登录失败")
                    return

            # SQL 注入
            if self.var_sql.get():
                self._log("\n" + "=" * 50)
                self._log("[*] 开始 SQL 注入扫描...")
                scanner = SQLInjectionScanner(self.client)
                sql_target = target + "/sqli?id=1"
                results = scanner.scan(sql_target)
                self.last_results["sql"] = results
                scanner.report = lambda: self._print_sql_report(results)

            # XSS
            if self.var_xss.get() and not self._stopped:
                self._log("\n" + "=" * 50)
                self._log("[*] 开始 XSS 扫描...")
                scanner = XSSScanner(self.client)
                xss_target = target + "/xss?input=hello"
                results = scanner.scan(xss_target)
                self.last_results["xss"] = results

            # 目录爆破
            if self.var_dir.get() and not self._stopped:
                self._log("\n" + "=" * 50)
                self._log("[*] 开始目录爆破...")
                scanner = DirBruteScanner(self.client)
                results = scanner.scan(target)
                self.last_results["dir"] = results

            # 端口扫描
            if self.var_port.get() and not self._stopped:
                self._log("\n" + "=" * 50)
                self._log("[*] 开始端口扫描...")
                # 从 URL 中提取主机
                from urllib.parse import urlparse
                host = urlparse(target).hostname or "127.0.0.1"
                scanner = PortScanner(timeout=1)
                results = scanner.scan(host, ports=[80, 443, 5000, 8080, 3306, 3389])
                self.last_results["port"] = results

            self._log("\n" + "=" * 50)
            self._log("[+] 扫描完成！")
            total = sum(len(v) for v in self.last_results.values())
            self._log(f"[+] 共发现 {total} 项发现")
            self.status_bar.config(text=f"扫描完成 - 共 {total} 项发现")

        except Exception as e:
            self._log(f"[!] 扫描出错: {e}")
            self.status_bar.config(text="扫描出错")
        finally:
            self.scanning = False
            self.btn_scan.config(state=tk.NORMAL)
            self.btn_stop.config(state=tk.DISABLED)
            self.progress.stop()

    _stopped = False

    def _stop_scan(self):
        self._stopped = True
        self._log("[!] 用户中止扫描")

    def _print_sql_report(self, results):
        """打印 SQL 注入报告到输出框"""
        for vuln_type, param, payload, url, severity, detail in results:
            self._log(f"  [!] [{severity}] 参数={param} payload={payload[:40]}")
            self._log(f"       {detail}")

    def _gen_report(self):
        """生成 HTML 报告"""
        if not self.last_results:
            messagebox.showwarning("提示", "请先执行扫描")
            return

        target = self.url_entry.get().strip()
        try:
            filepath = generate_report(
                target,
                self.last_results["sql"],
                self.last_results["xss"],
                self.last_results["dir"],
                self.last_results["port"],
            )
            self._log(f"\n[+] 报告已生成: {filepath}")
            self.status_bar.config(text=f"报告已保存")
            # 用默认浏览器打开
            os.startfile(filepath)
        except Exception as e:
            self._log(f"[!] 报告生成失败: {e}")

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    gui = LightScannerGUI()
    gui.run()
