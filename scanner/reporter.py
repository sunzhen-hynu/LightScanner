"""
LightScanner - HTML 报告生成模块

将扫描结果输出为彩色 HTML 格式报告，方便存档和展示。
漏洞等级用颜色区分：高危红色、中危橙色、低危绿色。
"""

import os
import datetime


def _escape(text):
    """HTML 转义"""
    return (str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def generate_report(target, sql_results, xss_results, dir_results, port_results, output_dir=None):
    """
    生成 HTML 格式的完整扫描报告。
    
    参数:
        target:     扫描目标 URL
        sql_results: SQLInjectionScanner 的 results 列表
                      每项: (type, param, payload, url, severity, detail)
        xss_results: XSSScanner 的 results 列表
                      每项: (param, payload, url, severity)
        dir_results: DirBruteScanner 的 results 列表
                      每项: (path, code, label, url)
        port_results: PortScanner 的 results 列表
                      每项: (port, service)
        output_dir:  输出目录，默认为桌面
    """
    if output_dir is None:
        output_dir = os.path.join(os.path.expanduser("~"), "Desktop")

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = f"LightScanner_Report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    filepath = os.path.join(output_dir, filename)

    # 统计
    total_vulns = len(sql_results) + len(xss_results) + len(dir_results)
    high_count = sum(1 for r in sql_results if r[4] == "高危")
    high_count += sum(1 for r in xss_results if r[3] == "高危")

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LightScanner 扫描报告 - {_escape(target)}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI','PingFang SC',sans-serif;background:#f5f6fa;color:#2c3e50;padding:40px}}
.card{{max-width:900px;margin:0 auto 24px;background:#fff;border-radius:12px;padding:28px 32px;box-shadow:0 1px 4px rgba(0,0,0,.08)}}
h1{{font-size:22px;margin-bottom:4px}}
h2{{font-size:16px;color:#555;margin-bottom:20px;padding-bottom:10px;border-bottom:2px solid #3498db}}
.meta{{font-size:13px;color:#888;margin-bottom:16px}}
.stats{{display:flex;gap:16px;margin-bottom:20px}}
.stat{{flex:1;text-align:center;padding:16px;border-radius:8px;background:#f8f9fb}}
.stat .num{{font-size:32px;font-weight:700}}
.stat .label{{font-size:12px;color:#888;margin-top:4px}}
.stat.high .num{{color:#e74c3c}}
.stat.mid .num{{color:#f39c12}}
.stat.low .num{{color:#27ae60}}
table{{width:100%;border-collapse:collapse;font-size:13px;margin-bottom:16px}}
th{{text-align:left;padding:10px 8px;border-bottom:1px solid #e0e0e0;color:#888;font-weight:500;font-size:12px}}
td{{padding:10px 8px;border-bottom:1px solid #f0f0f0}}
.sev{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}}
.sev-high{{background:#fde8e8;color:#c0392b}}
.sev-mid{{background:#fef3e2;color:#d35400}}
.sev-low{{background:#e8f8f0;color:#27ae60}}
.footer{{text-align:center;font-size:12px;color:#aaa;margin-top:24px}}
</style>
</head>
<body>
<div class="card">
<h1>LightScanner 扫描报告</h1>
<div class="meta">目标: {_escape(target)} | 生成时间: {now}</div>
<div class="stats">
<div class="stat high"><div class="num">{high_count}</div><div class="label">高危漏洞</div></div>
<div class="stat mid"><div class="num">{total_vulns - high_count}</div><div class="label">中低危发现</div></div>
<div class="stat low"><div class="num">{len(port_results)}</div><div class="label">开放端口</div></div>
</div>
</div>
"""

    # SQL 注入
    if sql_results:
        html += '<div class="card"><h2>SQL 注入扫描</h2>'
        html += '<table><tr><th>类型</th><th>参数</th><th>Payload</th><th>等级</th><th>详情</th></tr>'
        for vuln_type, param, payload, url, severity, detail in sql_results:
            sev_cls = "sev-high" if "高危" in severity else "sev-mid"
            html += f'<tr><td>{_escape(vuln_type)}</td><td>{_escape(param)}</td><td style="font-family:monospace;font-size:12px">{_escape(payload[:50])}</td><td><span class="sev {sev_cls}">{_escape(severity)}</span></td><td style="font-size:12px">{_escape(detail)}</td></tr>'
        html += '</table></div>'

    # XSS
    if xss_results:
        html += '<div class="card"><h2>XSS 扫描</h2>'
        html += '<table><tr><th>参数</th><th>Payload</th><th>等级</th></tr>'
        for param, payload, url, severity in xss_results:
            sev_cls = "sev-high" if "高危" in severity else "sev-mid"
            html += f'<tr><td>{_escape(param)}</td><td style="font-family:monospace;font-size:12px">{_escape(payload[:60])}</td><td><span class="sev {sev_cls}">{_escape(severity)}</span></td></tr>'
        html += '</table></div>'

    # 目录
    if dir_results:
        html += '<div class="card"><h2>目录爆破</h2>'
        html += '<table><tr><th>路径</th><th>状态码</th><th>说明</th></tr>'
        for path, code, label, url in dir_results:
            sev_cls = "sev-low" if code == 200 else "sev-mid"
            html += f'<tr><td style="font-family:monospace">/{_escape(path)}</td><td>{code}</td><td><span class="sev {sev_cls}">{_escape(label)}</span></td></tr>'
        html += '</table></div>'

    # 端口
    if port_results:
        html += '<div class="card"><h2>端口扫描</h2>'
        html += '<table><tr><th>端口</th><th>服务</th><th>状态</th></tr>'
        for port, service in port_results:
            html += f'<tr><td>{port}</td><td>{service}</td><td style="color:#27ae60">开放</td></tr>'
        html += '</table></div>'

    html += '<div class="footer">Generated by LightScanner | 仅供学习研究使用</div></body></html>'

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[+] 报告已生成: {filepath}")
    return filepath
