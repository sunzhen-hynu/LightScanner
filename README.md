# LightScanner - 轻量级 Web 漏洞扫描器

基于 Python 实现的 Web 漏洞扫描工具，支持 SQL 注入、XSS、目录爆破、端口扫描。

## 功能模块

| 模块 | 功能 |
|------|------|
| SQL 注入检测 | 基于规则的注入点探测，覆盖闭合/盲注/UNION 三类 payload |
| XSS 检测 | 反射型 XSS 检测，含过滤绕过 payload |
| 目录爆破 | 基于字典的敏感路径探测 |
| 端口扫描 | 常见服务端口开放检测 |
| GUI 界面 | Tkinter 图形化操作 |
| 报告生成 | HTML 格式扫描报告 |

## 快速开始

```bash
pip install requests
cd scanner
python http_client.py
```

## 测试靶场

- http://testphp.vulnweb.com (Acunetix 官方靶场)

## 免责声明

本工具仅供学习研究，请勿用于未经授权的安全测试。

## 作者

孙振 · 衡阳师范学院 · 网络空间安全 · 2023级

---

*2026年6月*
