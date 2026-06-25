"""
LightScanner 本地测试靶场
故意包含 SQL 注入和 XSS 漏洞，专供扫描器测试。
启动后访问 http://127.0.0.1:5000

运行: python target.py
"""

from flask import Flask, request

app = Flask(__name__)

# 首页
@app.route("/")
def home():
    return """<h2>LightScanner 测试靶场</h2>
    <ul>
    <li><a href='/sqli?id=1'>/sqli?id=1</a> — SQL注入（数字型）</li>
    <li><a href='/sqli2?name=admin'>/sqli2?name=admin</a> — SQL注入（字符型）</li>
    <li><a href='/xss?input=hello'>/xss?input=hello</a> — 反射型XSS</li>
    <li><a href='/admin'>/admin</a> — 隐藏管理页面</li>
    <li><a href='/backup'>/backup</a> — 隐藏备份目录</li>
    </ul>"""

# 数字型 SQL 注入（不用数据库，纯模拟）
@app.route("/sqli")
def sqli():
    user_id = request.args.get("id", "1")
    # 故意拼接 —— 这就是漏洞
    query = f"SELECT * FROM users WHERE id = {user_id}"
    if "'" in user_id or "union" in user_id.lower():
        return f"<pre>ERROR: You have an error in your SQL syntax near '{user_id}' at line 1</pre>", 200
    return f"<pre>OK: {query}</pre>"

# 字符型 SQL 注入
@app.route("/sqli2")
def sqli2():
    name = request.args.get("name", "admin")
    query = f"SELECT * FROM users WHERE username = '{name}'"
    if "1=1" in name or "--" in name:
        return f"<pre>MySQL error: Unclosed quotation mark after the character string '{name}'</pre>", 200
    return f"<pre>OK: {query}</pre>"

# 反射型 XSS
@app.route("/xss")
def xss():
    user_input = request.args.get("input", "")
    # 不做任何过滤直接回显 —— 这就是漏洞
    return f"<html><body><h3>你输入的是：</h3><p>{user_input}</p></body></html>"

# 隐藏页面（目录扫描目标）
@app.route("/admin")
def admin():
    return "<h1>Admin Panel</h1><p>Welcome, admin!</p>"

@app.route("/backup")
def backup():
    return "<pre>database_backup_2026.sql (2.3 MB)</pre>"

if __name__ == "__main__":
    print("LightScanner 测试靶场已启动: http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
