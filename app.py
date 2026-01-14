from flask import Flask, request, jsonify, Response, render_template_string, session, redirect, url_for
import cloudscraper
import json
import uuid
import sqlite3
import secrets
from datetime import datetime
from functools import wraps
import os

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Admin credentials (override in Render env vars)
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'verse_admin_2026')

# SQLite DB path (Render persistent disk mounts in project directory)
DB_PATH = os.path.join(os.getcwd(), 'verse_api.db')

# Cloudscriper client
scraper = cloudscraper.create_scraper(
    browser={
        'browser': 'chrome',
        'platform': 'windows',
        'mobile': False
    }
)

# ---------- DB INIT ----------

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS api_keys
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  key_name TEXT NOT NULL,
                  api_key TEXT UNIQUE NOT NULL,
                  created_at TEXT NOT NULL,
                  total_requests INTEGER DEFAULT 0,
                  last_used TEXT,
                  status TEXT DEFAULT 'active')''')

    c.execute('''CREATE TABLE IF NOT EXISTS activity_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  api_key_id INTEGER,
                  endpoint TEXT,
                  model TEXT,
                  request_time TEXT,
                  response_status INTEGER,
                  ip_address TEXT,
                  FOREIGN KEY (api_key_id) REFERENCES api_keys (id))''')

    c.execute('''CREATE TABLE IF NOT EXISTS anonymous_ids
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  anonymous_id TEXT UNIQUE NOT NULL,
                  created_at TEXT NOT NULL,
                  usage_count INTEGER DEFAULT 0,
                  last_used TEXT,
                  status TEXT DEFAULT 'active')''')

    conn.commit()

    # Seed some anonymous ids if empty
    c.execute('SELECT COUNT(*) FROM anonymous_ids')
    count = c.fetchone()[0]
    if count == 0:
        for _ in range(20):
            anon_id = str(uuid.uuid4())
            c.execute('''INSERT OR IGNORE INTO anonymous_ids
                         (anonymous_id, created_at, usage_count, status)
                         VALUES (?, ?, 0, 'active')''',
                      (anon_id, datetime.now().isoformat()))
        conn.commit()

    conn.close()

init_db()

def get_anonymous_id():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute('''SELECT anonymous_id FROM anonymous_ids
                 WHERE status = 'active' AND usage_count < 100
                 ORDER BY RANDOM() LIMIT 1''')
    row = c.fetchone()

    if row:
        anon_id = row[0]
        c.execute('''UPDATE anonymous_ids
                     SET usage_count = usage_count + 1,
                         last_used = ?
                     WHERE anonymous_id = ?''',
                  (datetime.now().isoformat(), anon_id))
        conn.commit()
    else:
        anon_id = str(uuid.uuid4())
        c.execute('''INSERT INTO anonymous_ids
                     (anonymous_id, created_at, usage_count, last_used, status)
                     VALUES (?, ?, 1, ?, 'active')''',
                  (anon_id, datetime.now().isoformat(), datetime.now().isoformat()))
        conn.commit()

    conn.close()
    return anon_id

# ---------- DECORATORS & LOGGING ----------

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return wrapper

def require_api_key(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        if not api_key:
            return jsonify({'success': False, 'error': 'API key missing'}), 401

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT id, key_name, status FROM api_keys WHERE api_key = ?', (api_key,))
        row = c.fetchone()
        if not row:
            conn.close()
            return jsonify({'success': False, 'error': 'Invalid API key'}), 403
        if row[2] != 'active':
            conn.close()
            return jsonify({'success': False, 'error': 'API key disabled'}), 403

        c.execute('''UPDATE api_keys
                     SET total_requests = total_requests + 1,
                         last_used = ?
                     WHERE api_key = ?''',
                  (datetime.now().isoformat(), api_key))
        conn.commit()
        conn.close()

        request.api_key_info = {'id': row[0], 'name': row[1]}
        return f(*args, **kwargs)
    return wrapper

def log_activity(api_key_id, endpoint, model, status_code, ip):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''INSERT INTO activity_logs
                 (api_key_id, endpoint, model, request_time, response_status, ip_address)
                 VALUES (?, ?, ?, ?, ?, ?)''',
              (api_key_id, endpoint, model,
               datetime.now().isoformat(), status_code, ip))
    conn.commit()
    # keep last 1000 only
    c.execute('DELETE FROM activity_logs WHERE id NOT IN '
              '(SELECT id FROM activity_logs ORDER BY id DESC LIMIT 1000)')
    conn.commit()
    conn.close()

@app.after_request
def after_request(resp):
    resp.headers.add('Access-Control-Allow-Origin', '*')
    resp.headers.add('Access-Control-Allow-Headers', 'Content-Type,X-API-Key')
    resp.headers.add('Access-Control-Allow-Methods', 'GET,POST')
    return resp

# ---------- HTML TEMPLATES ----------

HOME_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Verse API - AI Gateway</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    * { margin:0; padding:0; box-sizing:border-box; }
    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      min-height:100vh;
      display:flex;
      justify-content:center;
      align-items:center;
      background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);
      padding:20px;
    }
    .card {
      background:#fff;
      border-radius:20px;
      box-shadow:0 20px 60px rgba(0,0,0,0.25);
      max-width:850px;
      width:100%;
      padding:40px 32px;
    }
    h1 {
      text-align:center;
      font-size:2.4rem;
      color:#4c51bf;
      margin-bottom:8px;
    }
    .subtitle {
      text-align:center;
      color:#4a5568;
      margin-bottom:24px;
    }
    .badge {
      display:inline-block;
      padding:6px 14px;
      border-radius:999px;
      background:linear-gradient(135deg,#16a34a,#22c55e);
      color:#fff;
      font-size:0.8rem;
      font-weight:600;
      margin-bottom:14px;
    }
    .section {
      background:#f7fafc;
      border-radius:16px;
      padding:20px 18px;
      margin-bottom:20px;
    }
    .section h2 {
      margin-bottom:10px;
      font-size:1.2rem;
      color:#2d3748;
    }
    label {
      display:block;
      font-size:0.9rem;
      color:#4a5568;
      margin-bottom:6px;
      font-weight:600;
    }
    input[type="text"] {
      width:100%;
      padding:10px 12px;
      border-radius:10px;
      border:2px solid #e2e8f0;
      font-size:0.95rem;
      outline:none;
      transition:border-color 0.2s;
    }
    input[type="text"]:focus {
      border-color:#667eea;
    }
    button {
      width:100%;
      margin-top:10px;
      padding:12px 14px;
      border:none;
      border-radius:10px;
      background:linear-gradient(135deg,#667eea,#764ba2);
      color:#fff;
      font-weight:600;
      font-size:0.95rem;
      cursor:pointer;
      transition:transform 0.15s, box-shadow 0.15s;
    }
    button:hover {
      transform:translateY(-1px);
      box-shadow:0 10px 25px rgba(102,126,234,0.45);
    }
    .result {
      margin-top:12px;
      padding:14px;
      border-radius:10px;
      display:none;
      font-size:0.9rem;
    }
    .result.success {
      background:#ecfdf3;
      border:1px solid #16a34a;
      color:#166534;
    }
    .result.error {
      background:#fef2f2;
      border:1px solid #dc2626;
      color:#b91c1c;
    }
    .api-key-box {
      margin:8px 0;
      padding:10px 12px;
      border-radius:8px;
      background:#fff;
      font-family:monospace;
      font-size:0.85rem;
      word-break:break-all;
      border:1px dashed #a0aec0;
    }
    ul { list-style:none; margin-top:8px; }
    li {
      padding:6px 0;
      border-bottom:1px solid #e2e8f0;
      font-size:0.9rem;
      color:#4a5568;
    }
    li:last-child { border-bottom:none; }
    li::before {
      content:"✓ ";
      color:#4c51bf;
      font-weight:700;
    }
    .nav {
      display:flex;
      gap:10px;
      margin-top:22px;
      flex-wrap:wrap;
    }
    .nav a {
      flex:1;
      min-width:120px;
      text-align:center;
      text-decoration:none;
      padding:9px 10px;
      border-radius:10px;
      font-size:0.9rem;
      color:#fff;
      background:#4a5568;
    }
    .nav a.admin { background:#dc2626; }
  </style>
</head>
<body>
  <div class="card">
    <div style="text-align:center;">
      <span class="badge">🆓 100% Free • Verse API</span>
    </div>
    <h1>Verse API</h1>
    <p class="subtitle">Production-ready AI chat API gateway with keys, usage and admin panel.</p>

    <div class="section">
      <h2>Generate your API key</h2>
      <label for="apiName">API key name</label>
      <input id="apiName" type="text" placeholder="e.g. My Project API">
      <button onclick="generateKey()">Generate key</button>
      <div id="keyResult" class="result"></div>
    </div>

    <div class="section">
      <h2>What you get</h2>
      <ul>
        <li>AI chat endpoint proxied to NoteGPT with cloudscraper</li>
        <li>Multiple models: GPT‑4.1 mini, DeepSeek, Gemini etc.</li>
        <li>Per-key usage tracking and statistics</li>
        <li>Admin panel with recent requests and key management</li>
        <li>Dynamic anonymous user tokens to reduce blocking</li>
      </ul>
    </div>

    <div class="nav">
      <a href="/documentation">📖 API docs</a>
      <a href="/check-usage">📊 Check usage</a>
      <a href="/admin/login" class="admin">🔐 Admin</a>
    </div>
  </div>

  <script>
    function generateKey() {
      const name = document.getElementById('apiName').value.trim();
      const box = document.getElementById('keyResult');
      if (!name) {
        box.className = 'result error';
        box.style.display = 'block';
        box.innerHTML = '<strong>Error:</strong> Please enter an API key name.';
        return;
      }
      fetch('/api/generate-key', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({key_name:name})
      })
      .then(r => r.json())
      .then(data => {
        if (data.success) {
          box.className = 'result success';
          box.innerHTML = `
            <strong>Key created!</strong>
            <div class="api-key-box">${data.api_key}</div>
            <div>Created at: ${data.created_at}</div>
            <div><strong>Save this key now. You won't see it again.</strong></div>
          `;
        } else {
          box.className = 'result error';
          box.innerHTML = '<strong>Error:</strong> ' + (data.error || 'Unexpected error');
        }
        box.style.display = 'block';
      })
      .catch(() => {
        box.className = 'result error';
        box.style.display = 'block';
        box.innerHTML = '<strong>Error:</strong> Failed to generate key.';
      });
    }
  </script>
</body>
</html>
"""

ADMIN_LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Admin login - Verse API</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    * { margin:0; padding:0; box-sizing:border-box; }
    body {
      font-family:system-ui;
      min-height:100vh;
      display:flex;
      justify-content:center;
      align-items:center;
      background:linear-gradient(135deg,#667eea,#764ba2);
      padding:20px;
    }
    .box {
      background:#fff;
      border-radius:20px;
      padding:30px 26px;
      max-width:380px;
      width:100%;
      box-shadow:0 18px 50px rgba(0,0,0,0.25);
    }
    h1 { text-align:center; color:#4c51bf; margin-bottom:18px; }
    .error {
      background:#fee2e2;
      border:1px solid #f97373;
      color:#b91c1c;
      border-radius:8px;
      padding:8px 10px;
      font-size:0.85rem;
      margin-bottom:12px;
    }
    label {
      display:block;
      font-size:0.85rem;
      color:#4b5563;
      margin-bottom:4px;
      font-weight:600;
    }
    input {
      width:100%;
      padding:9px 10px;
      border-radius:8px;
      border:2px solid #e5e7eb;
      margin-bottom:12px;
      font-size:0.9rem;
    }
    button {
      width:100%;
      padding:10px 12px;
      border-radius:8px;
      border:none;
      background:linear-gradient(135deg,#667eea,#764ba2);
      color:#fff;
      font-size:0.95rem;
      font-weight:600;
      cursor:pointer;
      margin-top:6px;
    }
    a {
      display:block;
      text-align:center;
      margin-top:12px;
      font-size:0.85rem;
      color:#4c51bf;
      text-decoration:none;
    }
  </style>
</head>
<body>
  <div class="box">
    <h1>Admin login</h1>
    {% if error %}
      <div class="error">{{ error }}</div>
    {% endif %}
    <form method="POST">
      <label>Username</label>
      <input name="username" required>
      <label>Password</label>
      <input name="password" type="password" required>
      <button type="submit">Login</button>
    </form>
    <a href="/">← Back to homepage</a>
  </div>
</body>
</html>
"""

ADMIN_DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Admin dashboard - Verse API</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    *{margin:0;padding:0;box-sizing:border-box;}
    body {
      font-family:system-ui;
      background:#f3f4f6;
      padding:18px;
    }
    .header {
      background:linear-gradient(135deg,#667eea,#764ba2);
      color:#fff;
      padding:18px 16px;
      border-radius:16px;
      display:flex;
      justify-content:space-between;
      align-items:center;
      margin-bottom:16px;
    }
    .header h1 { font-size:1.4rem; }
    .logout {
      background:rgba(255,255,255,0.2);
      color:#fff;
      padding:6px 12px;
      border-radius:999px;
      text-decoration:none;
      font-size:0.85rem;
      border:1px solid #e5e7eb;
    }
    .grid {
      display:grid;
      grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
      gap:10px;
      margin-bottom:16px;
    }
    .card {
      background:#fff;
      border-radius:14px;
      padding:14px 12px;
      box-shadow:0 2px 6px rgba(0,0,0,0.06);
    }
    .card h3 {
      font-size:0.8rem;
      color:#6b7280;
      margin-bottom:4px;
      text-transform:uppercase;
    }
    .card .num {
      font-size:1.6rem;
      color:#4c51bf;
      font-weight:700;
    }
    h2 {
      font-size:1rem;
      margin-bottom:8px;
      color:#111827;
    }
    table {
      width:100%;
      border-collapse:collapse;
      font-size:0.8rem;
    }
    th,td {
      padding:7px 6px;
      border-bottom:1px solid #e5e7eb;
      text-align:left;
      white-space:nowrap;
    }
    th {
      background:#f9fafb;
      font-weight:600;
      color:#4b5563;
    }
    .badge {
      display:inline-block;
      padding:2px 8px;
      border-radius:999px;
      font-size:0.7rem;
      font-weight:600;
    }
    .ok { background:#dcfce7; color:#166534; }
    .warn { background:#fee2e2; color:#b91c1c; }
    .section { margin-bottom:16px; }
    .section-inner {
      background:#fff;
      border-radius:14px;
      padding:12px;
      box-shadow:0 2px 6px rgba(0,0,0,0.06);
      overflow-x:auto;
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>Verse API admin</h1>
    <a class="logout" href="/admin/logout">Logout</a>
  </div>

  <div class="grid">
    <div class="card">
      <h3>Total keys</h3>
      <div class="num">{{ stats.total_keys }}</div>
    </div>
    <div class="card">
      <h3>Active keys</h3>
      <div class="num">{{ stats.active_keys }}</div>
    </div>
    <div class="card">
      <h3>Total requests</h3>
      <div class="num">{{ stats.total_requests }}</div>
    </div>
    <div class="card">
      <h3>Anonymous IDs</h3>
      <div class="num">{{ stats.anonymous_ids }}</div>
    </div>
  </div>

  <div class="section">
    <h2>Recent activity (last 20)</h2>
    <div class="section-inner">
      {% if recent_activity %}
      <table>
        <thead>
          <tr>
            <th>Time</th><th>Key</th><th>Endpoint</th><th>Model</th><th>Status</th><th>IP</th>
          </tr>
        </thead>
        <tbody>
          {% for r in recent_activity %}
          <tr>
            <td>{{ r[0][:19] }}</td>
            <td>{{ r[1] }}</td>
            <td>{{ r[2] }}</td>
            <td>{{ r[3] or 'N/A' }}</td>
            <td>
              {% if r[4] == 200 %}
                <span class="badge ok">{{ r[4] }}</span>
              {% else %}
                <span class="badge warn">{{ r[4] }}</span>
              {% endif %}
            </td>
            <td>{{ r[5] }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      {% else %}
        <p>No activity yet.</p>
      {% endif %}
    </div>
  </div>

  <div class="section">
    <h2>API keys</h2>
    <div class="section-inner">
      <table>
        <thead>
          <tr>
            <th>Name</th><th>Created</th><th>Requests</th><th>Last used</th><th>Status</th>
          </tr>
        </thead>
        <tbody>
          {% for k in api_keys %}
          <tr>
            <td>{{ k[0] }}</td>
            <td>{{ k[1][:19] }}</td>
            <td>{{ k[2] }}</td>
            <td>{{ k[3][:19] if k[3] else 'Never' }}</td>
            <td>{{ k[4] }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
</body>
</html>
"""

DOCUMENTATION_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>API docs - Verse API</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body{font-family:system-ui;background:#f3f4f6;padding:18px;}
    .container{
      max-width:900px;margin:0 auto;background:#fff;border-radius:18px;
      padding:26px 22px;box-shadow:0 6px 20px rgba(0,0,0,0.1);
    }
    h1{color:#4c51bf;margin-bottom:6px;}
    h2{margin-top:20px;margin-bottom:8px;color:#111827;}
    code{
      display:block;background:#111827;color:#e5e7eb;border-radius:8px;
      padding:10px 12px;font-size:0.85rem;overflow-x:auto;
    }
    .endpoint{margin-top:14px;padding:12px;border-left:3px solid #4c51bf;background:#f9fafb;border-radius:10px;}
    .badge{display:inline-block;padding:3px 8px;border-radius:999px;font-size:0.75rem;font-weight:600;color:#fff;}
    .get{background:#16a34a;} .post{background:#2563eb;}
    table{width:100%;border-collapse:collapse;font-size:0.85rem;margin-top:8px;}
    th,td{border:1px solid #e5e7eb;padding:6px 8px;text-align:left;}
    th{background:#eef2ff;}
    a.back{display:inline-block;margin-bottom:10px;color:#4c51bf;text-decoration:none;font-size:0.9rem;}
  </style>
</head>
<body>
  <div class="container">
    <a class="back" href="/">← Back to homepage</a>
    <h1>Verse API - documentation</h1>
    <p>Base URL: <code>https://verse-api-chat.onrender.com</code></p>

    <h2>Authentication</h2>
    <p>Include your API key either in header or query:</p>
    <code>X-API-Key: YOUR_KEY</code>
    <code>?api_key=YOUR_KEY</code>

    <h2>Endpoints</h2>

    <div class="endpoint">
      <span class="badge get">GET</span> <strong>/api/chat</strong>
      <p>Send a message and get AI response.</p>
      <table>
        <tr><th>Param</th><th>Required</th><th>Description</th></tr>
        <tr><td>api_key</td><td>Yes</td><td>Your API key</td></tr>
        <tr><td>mensaje / prompt / texto</td><td>Yes</td><td>Message content</td></tr>
        <tr><td>modelo</td><td>No</td><td>AI model (default gpt-4.1-mini)</td></tr>
      </table>
      <code>curl "https://verse-api-chat.onrender.com/api/chat?mensaje=Hello&api_key=YOUR_KEY"</code>
    </div>

    <div class="endpoint">
      <span class="badge get">GET</span> <strong>/api/modelos</strong>
      <p>List available models.</p>
    </div>

    <div class="endpoint">
      <span class="badge post">POST</span> <strong>/api/generate-key</strong>
      <p>Create a new API key.</p>
      <code>{ "key_name": "My project" }</code>
    </div>

    <div class="endpoint">
      <span class="badge get">GET</span> <strong>/api/usage</strong>
      <p>Get usage info for a key.</p>
      <code>/api/usage?api_key=YOUR_KEY</code>
    </div>
  </div>
</body>
</html>
"""

CHECK_USAGE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Check usage - Verse API</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    *{margin:0;padding:0;box-sizing:border-box;}
    body{
      font-family:system-ui;
      min-height:100vh;
      display:flex;
      justify-content:center;
      align-items:center;
      background:linear-gradient(135deg,#667eea,#764ba2);
      padding:20px;
    }
    .card{
      background:#fff;
      border-radius:20px;
      padding:32px 26px;
      max-width:480px;
      width:100%;
      box-shadow:0 20px 60px rgba(0,0,0,0.25);
    }
    h1{text-align:center;margin-bottom:6px;color:#4c51bf;}
    .subtitle{text-align:center;margin-bottom:22px;color:#4b5563;font-size:0.9rem;}
    label{display:block;font-size:0.85rem;color:#4b5563;margin-bottom:4px;font-weight:600;}
    input{
      width:100%;padding:9px 10px;border-radius:9px;border:2px solid #e5e7eb;
      margin-bottom:12px;font-size:0.9rem;
    }
    button{
      width:100%;padding:10px 12px;border-radius:9px;border:none;
      background:linear-gradient(135deg,#667eea,#764ba2);
      color:#fff;font-weight:600;font-size:0.9rem;cursor:pointer;
    }
    .result{
      margin-top:16px;padding:14px;border-radius:10px;display:none;font-size:0.85rem;
    }
    .success{background:#ecfdf3;border:1px solid #16a34a;color:#166534;}
    .error{background:#fef2f2;border:1px solid #dc2626;color:#b91c1c;}
    .row{display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid #e5e7eb;}
    .row:last-child{border-bottom:none;}
    .label{font-weight:600;color:#374151;}
    .value{color:#4c51bf;}
    a{
      display:block;margin-top:12px;text-align:center;font-size:0.8rem;
      color:#4c51bf;text-decoration:none;
    }
  </style>
</head>
<body>
  <div class="card">
    <h1>Check usage</h1>
    <p class="subtitle">Enter your API key to see total requests and timestamps.</p>
    <label for="apiKey">API key</label>
    <input id="apiKey" placeholder="vsk_...">
    <button onclick="checkUsage()">Search</button>
    <div id="res" class="result"></div>
    <a href="/">← Back to homepage</a>
  </div>

  <script>
    function checkUsage(){
      const key=document.getElementById('apiKey').value.trim();
      const box=document.getElementById('res');
      if(!key){
        box.className='result error';
        box.style.display='block';
        box.innerHTML='<strong>Error:</strong> enter a key.';
        return;
      }
      fetch('/api/usage?api_key='+encodeURIComponent(key))
      .then(r=>r.json())
      .then(d=>{
        if(d.success){
          box.className='result success';
          box.innerHTML=`
            <div class="row"><span class="label">Key name</span><span class="value">${d.key_name}</span></div>
            <div class="row"><span class="label">Total requests</span><span class="value">${d.total_requests}</span></div>
            <div class="row"><span class="label">Created at</span><span class="value">${d.created_at}</span></div>
            <div class="row"><span class="label">Last used</span><span class="value">${d.last_used || 'Never'}</span></div>
          `;
        } else {
          box.className='result error';
          box.innerHTML='<strong>Error:</strong> '+(d.error || 'Invalid key');
        }
        box.style.display='block';
      })
      .catch(()=>{
        box.className='result error';
        box.style.display='block';
        box.innerHTML='<strong>Error:</strong> failed to fetch usage.';
      });
    }
  </script>
</body>
</html>
"""

# ---------- ROUTES ----------

@app.route('/')
def home():
    return render_template_string(HOME_HTML)

@app.route('/documentation')
def documentation():
    return render_template_string(DOCUMENTATION_HTML)

@app.route('/check-usage')
def check_usage_page():
    return render_template_string(CHECK_USAGE_HTML)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        u = request.form.get('username', '')
        p = request.form.get('password', '')
        if u == ADMIN_USERNAME and p == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        return render_template_string(ADMIN_LOGIN_HTML, error="Invalid credentials")
    return render_template_string(ADMIN_LOGIN_HTML)

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('home'))

@app.route('/admin')
@admin_required
def admin_dashboard():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute('SELECT COUNT(*) FROM api_keys')
    total_keys = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM api_keys WHERE status='active'")
    active_keys = c.fetchone()[0]
    c.execute('SELECT SUM(total_requests) FROM api_keys')
    total_requests = c.fetchone()[0] or 0
    c.execute('SELECT COUNT(*) FROM anonymous_ids')
    anon_count = c.fetchone()[0]

    stats = {
        'total_keys': total_keys,
        'active_keys': active_keys,
        'total_requests': total_requests,
        'anonymous_ids': anon_count
    }

    c.execute('''SELECT al.request_time, ak.key_name, al.endpoint, al.model,
                        al.response_status, al.ip_address
                 FROM activity_logs al
                 JOIN api_keys ak ON al.api_key_id = ak.id
                 ORDER BY al.request_time DESC LIMIT 20''')
    recent = c.fetchall()

    c.execute('''SELECT key_name, created_at, total_requests, last_used, status, id
                 FROM api_keys ORDER BY created_at DESC''')
    api_keys = c.fetchall()

    conn.close()
    return render_template_string(ADMIN_DASHBOARD_HTML,
                                  stats=stats,
                                  recent_activity=recent,
                                  api_keys=api_keys)

# ---------- API ENDPOINTS ----------

@app.route('/api/generate-key', methods=['POST'])
def generate_key():
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get('key_name') or '').strip()
    if not name:
        return jsonify({'success': False, 'error': 'key_name is required'}), 400

    api_key = 'vsk_' + secrets.token_urlsafe(32)
    created_at = datetime.now().isoformat()

    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''INSERT INTO api_keys (key_name, api_key, created_at, total_requests, status)
                     VALUES (?, ?, ?, 0, 'active')''',
                  (name, api_key, created_at))
        conn.commit()
        conn.close()
        return jsonify({
            'success': True,
            'api_key': api_key,
            'key_name': name,
            'created_at': created_at
        }), 201
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/usage', methods=['GET'])
def usage():
    api_key = request.args.get('api_key')
    if not api_key:
        return jsonify({'success': False, 'error': 'api_key required'}), 400

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''SELECT key_name, total_requests, created_at, last_used
                 FROM api_keys WHERE api_key = ?''', (api_key,))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify({'success': False, 'error': 'Invalid API key'}), 404

    return jsonify({
        'success': True,
        'key_name': row[0],
        'total_requests': row[1],
        'created_at': row[2],
        'last_used': row[3]
    })

@app.route('/api/modelos', methods=['GET'])
def modelos():
    models = [
        "TA/deepseek-ai/DeepSeek-V3",
        "TA/deepseek-ai/DeepSeek-R1",
        "gpt-4.1-mini",
        "gemini-3-flash-preview"
    ]
    return jsonify({'modelos': models, 'default': 'gpt-4.1-mini'})

@app.route('/api/chat', methods=['GET'])
@require_api_key
def chat():
    modelo = request.args.get('modelo', 'gpt-4.1-mini')
    mensaje = request.args.get('mensaje') or request.args.get('prompt') or request.args.get('texto')
    if not mensaje:
        return jsonify({'success': False,
                        'error': 'Missing mensaje / prompt / texto'}), 400

    anon_id = get_anonymous_id()
    url = "https://notegpt.io/api/v2/chat/stream"

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Referer": "https://notegpt.io/ai-chat",
        "Origin": "https://notegpt.io",
        "Cookie": f"anonymous_user_id={anon_id}",
        "Accept": "text/event-stream"
    }

    payload = {
        "message": mensaje,
        "model": modelo,
        "tone": "default",
        "length": "moderate",
        "conversation_id": str(uuid.uuid4())
    }

    try:
        resp = scraper.post(url, headers=headers, json=payload, stream=True, timeout=50)
        status = resp.status_code
        if status != 200:
            log_activity(request.api_key_info['id'], '/api/chat', modelo,
                         status, request.remote_addr)
            return jsonify({'success': False, 'error': f'Upstream error {status}'}), status

        text = resp.content.decode('utf-8', errors='ignore')
        respuesta = ""
        razon = ""
        for line in text.splitlines():
            if line.startswith('data:'):
                try:
                    js = line[5:].strip()
                    if not js:
                        continue
                    obj = json.loads(js)
                    if obj.get('text'):
                        respuesta += obj['text']
                    if obj.get('reasoning'):
                        razon += obj['reasoning']
                except Exception:
                    continue

        if not respuesta.strip():
            log_activity(request.api_key_info['id'], '/api/chat', modelo,
                         500, request.remote_addr)
            return jsonify({'success': False,
                            'error': 'No text content from upstream'}), 500

        log_activity(request.api_key_info['id'], '/api/chat', modelo,
                     200, request.remote_addr)

        out = {
            'success': True,
            'respuesta': respuesta.strip(),
            'modelo': modelo,
            'pregunta': mensaje
        }
        if razon.strip():
            out['razonamiento'] = razon.strip()
        return jsonify(out)
    except Exception as e:
        log_activity(request.api_key_info['id'], '/api/chat', modelo,
                     500, request.remote_addr)
        return jsonify({'success': False, 'error': str(e)}), 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
