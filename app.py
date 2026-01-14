from flask import Flask, request, jsonify, Response, render_template_string, session, redirect, url_for
import cloudscraper
import json
import uuid
import sqlite3
import secrets
import hashlib
from datetime import datetime, timedelta
from functools import wraps
import os
import random

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False
app.config['SECRET_KEY'] = secrets.token_hex(32)  # For session management

# Initialize cloudscraper
scraper = cloudscraper.create_scraper(
    browser={
        'browser': 'chrome',
        'platform': 'windows',
        'mobile': False
    }
)

# Admin credentials (change these!)
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "verse_admin_2026"  # CHANGE THIS IN PRODUCTION!

# Database initialization
def init_db():
    conn = sqlite3.connect('verse_api.db')
    c = conn.cursor()
    
    # API Keys table
    c.execute('''CREATE TABLE IF NOT EXISTS api_keys
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  key_name TEXT NOT NULL,
                  api_key TEXT UNIQUE NOT NULL,
                  created_at TEXT NOT NULL,
                  total_requests INTEGER DEFAULT 0,
                  last_used TEXT,
                  status TEXT DEFAULT 'active')''')
    
    # Activity logs table
    c.execute('''CREATE TABLE IF NOT EXISTS activity_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  api_key_id INTEGER,
                  endpoint TEXT,
                  model TEXT,
                  request_time TEXT,
                  response_status INTEGER,
                  ip_address TEXT,
                  FOREIGN KEY (api_key_id) REFERENCES api_keys (id))''')
    
    # Anonymous IDs pool table
    c.execute('''CREATE TABLE IF NOT EXISTS anonymous_ids
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  anonymous_id TEXT UNIQUE NOT NULL,
                  created_at TEXT NOT NULL,
                  usage_count INTEGER DEFAULT 0,
                  last_used TEXT,
                  status TEXT DEFAULT 'active')''')
    
    conn.commit()
    conn.close()

init_db()

# Generate or rotate anonymous IDs
def get_anonymous_id():
    """Get a random active anonymous ID from pool or generate new one"""
    conn = sqlite3.connect('verse_api.db')
    c = conn.cursor()
    
    # Try to get an active ID with low usage
    c.execute('''SELECT anonymous_id FROM anonymous_ids 
                 WHERE status = 'active' AND usage_count < 100 
                 ORDER BY RANDOM() LIMIT 1''')
    result = c.fetchone()
    
    if result:
        anon_id = result[0]
        # Update usage
        c.execute('''UPDATE anonymous_ids 
                     SET usage_count = usage_count + 1, 
                         last_used = ? 
                     WHERE anonymous_id = ?''', 
                  (datetime.now().isoformat(), anon_id))
        conn.commit()
    else:
        # Generate new anonymous ID
        anon_id = str(uuid.uuid4())
        c.execute('''INSERT INTO anonymous_ids 
                     (anonymous_id, created_at, usage_count, last_used, status)
                     VALUES (?, ?, 1, ?, 'active')''',
                  (anon_id, datetime.now().isoformat(), datetime.now().isoformat()))
        conn.commit()
    
    conn.close()
    return anon_id

# Admin authentication decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# API Key decorator with logging
def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        
        if not api_key:
            return jsonify({
                'error': 'API key missing. Provide it via X-API-Key header or api_key parameter',
                'success': False
            }), 401
        
        conn = sqlite3.connect('verse_api.db')
        c = conn.cursor()
        c.execute('SELECT id, key_name, status FROM api_keys WHERE api_key = ?', (api_key,))
        result = c.fetchone()
        
        if not result:
            conn.close()
            return jsonify({
                'error': 'Invalid API key',
                'success': False
            }), 403
        
        if result[2] != 'active':
            conn.close()
            return jsonify({
                'error': 'API key is disabled',
                'success': False
            }), 403
        
        # Update usage
        c.execute('''UPDATE api_keys 
                     SET total_requests = total_requests + 1, 
                         last_used = ? 
                     WHERE api_key = ?''', 
                  (datetime.now().isoformat(), api_key))
        conn.commit()
        conn.close()
        
        request.api_key_info = {'id': result[0], 'name': result[1]}
        return f(*args, **kwargs)
    
    return decorated_function

# Log activity
def log_activity(api_key_id, endpoint, model, status, ip_address):
    conn = sqlite3.connect('verse_api.db')
    c = conn.cursor()
    c.execute('''INSERT INTO activity_logs 
                 (api_key_id, endpoint, model, request_time, response_status, ip_address)
                 VALUES (?, ?, ?, ?, ?, ?)''',
              (api_key_id, endpoint, model, datetime.now().isoformat(), status, ip_address))
    conn.commit()
    conn.close()

# CORS
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,X-API-Key')
    response.headers.add('Access-Control-Allow-Methods', 'GET,POST')
    return response

# ============ ADMIN PANEL ============

ADMIN_LOGIN_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login - Verse API</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .login-container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 400px;
            width: 100%;
            padding: 40px;
        }
        h1 {
            color: #667eea;
            text-align: center;
            margin-bottom: 30px;
        }
        .input-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            color: #555;
            margin-bottom: 8px;
            font-weight: 600;
        }
        input {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 14px;
        }
        input:focus {
            outline: none;
            border-color: #667eea;
        }
        button {
            width: 100%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 12px;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        .error {
            background: #f8d7da;
            color: #721c24;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 15px;
            text-align: center;
        }
        .back-link {
            display: block;
            text-align: center;
            margin-top: 15px;
            color: #667eea;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>🔐 Admin Login</h1>
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        <form method="POST">
            <div class="input-group">
                <label>Username</label>
                <input type="text" name="username" required>
            </div>
            <div class="input-group">
                <label>Password</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit">Login</button>
        </form>
        <a href="/" class="back-link">← Back to Home</a>
    </div>
</body>
</html>
'''

ADMIN_DASHBOARD_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - Verse API</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f7fa;
            padding: 20px;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px 30px;
            border-radius: 15px;
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 { font-size: 1.8em; }
        .logout-btn {
            background: rgba(255,255,255,0.2);
            color: white;
            border: 2px solid white;
            padding: 8px 20px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .stat-card h3 {
            color: #666;
            font-size: 0.9em;
            margin-bottom: 10px;
            text-transform: uppercase;
        }
        .stat-card .number {
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }
        .section {
            background: white;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .section h2 {
            color: #333;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #eee;
        }
        th {
            background: #f8f9fa;
            font-weight: 600;
            color: #555;
        }
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
        }
        .badge-success { background: #d4edda; color: #155724; }
        .badge-warning { background: #fff3cd; color: #856404; }
        .badge-danger { background: #f8d7da; color: #721c24; }
        .btn-small {
            padding: 5px 15px;
            border-radius: 5px;
            border: none;
            cursor: pointer;
            font-size: 0.85em;
            font-weight: 600;
        }
        .btn-danger { background: #dc3545; color: white; }
        .btn-success { background: #28a745; color: white; }
        .refresh-btn {
            background: #667eea;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            margin-bottom: 15px;
        }
        .refresh-btn:hover { background: #5568d3; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🎛️ Admin Dashboard - Verse API</h1>
        <a href="/admin/logout" class="logout-btn">Logout</a>
    </div>

    <div class="stats-grid">
        <div class="stat-card">
            <h3>Total API Keys</h3>
            <div class="number">{{ stats.total_keys }}</div>
        </div>
        <div class="stat-card">
            <h3>Active Keys</h3>
            <div class="number">{{ stats.active_keys }}</div>
        </div>
        <div class="stat-card">
            <h3>Total Requests</h3>
            <div class="number">{{ stats.total_requests }}</div>
        </div>
        <div class="stat-card">
            <h3>Anonymous IDs</h3>
            <div class="number">{{ stats.anonymous_ids }}</div>
        </div>
    </div>

    <div class="section">
        <h2>Recent Activity (Last 20)</h2>
        <table>
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Key Name</th>
                    <th>Endpoint</th>
                    <th>Model</th>
                    <th>Status</th>
                    <th>IP</th>
                </tr>
            </thead>
            <tbody>
                {% for activity in recent_activity %}
                <tr>
                    <td>{{ activity[0] }}</td>
                    <td>{{ activity[1] }}</td>
                    <td>{{ activity[2] }}</td>
                    <td>{{ activity[3] or 'N/A' }}</td>
                    <td>
                        {% if activity[4] == 200 %}
                        <span class="badge badge-success">{{ activity[4] }}</span>
                        {% elif activity[4] >= 400 and activity[4] < 500 %}
                        <span class="badge badge-warning">{{ activity[4] }}</span>
                        {% else %}
                        <span class="badge badge-danger">{{ activity[4] }}</span>
                        {% endif %}
                    </td>
                    <td>{{ activity[5] }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2>API Keys Management</h2>
        <table>
            <thead>
                <tr>
                    <th>Key Name</th>
                    <th>Created</th>
                    <th>Requests</th>
                    <th>Last Used</th>
                    <th>Status</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                {% for key in api_keys %}
                <tr>
                    <td>{{ key[0] }}</td>
                    <td>{{ key[1] }}</td>
                    <td>{{ key[2] }}</td>
                    <td>{{ key[3] or 'Never' }}</td>
                    <td>
                        {% if key[4] == 'active' %}
                        <span class="badge badge-success">Active</span>
                        {% else %}
                        <span class="badge badge-danger">Disabled</span>
                        {% endif %}
                    </td>
                    <td>
                        {% if key[4] == 'active' %}
                        <button class="btn-small btn-danger" onclick="toggleKey('{{ key[5] }}', 'disable')">Disable</button>
                        {% else %}
                        <button class="btn-small btn-success" onclick="toggleKey('{{ key[5] }}', 'enable')">Enable</button>
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2>Anonymous IDs Pool</h2>
        <button class="refresh-btn" onclick="generateNewIds()">Generate 10 New IDs</button>
        <table>
            <thead>
                <tr>
                    <th>Anonymous ID</th>
                    <th>Created</th>
                    <th>Usage Count</th>
                    <th>Last Used</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {% for aid in anonymous_ids %}
                <tr>
                    <td>{{ aid[0] }}</td>
                    <td>{{ aid[1] }}</td>
                    <td>{{ aid[2] }}</td>
                    <td>{{ aid[3] or 'Never' }}</td>
                    <td>
                        {% if aid[2] >= 100 %}
                        <span class="badge badge-warning">High Usage</span>
                        {% else %}
                        <span class="badge badge-success">Active</span>
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

    <script>
        function toggleKey(keyId, action) {
            if (confirm(`Are you sure you want to ${action} this key?`)) {
                fetch('/admin/toggle-key', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ key_id: keyId, action: action })
                })
                .then(res => res.json())
                .then(data => {
                    if (data.success) {
                        location.reload();
                    } else {
                        alert('Error: ' + data.error);
                    }
                });
            }
        }

        function generateNewIds() {
            fetch('/admin/generate-anonymous-ids', { method: 'POST' })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    alert(`Generated ${data.count} new anonymous IDs`);
                    location.reload();
                } else {
                    alert('Error: ' + data.error);
                }
            });
        }
    </script>
</body>
</html>
'''

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            return render_template_string(ADMIN_LOGIN_HTML, error="Invalid credentials")
    
    return render_template_string(ADMIN_LOGIN_HTML)

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('home'))

@app.route('/admin')
@admin_required
def admin_dashboard():
    conn = sqlite3.connect('verse_api.db')
    c = conn.cursor()
    
    # Get statistics
    c.execute('SELECT COUNT(*) FROM api_keys')
    total_keys = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM api_keys WHERE status = 'active'")
    active_keys = c.fetchone()[0]
    
    c.execute('SELECT SUM(total_requests) FROM api_keys')
    total_requests = c.fetchone()[0] or 0
    
    c.execute('SELECT COUNT(*) FROM anonymous_ids')
    anonymous_ids_count = c.fetchone()[0]
    
    stats = {
        'total_keys': total_keys,
        'active_keys': active_keys,
        'total_requests': total_requests,
        'anonymous_ids': anonymous_ids_count
    }
    
    # Get recent activity
    c.execute('''SELECT al.request_time, ak.key_name, al.endpoint, al.model, 
                        al.response_status, al.ip_address
                 FROM activity_logs al
                 JOIN api_keys ak ON al.api_key_id = ak.id
                 ORDER BY al.request_time DESC LIMIT 20''')
    recent_activity = c.fetchall()
    
    # Get all API keys
    c.execute('''SELECT key_name, created_at, total_requests, last_used, status, id
                 FROM api_keys ORDER BY created_at DESC''')
    api_keys = c.fetchall()
    
    # Get anonymous IDs
    c.execute('''SELECT anonymous_id, created_at, usage_count, last_used
                 FROM anonymous_ids ORDER BY created_at DESC LIMIT 50''')
    anonymous_ids = c.fetchall()
    
    conn.close()
    
    return render_template_string(ADMIN_DASHBOARD_HTML, 
                                 stats=stats,
                                 recent_activity=recent_activity,
                                 api_keys=api_keys,
                                 anonymous_ids=anonymous_ids)

@app.route('/admin/toggle-key', methods=['POST'])
@admin_required
def toggle_key():
    data = request.get_json()
    key_id = data.get('key_id')
    action = data.get('action')
    
    new_status = 'active' if action == 'enable' else 'disabled'
    
    conn = sqlite3.connect('verse_api.db')
    c = conn.cursor()
    c.execute('UPDATE api_keys SET status = ? WHERE id = ?', (new_status, key_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/admin/generate-anonymous-ids', methods=['POST'])
@admin_required
def generate_anonymous_ids():
    conn = sqlite3.connect('verse_api.db')
    c = conn.cursor()
    
    count = 0
    for _ in range(10):
        anon_id = str(uuid.uuid4())
        try:
            c.execute('''INSERT INTO anonymous_ids 
                         (anonymous_id, created_at, usage_count, status)
                         VALUES (?, ?, 0, 'active')''',
                      (anon_id, datetime.now().isoformat()))
            count += 1
        except:
            continue
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'count': count})

# ============ WEB INTERFACE (Same as before) ============

HOME_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verse API - Professional API Gateway</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 800px;
            width: 100%;
            padding: 50px;
        }
        h1 {
            color: #667eea;
            font-size: 2.5em;
            margin-bottom: 10px;
            text-align: center;
        }
        .subtitle {
            text-align: center;
            color: #666;
            margin-bottom: 40px;
            font-size: 1.1em;
        }
        .free-badge {
            background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
            color: white;
            padding: 8px 20px;
            border-radius: 20px;
            font-weight: bold;
            display: inline-block;
            margin-bottom: 20px;
        }
        .section {
            background: #f8f9fa;
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 20px;
        }
        .section h2 {
            color: #333;
            margin-bottom: 20px;
            font-size: 1.5em;
        }
        .input-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            color: #555;
            margin-bottom: 8px;
            font-weight: 600;
        }
        input[type="text"] {
            width: 100%;
            padding: 15px;
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        input[type="text"]:focus {
            outline: none;
            border-color: #667eea;
        }
        button {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 15px 40px;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            width: 100%;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4);
        }
        .result {
            margin-top: 20px;
            padding: 20px;
            border-radius: 10px;
            display: none;
        }
        .result.success {
            background: #d4edda;
            border: 2px solid #28a745;
            color: #155724;
        }
        .result.error {
            background: #f8d7da;
            border: 2px solid #dc3545;
            color: #721c24;
        }
        .api-key-display {
            background: white;
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
            word-break: break-all;
            font-family: 'Courier New', monospace;
            font-size: 14px;
        }
        .nav-buttons {
            display: flex;
            gap: 15px;
            margin-top: 30px;
            flex-wrap: wrap;
        }
        .nav-buttons a {
            flex: 1;
            min-width: 150px;
            text-align: center;
            padding: 12px;
            background: #6c757d;
            color: white;
            text-decoration: none;
            border-radius: 10px;
            transition: background 0.3s;
        }
        .nav-buttons a:hover {
            background: #5a6268;
        }
        .admin-link {
            background: #dc3545 !important;
        }
        .admin-link:hover {
            background: #c82333 !important;
        }
        .feature-list {
            list-style: none;
            margin-top: 15px;
        }
        .feature-list li {
            padding: 10px 0;
            border-bottom: 1px solid #e0e0e0;
            color: #555;
        }
        .feature-list li:last-child {
            border-bottom: none;
        }
        .feature-list li:before {
            content: "✓ ";
            color: #667eea;
            font-weight: bold;
            margin-right: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Verse API</h1>
        <div style="text-align: center;">
            <span class="free-badge">🆓 100% FREE SERVICE</span>
        </div>
        <p class="subtitle">Professional AI Chat API Gateway</p>
        
        <div class="section">
            <h2>Generate Your API Key</h2>
            <div class="input-group">
                <label for="apiName">API Key Name</label>
                <input type="text" id="apiName" placeholder="e.g., My Project API" />
            </div>
            <button onclick="generateKey()">Generate API Key</button>
            <div id="keyResult" class="result"></div>
        </div>

        <div class="section">
            <h2>Features</h2>
            <ul class="feature-list">
                <li>Multiple AI Models (GPT-4, DeepSeek, Gemini)</li>
                <li>Automatic Language Detection</li>
                <li>Usage Tracking & Analytics</li>
                <li>Dynamic Token Rotation for Reliability</li>
                <li>Cloudflare Bypass with Cloudscraper</li>
                <li>RESTful JSON API</li>
                <li>100% Free Forever</li>
            </ul>
        </div>

        <div class="nav-buttons">
            <a href="/documentation">📖 API Docs</a>
            <a href="/check-usage">📊 Check Usage</a>
            <a href="/admin/login" class="admin-link">🔐 Admin Panel</a>
        </div>
    </div>

    <script>
        function generateKey() {
            const name = document.getElementById('apiName').value;
            const resultDiv = document.getElementById('keyResult');
            
            if (!name.trim()) {
                resultDiv.className = 'result error';
                resultDiv.style.display = 'block';
                resultDiv.innerHTML = '<strong>Error:</strong> Please enter an API key name';
                return;
            }
            
            fetch('/api/generate-key', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ key_name: name })
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    resultDiv.className = 'result success';
                    resultDiv.innerHTML = `
                        <strong>✓ Success!</strong> Your API key has been generated:
                        <div class="api-key-display">${data.api_key}</div>
                        <p><strong>Important:</strong> Save this key securely. You won't be able to see it again!</p>
                        <p><strong>Created:</strong> ${data.created_at}</p>
                    `;
                } else {
                    resultDiv.className = 'result error';
                    resultDiv.innerHTML = `<strong>Error:</strong> ${data.error}`;
                }
                resultDiv.style.display = 'block';
            })
            .catch(err => {
                resultDiv.className = 'result error';
                resultDiv.innerHTML = '<strong>Error:</strong> Failed to generate key';
                resultDiv.style.display = 'block';
            });
        }
    </script>
</body>
</html>
'''

# [Previous DOCUMENTATION_HTML and CHECK_USAGE_HTML remain the same]
DOCUMENTATION_HTML = '''[Same as before - keeping it for brevity]'''
CHECK_USAGE_HTML = '''[Same as before - keeping it for brevity]'''

@app.route('/')
def home():
    return render_template_string(HOME_HTML)

@app.route('/documentation')
def documentation():
    return render_template_string(DOCUMENTATION_HTML)

@app.route('/check-usage')
def check_usage_page():
    return render_template_string(CHECK_USAGE_HTML)

# ============ API ENDPOINTS ============

@app.route('/api/generate-key', methods=['POST'])
def generate_key():
    """Generate a new API key"""
    data = request.get_json()
    key_name = data.get('key_name')
    
    if not key_name or not key_name.strip():
        return jsonify({
            'error': 'key_name is required',
            'success': False
        }), 400
    
    api_key = 'vsk_' + secrets.token_urlsafe(32)
    created_at = datetime.now().isoformat()
    
    try:
        conn = sqlite3.connect('verse_api.db')
        c = conn.cursor()
        c.execute('''INSERT INTO api_keys (key_name, api_key, created_at, total_requests, status)
                     VALUES (?, ?, ?, 0, 'active')''', (key_name.strip(), api_key, created_at))
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'api_key': api_key,
            'key_name': key_name.strip(),
            'created_at': created_at
        }), 201
    except sqlite3.IntegrityError:
        return jsonify({
            'error': 'Failed to generate key. Please try again.',
            'success': False
        }), 500

@app.route('/api/usage', methods=['GET'])
def get_usage():
    """Get API key usage statistics"""
    api_key = request.args.get('api_key')
    
    if not api_key:
        return jsonify({
            'error': 'api_key parameter is required',
            'success': False
        }), 400
    
    conn = sqlite3.connect('verse_api.db')
    c = conn.cursor()
    c.execute('''SELECT key_name, total_requests, created_at, last_used 
                 FROM api_keys WHERE api_key = ?''', (api_key,))
    result = c.fetchone()
    conn.close()
    
    if not result:
        return jsonify({
            'error': 'Invalid API key',
            'success': False
        }), 404
    
    return jsonify({
        'success': True,
        'key_name': result[0],
        'total_requests': result[1],
        'created_at': result[2],
        'last_used': result[3]
    })

@app.route('/api/chat', methods=['GET'])
@require_api_key
def chat():
    """Main chat endpoint with AI using cloudscraper"""
    modelo = request.args.get('modelo', 'gpt-4.1-mini')
    mensaje = request.args.get('mensaje') or request.args.get('prompt') or request.args.get('texto')
    
    if not mensaje:
        return Response(
            json.dumps({
                'error': 'Missing parameter: mensaje, prompt, or texto',
                'success': False
            }, ensure_ascii=False, indent=2),
            mimetype='application/json; charset=utf-8',
            status=400
        )
    
    # Get dynamic anonymous ID
    anonymous_id = get_anonymous_id()
    
    url = "https://notegpt.io/api/v2/chat/stream"
    
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Referer": "https://notegpt.io/ai-chat",
        "Origin": "https://notegpt.io",
        "Cookie": f"anonymous_user_id={anonymous_id}",
        "Accept": "text/event-stream",
        "Accept-Language": "en-US,en;q=0.9"
    }
    
    payload = {
        "message": mensaje,
        "model": modelo,
        "tone": "default",
        "length": "moderate",
        "conversation_id": str(uuid.uuid4())
    }
    
    try:
        # Use cloudscraper for better reliability
        response = scraper.post(url, headers=headers, json=payload, stream=True, timeout=60)
        
        if response.status_code != 200:
            log_activity(request.api_key_info['id'], '/api/chat', modelo, 
                        response.status_code, request.remote_addr)
            return Response(
                json.dumps({
                    'error': f'Error {response.status_code}',
                    'success': False
                }, ensure_ascii=False, indent=2),
                mimetype='application/json; charset=utf-8',
                status=response.status_code
            )
        
        responseText = response.content.decode('utf-8')
        
        if not responseText or not responseText.strip():
            log_activity(request.api_key_info['id'], '/api/chat', modelo, 
                        500, request.remote_addr)
            return Response(
                json.dumps({
                    'error': 'Empty response from AI service',
                    'success': False
                }, ensure_ascii=False, indent=2),
                mimetype='application/json; charset=utf-8',
                status=500
            )
        
        respuesta_completa = ""
        razonamiento = ""
        
        for line in responseText.split('
'):
            if line.startswith('data:'):
                try:
                    jsonStr = line.replace('data:', '').strip()
                    if not jsonStr:
                        continue
                    
                    data = json.loads(jsonStr)
                    
                    if data.get('text'):
                        respuesta_completa += data['text']
                    
                    if data.get('reasoning'):
                        razonamiento += data['reasoning']
                        
                except:
                    continue
        
        if not respuesta_completa.strip():
            log_activity(request.api_key_info['id'], '/api/chat', modelo, 
                        500, request.remote_addr)
            return Response(
                json.dumps({
                    'error': 'No text content extracted from AI service',
                    'success': False
                }, ensure_ascii=False, indent=2),
                mimetype='application/json; charset=utf-8',
                status=500
            )
        
        # Log successful activity
        log_activity(request.api_key_info['id'], '/api/chat', modelo, 
                    200, request.remote_addr)
        
        resultado = {
            'success': True,
            'respuesta': respuesta_completa.strip(),
            'modelo': modelo,
            'pregunta': mensaje
        }
        
        if razonamiento.strip():
            resultado['razonamiento'] = razonamiento.strip()
        
        return Response(
            json.dumps(resultado, ensure_ascii=False, indent=2),
            mimetype='application/json; charset=utf-8',
            status=200
        )
                    
    except Exception as e:
        log_activity(request.api_key_info['id'], '/api/chat', modelo, 
                    500, request.remote_addr)
        return Response(
            json.dumps({
                'error': str(e),
                'success': False
            }, ensure_ascii=False, indent=2),
            mimetype='application/json; charset=utf-8',
            status=500
        )

@app.route('/api/modelos', methods=['GET'])
def modelos():
    """List available AI models"""
    available_models = [
        "TA/deepseek-ai/DeepSeek-V3",
        "TA/deepseek-ai/DeepSeek-R1",
        "gpt-4.1-mini",
        "gemini-3-flash-preview"
    ]
    return Response(
        json.dumps({
            'modelos': available_models,
            'default': 'gpt-4.1-mini'
        }, ensure_ascii=False, indent=2),
        mimetype='application/json; charset=utf-8'
    )

# For Vercel
if __name__ == '__main__':
    app.run(debug=False)
