from flask import Flask, request, jsonify, Response, render_template_string, session, redirect, url_for
import cloudscraper
import json
import uuid
import secrets
import hashlib
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict
import threading

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False
app.config['SECRET_KEY'] = secrets.token_hex(32)

# Initialize cloudscraper
scraper = cloudscraper.create_scraper(
    browser={
        'browser': 'chrome',
        'platform': 'windows',
        'mobile': False
    }
)

# Admin credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "verse_admin_2026"

# In-memory storage (for Vercel serverless)
api_keys_db = {}  # {api_key: {name, created_at, requests, last_used, status}}
activity_logs = []  # List of activity records
anonymous_ids_pool = []  # Pool of anonymous IDs
lock = threading.Lock()

# Initialize some anonymous IDs
for _ in range(10):
    anonymous_ids_pool.append({
        'id': str(uuid.uuid4()),
        'created_at': datetime.now().isoformat(),
        'usage_count': 0,
        'last_used': None
    })

def get_anonymous_id():
    """Get a random anonymous ID from pool"""
    with lock:
        if not anonymous_ids_pool:
            # Generate new one if pool is empty
            new_id = str(uuid.uuid4())
            anonymous_ids_pool.append({
                'id': new_id,
                'created_at': datetime.now().isoformat(),
                'usage_count': 0,
                'last_used': None
            })
        
        # Get ID with lowest usage
        anon_entry = min(anonymous_ids_pool, key=lambda x: x['usage_count'])
        anon_entry['usage_count'] += 1
        anon_entry['last_used'] = datetime.now().isoformat()
        
        # Rotate if usage is high
        if anon_entry['usage_count'] > 50:
            new_id = str(uuid.uuid4())
            anonymous_ids_pool.append({
                'id': new_id,
                'created_at': datetime.now().isoformat(),
                'usage_count': 0,
                'last_used': None
            })
        
        return anon_entry['id']

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        
        if not api_key:
            return jsonify({
                'error': 'API key missing. Provide it via X-API-Key header or api_key parameter',
                'success': False
            }), 401
        
        with lock:
            if api_key not in api_keys_db:
                return jsonify({
                    'error': 'Invalid API key',
                    'success': False
                }), 403
            
            key_data = api_keys_db[api_key]
            
            if key_data['status'] != 'active':
                return jsonify({
                    'error': 'API key is disabled',
                    'success': False
                }), 403
            
            # Update usage
            key_data['requests'] += 1
            key_data['last_used'] = datetime.now().isoformat()
        
        request.api_key_info = {'name': key_data['name']}
        return f(*args, **kwargs)
    
    return decorated_function

def log_activity(api_key_name, endpoint, model, status, ip_address):
    with lock:
        activity_logs.append({
            'time': datetime.now().isoformat(),
            'key_name': api_key_name,
            'endpoint': endpoint,
            'model': model,
            'status': status,
            'ip': ip_address
        })
        # Keep only last 100 logs
        if len(activity_logs) > 100:
            activity_logs.pop(0)

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
            flex-wrap: wrap;
        }
        .header h1 { font-size: 1.5em; }
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
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
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
        }
        .stat-card .number {
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }
        .section {
            background: white;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
            overflow-x: auto;
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
            min-width: 600px;
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
        .warning-box {
            background: #fff3cd;
            border: 2px solid #ffc107;
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        .warning-box strong {
            color: #856404;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🎛️ Admin Dashboard - Verse API</h1>
        <a href="/admin/logout" class="logout-btn">Logout</a>
    </div>

    <div class="warning-box">
        <strong>⚠️ Note:</strong> This data is stored in memory and will reset on each deployment. For persistent storage, upgrade to Vercel Postgres or another database.
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
        {% if recent_activity %}
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
                    <td>{{ activity.time[:19] }}</td>
                    <td>{{ activity.key_name }}</td>
                    <td>{{ activity.endpoint }}</td>
                    <td>{{ activity.model or 'N/A' }}</td>
                    <td>
                        {% if activity.status == 200 %}
                        <span class="badge badge-success">{{ activity.status }}</span>
                        {% else %}
                        <span class="badge badge-danger">{{ activity.status }}</span>
                        {% endif %}
                    </td>
                    <td>{{ activity.ip }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% else %}
        <p>No activity yet</p>
        {% endif %}
    </div>

    <div class="section">
        <h2>API Keys Management</h2>
        {% if api_keys %}
        <table>
            <thead>
                <tr>
                    <th>Key Name</th>
                    <th>Created</th>
                    <th>Requests</th>
                    <th>Last Used</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {% for key in api_keys %}
                <tr>
                    <td>{{ key.name }}</td>
                    <td>{{ key.created_at[:19] }}</td>
                    <td>{{ key.requests }}</td>
                    <td>{{ key.last_used[:19] if key.last_used else 'Never' }}</td>
                    <td>
                        {% if key.status == 'active' %}
                        <span class="badge badge-success">Active</span>
                        {% else %}
                        <span class="badge badge-danger">Disabled</span>
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% else %}
        <p>No API keys generated yet</p>
        {% endif %}
    </div>

    <div class="section">
        <h2>Anonymous IDs Pool ({{ anonymous_ids|length }} IDs)</h2>
        <table>
            <thead>
                <tr>
                    <th>Anonymous ID</th>
                    <th>Created</th>
                    <th>Usage Count</th>
                    <th>Last Used</th>
                </tr>
            </thead>
            <tbody>
                {% for aid in anonymous_ids[:20] %}
                <tr>
                    <td>{{ aid.id }}</td>
                    <td>{{ aid.created_at[:19] }}</td>
                    <td>{{ aid.usage_count }}</td>
                    <td>{{ aid.last_used[:19] if aid.last_used else 'Never' }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
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
    with lock:
        stats = {
            'total_keys': len(api_keys_db),
            'active_keys': sum(1 for k in api_keys_db.values() if k['status'] == 'active'),
            'total_requests': sum(k['requests'] for k in api_keys_db.values()),
            'anonymous_ids': len(anonymous_ids_pool)
        }
        
        recent_activity = list(reversed(activity_logs[-20:]))
        
        api_keys = [
            {
                'name': v['name'],
                'created_at': v['created_at'],
                'requests': v['requests'],
                'last_used': v['last_used'],
                'status': v['status']
            }
            for v in api_keys_db.values()
        ]
        
        anonymous_ids = anonymous_ids_pool[:]
    
    return render_template_string(ADMIN_DASHBOARD_HTML, 
                                 stats=stats,
                                 recent_activity=recent_activity,
                                 api_keys=api_keys,
                                 anonymous_ids=anonymous_ids)

# ============ WEB INTERFACE ============

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
        }
        .admin-link {
            background: #dc3545 !important;
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
                <li>Dynamic Token Rotation</li>
                <li>Cloudflare Bypass</li>
                <li>RESTful JSON API</li>
                <li>100% Free Forever</li>
            </ul>
        </div>

        <div class="nav-buttons">
            <a href="/documentation">📖 API Docs</a>
            <a href="/check-usage">📊 Check Usage</a>
            <a href="/admin/login" class="admin-link">🔐 Admin</a>
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
                        <p><strong>Important:</strong> Save this key securely!</p>
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

DOCUMENTATION_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Documentation - Verse API</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            padding: 40px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
        }
        h1 {
            color: #667eea;
            margin-bottom: 10px;
        }
        h2 {
            color: #333;
            margin: 30px 0 15px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
        }
        h3 {
            color: #555;
            margin: 20px 0 10px;
        }
        .endpoint {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
            border-left: 4px solid #667eea;
        }
        .method {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 5px;
            font-weight: bold;
            color: white;
            margin-right: 10px;
        }
        .get { background: #28a745; }
        .post { background: #007bff; }
        code {
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 8px;
            display: block;
            overflow-x: auto;
            margin: 10px 0;
            font-family: 'Courier New', monospace;
            font-size: 14px;
        }
        .param-table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        .param-table th, .param-table td {
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }
        .param-table th {
            background: #667eea;
            color: white;
        }
        .back-link {
            display: inline-block;
            margin-bottom: 20px;
            color: #667eea;
            text-decoration: none;
            font-weight: 600;
        }
    </style>
</head>
<body>
    <div class="container">
        <a href="/" class="back-link">← Back to Home</a>
        <h1>📖 API Documentation</h1>
        <p>Complete guide to using the Verse API</p>

        <h2>Base URL</h2>
        <code>https://verse-api-chat.vercel.app</code>

        <h2>Authentication</h2>
        <p>Include your API key in one of two ways:</p>
        <ul>
            <li><strong>Header:</strong> X-API-Key: your_api_key_here</li>
            <li><strong>Query Parameter:</strong> ?api_key=your_api_key_here</li>
        </ul>

        <h2>Endpoints</h2>

        <div class="endpoint">
            <h3><span class="method get">GET</span> /api/chat</h3>
            <p><strong>Description:</strong> Send a message to AI and get response</p>
            
            <h4>Parameters:</h4>
            <table class="param-table">
                <tr>
                    <th>Parameter</th>
                    <th>Type</th>
                    <th>Required</th>
                    <th>Description</th>
                </tr>
                <tr>
                    <td>api_key</td>
                    <td>string</td>
                    <td>Yes</td>
                    <td>Your API key</td>
                </tr>
                <tr>
                    <td>mensaje</td>
                    <td>string</td>
                    <td>Yes</td>
                    <td>Your message</td>
                </tr>
                <tr>
                    <td>modelo</td>
                    <td>string</td>
                    <td>No</td>
                    <td>AI model (default: gpt-4.1-mini)</td>
                </tr>
            </table>

            <h4>Example:</h4>
            <code>curl "https://verse-api-chat.vercel.app/api/chat?mensaje=Hello&api_key=YOUR_KEY"</code>

            <h4>Response:</h4>
            <code>{
  "success": true,
  "respuesta": "Hello! How can I help you?",
  "modelo": "gpt-4.1-mini",
  "pregunta": "Hello"
}</code>
        </div>

        <div class="endpoint">
            <h3><span class="method get">GET</span> /api/modelos</h3>
            <p><strong>Description:</strong> List available models</p>
            <p><strong>Authentication:</strong> Not required</p>
        </div>

        <div class="endpoint">
            <h3><span class="method post">POST</span> /api/generate-key</h3>
            <p><strong>Description:</strong> Generate new API key</p>
            <p><strong>Authentication:</strong> Not required</p>
            
            <h4>Body:</h4>
            <code>{ "key_name": "My Project" }</code>
        </div>

        <div class="endpoint">
            <h3><span class="method get">GET</span> /api/usage</h3>
            <p><strong>Description:</strong> Check API key usage</p>
            <code>GET /api/usage?api_key=YOUR_KEY</code>
        </div>
    </div>
</body>
</html>
'''

CHECK_USAGE_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Check Usage - Verse API</title>
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
            max-width: 600px;
            width: 100%;
            padding: 50px;
        }
        h1 {
            color: #667eea;
            font-size: 2em;
            margin-bottom: 10px;
            text-align: center;
        }
        .subtitle {
            text-align: center;
            color: #666;
            margin-bottom: 40px;
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
        }
        button {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 15px;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            width: 100%;
        }
        .result {
            margin-top: 30px;
            padding: 25px;
            border-radius: 10px;
            display: none;
        }
        .result.success {
            background: #d4edda;
            border: 2px solid #28a745;
        }
        .result.error {
            background: #f8d7da;
            border: 2px solid #dc3545;
            color: #721c24;
        }
        .stat {
            display: flex;
            justify-content: space-between;
            padding: 12px 0;
            border-bottom: 1px solid rgba(0,0,0,0.1);
        }
        .stat-label {
            font-weight: 600;
            color: #333;
        }
        .stat-value {
            color: #667eea;
            font-weight: 600;
        }
        .back-link {
            display: block;
            text-align: center;
            margin-top: 20px;
            color: #667eea;
            text-decoration: none;
            font-weight: 600;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>📊 Check API Usage</h1>
        <p class="subtitle">Enter your API key to view usage</p>
        
        <div class="input-group">
            <label for="apiKey">API Key</label>
            <input type="text" id="apiKey" placeholder="vsk_xxxxx..." />
        </div>
        <button onclick="checkUsage()">Search</button>
        
        <div id="usageResult" class="result"></div>
        
        <a href="/" class="back-link">← Back to Home</a>
    </div>

    <script>
        function checkUsage() {
            const apiKey = document.getElementById('apiKey').value;
            const resultDiv = document.getElementById('usageResult');
            
            if (!apiKey.trim()) {
                resultDiv.className = 'result error';
                resultDiv.style.display = 'block';
                resultDiv.innerHTML = '<strong>Error:</strong> Please enter an API key';
                return;
            }
            
            fetch(`/api/usage?api_key=${encodeURIComponent(apiKey)}`)
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    resultDiv.className = 'result success';
                    resultDiv.innerHTML = `
                        <h3 style="margin-bottom: 20px; color: #155724;">Usage Statistics</h3>
                        <div class="stat">
                            <span class="stat-label">Key Name:</span>
                            <span class="stat-value">${data.key_name}</span>
                        </div>
                        <div class="stat">
                            <span class="stat-label">Total Requests:</span>
                            <span class="stat-value">${data.total_requests}</span>
                        </div>
                        <div class="stat">
                            <span class="stat-label">Created At:</span>
                            <span class="stat-value">${data.created_at.substring(0,19)}</span>
                        </div>
                        <div class="stat">
                            <span class="stat-label">Last Used:</span>
                            <span class="stat-value">${data.last_used ? data.last_used.substring(0,19) : 'Never'}</span>
                        </div>
                    `;
                } else {
                    resultDiv.className = 'result error';
                    resultDiv.innerHTML = `<strong>Error:</strong> ${data.error}`;
                }
                resultDiv.style.display = 'block';
            })
            .catch(err => {
                resultDiv.className = 'result error';
                resultDiv.innerHTML = '<strong>Error:</strong> Failed to fetch usage';
                resultDiv.style.display = 'block';
            });
        }
    </script>
</body>
</html>
'''

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
    data = request.get_json()
    key_name = data.get('key_name')
    
    if not key_name or not key_name.strip():
        return jsonify({
            'error': 'key_name is required',
            'success': False
        }), 400
    
    api_key = 'vsk_' + secrets.token_urlsafe(32)
    created_at = datetime.now().isoformat()
    
    with lock:
        api_keys_db[api_key] = {
            'name': key_name.strip(),
            'created_at': created_at,
            'requests': 0,
            'last_used': None,
            'status': 'active'
        }
    
    return jsonify({
        'success': True,
        'api_key': api_key,
        'key_name': key_name.strip(),
        'created_at': created_at
    }), 201

@app.route('/api/usage', methods=['GET'])
def get_usage():
    api_key = request.args.get('api_key')
    
    if not api_key:
        return jsonify({
            'error': 'api_key parameter is required',
            'success': False
        }), 400
    
    with lock:
        if api_key not in api_keys_db:
            return jsonify({
                'error': 'Invalid API key',
                'success': False
            }), 404
        
        key_data = api_keys_db[api_key]
    
    return jsonify({
        'success': True,
        'key_name': key_data['name'],
        'total_requests': key_data['requests'],
        'created_at': key_data['created_at'],
        'last_used': key_data['last_used']
    })

@app.route('/api/chat', methods=['GET'])
@require_api_key
def chat():
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
    
    anonymous_id = get_anonymous_id()
    
    url = "https://notegpt.io/api/v2/chat/stream"
    
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Referer": "https://notegpt.io/ai-chat",
        "Origin": "https://notegpt.io",
        "Cookie": f"anonymous_user_id={anonymous_id}",
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
        response = scraper.post(url, headers=headers, json=payload, stream=True, timeout=50)
        
        if response.status_code != 200:
            log_activity(request.api_key_info['name'], '/api/chat', modelo, 
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
            log_activity(request.api_key_info['name'], '/api/chat', modelo, 
                        500, request.remote_addr)
            return Response(
                json.dumps({
                    'error': 'No text content extracted',
                    'success': False
                }, ensure_ascii=False, indent=2),
                mimetype='application/json; charset=utf-8',
                status=500
            )
        
        log_activity(request.api_key_info['name'], '/api/chat', modelo, 
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
        log_activity(request.api_key_info['name'], '/api/chat', modelo, 
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

# Vercel entry point
app = app
