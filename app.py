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

# Initialize cloudscraper
scraper = cloudscraper.create_scraper(
    browser={
        'browser': 'chrome',
        'platform': 'windows',
        'mobile': False
    }
)

# Admin credentials
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'verse_admin_2026')

# Database path
DB_PATH = os.path.join(os.getcwd(), 'verse_api.db')

# Database initialization
def init_db():
    conn = sqlite3.connect(DB_PATH)
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
    
    # Generate initial anonymous IDs
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM anonymous_ids')
    count = c.fetchone()[0]
    
    if count == 0:
        for _ in range(20):
            try:
                anon_id = str(uuid.uuid4())
                c.execute('''INSERT INTO anonymous_ids 
                             (anonymous_id, created_at, usage_count, status)
                             VALUES (?, ?, 0, 'active')''',
                          (anon_id, datetime.now().isoformat()))
            except:
                continue
        conn.commit()
    conn.close()

init_db()

def get_anonymous_id():
    """Get a random active anonymous ID from pool or generate new one"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute('''SELECT anonymous_id FROM anonymous_ids 
                 WHERE status = 'active' AND usage_count < 100 
                 ORDER BY RANDOM() LIMIT 1''')
    result = c.fetchone()
    
    if result:
        anon_id = result[0]
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
                'error': 'API key missing',
                'success': False
            }), 401
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT id, key_name, status FROM api_keys WHERE api_key = ?', (api_key,))
        result = c.fetchone()
        
        if not result:
            conn.close()
            return jsonify({'error': 'Invalid API key', 'success': False}), 403
        
        if result[2] != 'active':
            conn.close()
            return jsonify({'error': 'API key disabled', 'success': False}), 403
        
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

def log_activity(api_key_id, endpoint, model, status, ip_address):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''INSERT INTO activity_logs 
                 (api_key_id, endpoint, model, request_time, response_status, ip_address)
                 VALUES (?, ?, ?, ?, ?, ?)''',
              (api_key_id, endpoint, model, datetime.now().isoformat(), status, ip_address))
    conn.commit()
    
    # Keep only last 1000 logs
    c.execute('DELETE FROM activity_logs WHERE id NOT IN (SELECT id FROM activity_logs ORDER BY id DESC LIMIT 1000)')
    conn.commit()
    conn.close()

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,X-API-Key')
    response.headers.add('Access-Control-Allow-Methods', 'GET,POST')
    return response

# [Include all the HTML templates from the previous admin panel version]
# I'll include the key ones here:

HOME_HTML = '''[Same as before - the complete home page HTML]'''
ADMIN_LOGIN_HTML = '''[Same as before]'''
ADMIN_DASHBOARD_HTML = '''[Same as before]'''
DOCUMENTATION_HTML = '''[Same as before]'''
CHECK_USAGE_HTML = '''[Same as before]'''

# [All route handlers remain the same as the SQLite version I provided earlier]

@app.route('/')
def home():
    return render_template_string(HOME_HTML)

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
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
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
    
    c.execute('''SELECT al.request_time, ak.key_name, al.endpoint, al.model, 
                        al.response_status, al.ip_address
                 FROM activity_logs al
                 JOIN api_keys ak ON al.api_key_id = ak.id
                 ORDER BY al.request_time DESC LIMIT 20''')
    recent_activity = c.fetchall()
    
    c.execute('''SELECT key_name, created_at, total_requests, last_used, status, id
                 FROM api_keys ORDER BY created_at DESC''')
    api_keys = c.fetchall()
    
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
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('UPDATE api_keys SET status = ? WHERE id = ?', (new_status, key_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/admin/generate-anonymous-ids', methods=['POST'])
@admin_required
def generate_anonymous_ids():
    conn = sqlite3.connect(DB_PATH)
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

@app.route('/documentation')
def documentation():
    return render_template_string(DOCUMENTATION_HTML)

@app.route('/check-usage')
def check_usage_page():
    return render_template_string(CHECK_USAGE_HTML)

@app.route('/api/generate-key', methods=['POST'])
def generate_key():
    data = request.get_json()
    key_name = data.get('key_name')
    
    if not key_name or not key_name.strip():
        return jsonify({'error': 'key_name is required', 'success': False}), 400
    
    api_key = 'vsk_' + secrets.token_urlsafe(32)
    created_at = datetime.now().isoformat()
    
    try:
        conn = sqlite3.connect(DB_PATH)
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
    except:
        return jsonify({'error': 'Failed to generate key', 'success': False}), 500

@app.route('/api/usage', methods=['GET'])
def get_usage():
    api_key = request.args.get('api_key')
    
    if not api_key:
        return jsonify({'error': 'api_key required', 'success': False}), 400
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''SELECT key_name, total_requests, created_at, last_used 
                 FROM api_keys WHERE api_key = ?''', (api_key,))
    result = c.fetchone()
    conn.close()
    
    if not result:
        return jsonify({'error': 'Invalid API key', 'success': False}), 404
    
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
    modelo = request.args.get('modelo', 'gpt-4.1-mini')
    mensaje = request.args.get('mensaje') or request.args.get('prompt') or request.args.get('texto')
    
    if not mensaje:
        return Response(
            json.dumps({'error': 'Missing mensaje parameter', 'success': False}, 
                      ensure_ascii=False, indent=2),
            mimetype='application/json; charset=utf-8',
            status=400
        )
    
    anonymous_id = get_anonymous_id()
    
    url = "https://notegpt.io/api/v2/chat/stream"
    
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
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
            log_activity(request.api_key_info['id'], '/api/chat', modelo, 
                        response.status_code, request.remote_addr)
            return Response(
                json.dumps({'error': f'Error {response.status_code}', 'success': False},
                          ensure_ascii=False, indent=2),
                mimetype='application/json; charset=utf-8',
                status=response.status_code
            )
        
        responseText = response.content.decode('utf-8')
        
        respuesta_completa = ""
        razonamiento = ""
        
        for line in responseText.split('\n'):
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
                json.dumps({'error': 'No content extracted', 'success': False},
                          ensure_ascii=False, indent=2),
                mimetype='application/json; charset=utf-8',
                status=500
            )
        
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
            json.dumps({'error': str(e), 'success': False},
                      ensure_ascii=False, indent=2),
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
        json.dumps({'modelos': available_models, 'default': 'gpt-4.1-mini'},
                  ensure_ascii=False, indent=2),
        mimetype='application/json; charset=utf-8'
    )

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
