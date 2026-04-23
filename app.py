from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps
import requests
import os
from datetime import datetime
import urllib.parse
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from url_detector import check_url

app = Flask(__name__, instance_relative_config=True)
app.secret_key = 'cyra-secret-key-2024'

# Google OAuth Configuration - UPDATED WITH YOUR NEW CREDENTIALS
GOOGLE_CLIENT_ID = '503272786317-b50gsqvb4ovcgbm3820euq4auld8tg8m.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = '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'

# Initialize scan_history
scan_history = []

# Database configuration
DATABASE = os.path.join(app.instance_path, 'users.db')

# Ensure instance folder exists
try:
    os.makedirs(app.instance_path)
except OSError:
    pass

# Database helper functions
def get_db():
    """Get database connection"""
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    """Initialize database tables"""
    with get_db() as db:
        # Create users table
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE,
                password TEXT,
                name TEXT,
                login_method TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_admin BOOLEAN DEFAULT 0
            )
        ''')
        
        # Check if admin user exists, if not create it
        admin = db.execute('SELECT * FROM users WHERE email = ?', ('dboss@cyra.com',)).fetchone()
        if not admin:
            db.execute('''
                INSERT INTO users (email, username, password, login_method, is_admin)
                VALUES (?, ?, ?, ?, ?)
            ''', ('dboss@cyra.com', 'dboss', 'shedguru99', 'email', 1))
            
            # Also create regular admin user
            db.execute('''
                INSERT INTO users (email, username, password, login_method, is_admin)
                VALUES (?, ?, ?, ?, ?)
            ''', ('admin@cyra.com', 'admin', 'password', 'email', 0))
        
        db.commit()

# Initialize database
with app.app_context():
    init_db()

def get_user_by_email(email):
    """Get user by email"""
    with get_db() as db:
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        return dict(user) if user else None

def get_user_by_username(username):
    """Get user by username"""
    with get_db() as db:
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        return dict(user) if user else None

def create_user(email, username=None, password=None, name=None, login_method='email', is_admin=0):
    """Create a new user"""
    with get_db() as db:
        db.execute('''
            INSERT INTO users (email, username, password, name, login_method, is_admin)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (email, username, password, name, login_method, is_admin))
        db.commit()

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_email = session.get('user')
        if not user_email:
            flash('Please login first!', 'error')
            return redirect(url_for('login'))
        
        user = get_user_by_email(user_email)
        if not user or not user.get('is_admin'):
            flash('Admin access required!', 'error')
            return redirect(url_for('home'))
            
        return f(*args, **kwargs)
    return decorated_function

def is_new_user(created_at):
    """Check if user registered within last 7 days"""
    if not created_at:
        return False
    if isinstance(created_at, str):
        created_at = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
    days_ago = (datetime.now() - created_at).days
    return days_ago <= 7

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        print(f"Login attempt: {username}")
        
        # Get user by username
        user = get_user_by_username(username)
        
        if user and user.get('password') == password:
            session['user'] = user['email']
            session['login_method'] = user['login_method']
            session['is_admin'] = user['is_admin']
            
            if user['is_admin']:
                flash(f'Welcome {username}! Admin login successful!', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Login successful!', 'success')
                return redirect(url_for('home'))
        else:
            flash('Invalid credentials!', 'error')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
        elif get_user_by_email(email):
            flash('Email already registered!', 'error')
        elif get_user_by_username(username):
            flash('Username already taken!', 'error')
        else:
            create_user(
                email=email,
                username=username,
                password=password,
                login_method='email',
                is_admin=0
            )
            flash('Account created successfully! Please login.', 'success')
            return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out!', 'info')
    return redirect(url_for('home'))

# Phishing Detection Route
@app.route('/detect', methods=['POST'])
def detect_phishing():
    if 'user' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('login'))
    
    url = request.form.get('url', '')
    
    if not url:
        flash('Please enter a URL', 'error')
        return redirect(url_for('home'))
    
    # Add http:// if no protocol
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    try:
        # Detect phishing using URL detector
        result = check_url(url)
        prediction = 1 if result['is_phishing'] else 0
        confidence = result['confidence']
        
        # Save to scan history
        scan_record = {
            'url': url,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'threat_level': 'HIGH' if prediction == 1 else 'LOW',
            'confidence': f"{confidence:.2f}%",
            'user': session.get('user')
        }
        scan_history.insert(0, scan_record)  # Add to beginning of list
        
        if prediction == 1:
            result_text = "⚠️ PHISHING WEBSITE DETECTED!"
            result_class = "phishing"
            threat_level = "HIGH"
        else:
            result_text = "✅ WEBSITE IS SAFE"
            result_class = "safe"
            threat_level = "LOW"
        
        return render_template('home.html', 
                             user=session.get('user'),
                             detection_result=result_text,
                             result_class=result_class,
                             confidence=f"{confidence:.2f}",
                             checked_url=url,
                             threat_level=threat_level)
    
    except Exception as e:
        flash(f'Error analyzing URL: {str(e)}', 'error')
        return redirect(url_for('home'))

# Admin Routes
@app.route('/admin')
@admin_required
def admin_dashboard():
    with get_db() as db:
        total_users = db.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
        google_users = db.execute('SELECT COUNT(*) as count FROM users WHERE login_method = ?', ('google',)).fetchone()['count']
        email_users = db.execute('SELECT COUNT(*) as count FROM users WHERE login_method = ?', ('email',)).fetchone()['count']
        admin_users = db.execute('SELECT COUNT(*) as count FROM users WHERE is_admin = ?', (1,)).fetchone()['count']
        
        recent_users_raw = db.execute('''
            SELECT * FROM users 
            ORDER BY created_at DESC 
            LIMIT 5
        ''').fetchall()
        recent_users = [dict(user) for user in recent_users_raw]

    stats = {
        'total_users': total_users,
        'google_users': google_users,
        'email_users': email_users,
        'admin_users': admin_users,
        'total_scans': len(scan_history),
        'phishing_detected': len([s for s in scan_history if s.get('threat_level') == 'HIGH']),
        'suspicious_scans': len([s for s in scan_history if s.get('threat_level') == 'MEDIUM']),
        'safe_scans': len([s for s in scan_history if s.get('threat_level') == 'LOW'])
    }

    recent_scans = scan_history[:5] if scan_history else []
    return render_template('admin.html', stats=stats, recent_users=recent_users, recent_scans=recent_scans)

@app.route('/admin/users')
@admin_required
def admin_users():
    with get_db() as db:
        users_raw = db.execute('SELECT * FROM users ORDER BY created_at DESC').fetchall()
        users = [dict(user) for user in users_raw]
    return render_template('admin_users.html', users=users, is_new_user=is_new_user)

@app.route('/admin/scans')
@admin_required
def admin_scans():
    return render_template('admin_scans.html', scans=scan_history)

@app.route('/admin/delete-user/<email>')
@admin_required
def admin_delete_user(email):
    if email == "dboss@cyra.com":
        flash('Cannot delete main admin user!', 'error')
    else:
        with get_db() as db:
            db.execute('DELETE FROM users WHERE email = ?', (email,))
            db.commit()
            flash(f'User {email} deleted successfully!', 'success')
    return redirect(url_for('admin_users'))

# Google OAuth Routes
@app.route('/google-login')
def google_login():
    base_url = "https://accounts.google.com/o/oauth2/v2/auth"
    params = {
        'client_id': GOOGLE_CLIENT_ID,
        'redirect_uri': 'http://localhost:5000/google-auth',
        'response_type': 'code',
        'scope': 'email profile',
        'access_type': 'online',
    }
    auth_url = f"{base_url}?{urllib.parse.urlencode(params)}"
    return redirect(auth_url)

@app.route('/google-auth')
def google_auth():
    try:
        code = request.args.get('code')
        if not code:
            flash('No authorization code received', 'error')
            return redirect(url_for('login'))
        
        token_url = "https://oauth2.googleapis.com/token"
        token_data = {
            'client_id': GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_CLIENT_SECRET,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': 'http://localhost:5000/google-auth'
        }
        
        token_response = requests.post(token_url, data=token_data)
        token_json = token_response.json()
        
        if 'access_token' not in token_json:
            flash('Google login failed: No access token', 'error')
            return redirect(url_for('login'))
        
        userinfo_response = requests.get(
            'https://www.googleapis.com/oauth2/v1/userinfo',
            headers={'Authorization': f'Bearer {token_json["access_token"]}'}
        )
        user_info = userinfo_response.json()
        
        email = user_info['email']
        
        # Check if user exists
        user = get_user_by_email(email)
        
        if not user:
            # Add Google user to database if new
            create_user(
                email=email,
                name=user_info.get('name', ''),
                login_method='google',
                is_admin=0
            )
            user = get_user_by_email(email)
        
        session['user'] = email
        session['login_method'] = 'google'
        session['is_admin'] = user['is_admin']
        
        flash(f'Welcome {user_info.get("name", "User")}! Google login successful.', 'success')
        return redirect(url_for('home'))
        
    except Exception as e:
        flash(f'Google login error: {str(e)}', 'error')
        return redirect(url_for('login'))

# Debug route to check users (remove this in production)
@app.route('/debug-users')
def debug_users():
    with get_db() as db:
        users_raw = db.execute('SELECT * FROM users').fetchall()
        users = [dict(user) for user in users_raw]
    return {
        'users': users,
        'total_users': len(users)
    }

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)