from flask import Flask, render_template, request, redirect, url_for, session, send_file, abort, jsonify, flash
from pymongo import MongoClient
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
import os
import qrcode
from io import BytesIO
from dotenv import load_dotenv
import logging
from datetime import timedelta, datetime
import secrets
import base64
from functools import wraps
import json
from urllib.parse import quote_plus

# Load environment variables
load_dotenv()

# Configure logging for production
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder='Templates', static_folder='static')

# Production-ready configuration with Session Fix
app.secret_key = os.getenv('SECRET_KEY', secrets.token_urlsafe(32))

# FIX: Custom session interface to handle bytes-to-string conversion
class FixedSession(Session):
    def _generate_sid(self):
        """Generate session ID as string instead of bytes"""
        return secrets.token_urlsafe(32)
    
    def _get_interface(self, app):
        config = app.config.copy()
        config.setdefault('SESSION_TYPE', 'filesystem')
        config.setdefault('SESSION_PERMANENT', False)
        config.setdefault('SESSION_USE_SIGNER', True)
        config.setdefault('SESSION_KEY_PREFIX', 'game_app:')
        config.setdefault('PERMANENT_SESSION_LIFETIME', timedelta(hours=24))
        
        # Ensure session directory exists
        session_dir = config.get('SESSION_FILE_DIR', 'flask_session')
        os.makedirs(session_dir, exist_ok=True)
        
        return super()._get_interface(app)

# Apply session configuration
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'game_app:'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
app.config['SESSION_COOKIE_SECURE'] = not app.debug  # Secure cookies in production
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Initialize fixed session
FixedSession(app)

# Creative Enhancement: Rate limiting decorator
def rate_limit(max_requests=5, window=300):  # 5 requests per 5 minutes
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            key = f"rate_limit:{f.__name__}:{client_ip}"
            
            # Simple in-memory rate limiting (use Redis in production)
            if not hasattr(app, '_rate_limits'):
                app._rate_limits = {}
            
            now = datetime.now()
            if key in app._rate_limits:
                requests, last_reset = app._rate_limits[key]
                if (now - last_reset).seconds > window:
                    app._rate_limits[key] = (1, now)
                elif requests >= max_requests:
                    return jsonify({'error': 'Rate limit exceeded'}), 429
                else:
                    app._rate_limits[key] = (requests + 1, last_reset)
            else:
                app._rate_limits[key] = (1, now)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Creative Enhancement: Activity logger
def log_activity(action, username=None):
    """Log user activities for audit trail"""
    try:
        activity = {
            'action': action,
            'username': username or session.get('username', 'anonymous'),
            'ip_address': request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr),
            'user_agent': request.headers.get('User-Agent', ''),
            'timestamp': datetime.utcnow(),
            'endpoint': request.endpoint
        }
        
        # Store in MongoDB (create activities collection)
        if 'db' in globals():
            db['activities'].insert_one(activity)
        
        logger.info(f"Activity logged: {action} by {activity['username']}")
    except Exception as e:
        logger.error(f"Failed to log activity: {e}")

# Security headers for production
@app.after_request
def after_request(response):
    # Security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Content Security Policy
    csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
    response.headers['Content-Security-Policy'] = csp
    
    # Only add HSTS in production (when using HTTPS)
    if not app.debug:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response

# MongoDB setup with enhanced error handling and connection pooling
mongo_uri = os.getenv('MONGO_URI')
if not mongo_uri:
    logger.error("MONGO_URI not set. Add it to your environment variables.")
    raise RuntimeError("MONGO_URI not set. Add it to your .env or Render environment.")

try:
    # Enhanced MongoDB connection with better configuration
    client = MongoClient(
        mongo_uri, 
        serverSelectionTimeoutMS=5000,
        maxPoolSize=50,  # Connection pooling
        minPoolSize=5,
        maxIdleTimeMS=30000,
        retryWrites=True
    )
    # Test the connection
    client.server_info()
    db = client['game_db']
    users_collection = db['users']
    activities_collection = db['activities']  # New collection for activity logging
    
    # Create indexes for better performance
    users_collection.create_index("username", unique=True)
    users_collection.create_index("email", unique=True)
    activities_collection.create_index("timestamp")
    activities_collection.create_index("username")
    
    logger.info("Successfully connected to MongoDB with enhanced configuration")
except Exception as e:
    logger.error(f"Failed to connect to MongoDB: {e}")
    raise

# Initial admin from environment variables
INITIAL_ADMIN_USERNAME = os.getenv('ADMIN_USERNAME')
INITIAL_ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')

# Create initial admin if needed
def create_initial_admin():
    try:
        if INITIAL_ADMIN_USERNAME and INITIAL_ADMIN_PASSWORD:
            existing_user = users_collection.find_one({'username': INITIAL_ADMIN_USERNAME})
            hashed_pw = generate_password_hash(INITIAL_ADMIN_PASSWORD)
            user_data = {
                'username': INITIAL_ADMIN_USERNAME,
                'password': hashed_pw,
                'role': 'admin',
                'email': f"{INITIAL_ADMIN_USERNAME}@example.com",
                'created_at': datetime.utcnow(),
                'last_login': None,
                'login_count': 0
            }
            
            if not existing_user:
                users_collection.insert_one(user_data)
                logger.info(f"Created initial admin user: {INITIAL_ADMIN_USERNAME}")
            else:
                users_collection.update_one(
                    {'username': INITIAL_ADMIN_USERNAME},
                    {'$set': {
                        'password': hashed_pw,
                        'role': 'admin'
                    }}
                )
                logger.info(f"Updated admin user: {INITIAL_ADMIN_USERNAME}")
    except Exception as e:
        logger.error(f"Error creating initial admin: {e}")

# Call on startup
create_initial_admin()

# Creative Enhancement: Authentication decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            log_activity('unauthorized_admin_access_attempt')
            flash('Admin access required.', 'error')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# Reusable error rendering
def render_error(template, message, status_code=400):
    flash(message, 'error')
    return render_template(template), status_code

# Creative Enhancement: System stats endpoint
@app.route('/api/stats')
@admin_required
def system_stats():
    try:
        stats = {
            'total_users': users_collection.count_documents({}),
            'total_admins': users_collection.count_documents({'role': 'admin'}),
            'total_moderators': users_collection.count_documents({'role': 'moderator'}),
            'recent_registrations': users_collection.count_documents({
                'created_at': {'$gte': datetime.utcnow() - timedelta(days=7)}
            }),
            'recent_activities': activities_collection.count_documents({
                'timestamp': {'$gte': datetime.utcnow() - timedelta(hours=24)}
            })
        }
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error fetching stats: {e}")
        return jsonify({'error': 'Failed to fetch stats'}), 500

# Health check endpoint for Render
@app.route('/health')
def health_check():
    try:
        # Test database connection
        client.server_info()
        
        # Check session store
        session_test = session.get('health_check', False)
        session['health_check'] = True
        
        return jsonify({
            'status': 'healthy', 
            'database': 'connected',
            'session_store': 'working',
            'timestamp': datetime.utcnow().isoformat()
        }), 200
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 503

@app.route('/')
def home():
    log_activity('home_page_visit')
    return render_template('index.html')

@app.route('/admin_login', methods=['GET', 'POST'])
@rate_limit(max_requests=3, window=300)  # Stricter rate limiting for admin login
def admin_login():
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')

            if not username or not password:
                log_activity('admin_login_attempt_missing_credentials', username)
                return render_error('admin_login.html', 'Username and password are required')

            user = users_collection.find_one({'username': username})

            if user and check_password_hash(user['password'], password) and user.get('role') == 'admin':
                session['is_admin'] = True
                session['username'] = username
                session.permanent = True
                
                # Update login stats
                users_collection.update_one(
                    {'username': username},
                    {
                        '$set': {'last_login': datetime.utcnow()},
                        '$inc': {'login_count': 1}
                    }
                )
                
                log_activity('admin_login_success', username)
                flash(f'Welcome back, {username}!', 'success')
                return redirect(url_for('admin_dashboard'))

            log_activity('admin_login_failed', username)
            return render_error('admin_login.html', 'Invalid admin credentials', 401)

        except Exception as e:
            logger.error(f"Error in admin login: {e}")
            log_activity('admin_login_error', username if 'username' in locals() else None)
            return render_error('admin_login.html', 'An error occurred during login', 500)

    return render_template('admin_login.html')

@app.route('/admin')
@admin_required
def admin_dashboard():
    log_activity('admin_dashboard_access')
    return render_template('admin.html')

@app.route('/admin/users')
@admin_required
def view_users():
    try:
        # Enhanced user query with pagination and sorting
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        sort_by = request.args.get('sort', 'username')
        
        skip = (page - 1) * per_page
        
        users = list(users_collection.find(
            {}, 
            {'_id': 0, 'password': 0}
        ).sort(sort_by, 1).skip(skip).limit(per_page))
        
        total_users = users_collection.count_documents({})
        
        log_activity('view_users_page')
        return render_template('users.html', 
                             users=users, 
                             page=page, 
                             per_page=per_page,
                             total_users=total_users)
    except Exception as e:
        logger.error(f"Error fetching users: {e}")
        return render_error('admin.html', 'Error loading users', 500)

@app.route('/admin/delete_user/<username>', methods=['DELETE'])
@admin_required
def delete_user(username):
    try:
        # Prevent self-deletion
        if session.get('username') == username:
            return jsonify({'success': False, 'message': 'Cannot delete your own account'}), 400
        
        result = users_collection.delete_one({'username': username})
        if result.deleted_count > 0:
            log_activity('user_deleted', username)
            return jsonify({'success': True, 'message': 'User deleted successfully'})
        else:
            return jsonify({'success': False, 'message': 'User not found'}), 404
    except Exception as e:
        logger.error(f"Error deleting user {username}: {e}")
        return jsonify({'success': False, 'message': 'Error deleting user'}), 500

@app.route('/admin/edit_user/<username>', methods=['PUT'])
@admin_required
def edit_user(username):
    try:
        data = request.get_json()
        if not data:
            return jsonify({'message': 'No data provided'}), 400
            
        update_data = {}
        if 'email' in data and data['email']:
            update_data['email'] = data['email'].strip().lower()
        if 'role' in data and data['role'] is not None:
            update_data['role'] = data['role']
        
        if not update_data:
            return jsonify({'message': 'No valid data to update'}), 400
            
        result = users_collection.update_one({'username': username}, {'$set': update_data})
        if result.matched_count == 0:
            return jsonify({'message': 'User not found'}), 404
        
        log_activity('user_updated', username)
        return jsonify({'success': True, 'message': 'User updated successfully'}), 200
    except Exception as e:
        logger.error(f"Error updating user {username}: {e}")
        return jsonify({'message': 'Error updating user'}), 500

@app.route('/admin/recover_user/<username>', methods=['PUT'])
@admin_required
def recover_user(username):
    try:
        data = request.get_json()
        if not data or not data.get('password'):
            return jsonify({'message': 'Password is required'}), 400
            
        hashed_pw = generate_password_hash(data['password'])
        result = users_collection.update_one({'username': username}, {'$set': {'password': hashed_pw}})
        
        if result.matched_count == 0:
            return jsonify({'message': 'User not found'}), 404
            
        log_activity('password_recovered', username)
        return jsonify({'success': True, 'message': 'Password updated successfully'})
    except Exception as e:
        logger.error(f"Error recovering password for {username}: {e}")
        return jsonify({'message': 'Error updating password'}), 500

@app.route('/register', methods=['GET', 'POST'])
@rate_limit(max_requests=5, window=600)  # 5 registrations per 10 minutes
def register():
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')

            # Enhanced validation
            if not all([username, email, password, confirm_password]):
                return render_error('register.html', 'All fields are required.')

            if len(username) < 3:
                return render_error('register.html', 'Username must be at least 3 characters long.')

            if password != confirm_password:
                return render_error('register.html', 'Passwords do not match.')

            if len(password) < 8:
                return render_error('register.html', 'Password must be at least 8 characters long.')

            # Check for password complexity
            if not any(c.isupper() for c in password) or not any(c.isdigit() for c in password):
                return render_error('register.html', 'Password must contain at least one uppercase letter and one number.')

            if users_collection.find_one({'username': username}):
                return render_error('register.html', 'Username already exists.')

            if users_collection.find_one({'email': email}):
                return render_error('register.html', 'Email already exists.')

            hashed_pw = generate_password_hash(password)
            user_data = {
                'username': username,
                'email': email,
                'password': hashed_pw,
                'role': 'user',
                'created_at': datetime.utcnow(),
                'last_login': None,
                'login_count': 0,
                'is_active': True
            }
            
            users_collection.insert_one(user_data)
            log_activity('user_registered', username)
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            logger.error(f"Error in registration: {e}")
            log_activity('registration_error')
            return render_error('register.html', 'An error occurred during registration', 500)

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@rate_limit(max_requests=10, window=300)  # 10 login attempts per 5 minutes
def login():
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')

            if not username or not password:
                return render_error('login.html', 'Username and password are required')

            user = users_collection.find_one({'username': username})

            if user and check_password_hash(user['password'], password):
                session['username'] = username
                session.permanent = True

                # Update login stats
                users_collection.update_one(
                    {'username': username},
                    {
                        '$set': {'last_login': datetime.utcnow()},
                        '$inc': {'login_count': 1}
                    }
                )

                # Set role-based sessions
                if user.get('role') == 'admin':
                    session['is_admin'] = True
                elif user.get('role') == 'moderator':
                    session['is_moderator'] = True

                log_activity('user_login_success', username)
                flash(f'Welcome back, {username}!', 'success')
                
                # Redirect to intended page or home
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('home'))
            else:
                log_activity('user_login_failed', username)
                return render_error('login.html', 'Invalid credentials', 401)

        except Exception as e:
            logger.error(f"Error in login: {e}")
            log_activity('login_error')
            return render_error('login.html', 'An error occurred during login', 500)

    return render_template('login.html')

@app.route('/moderator')
def moderator_dashboard():
    if not session.get('is_moderator') and not session.get('is_admin'):
        flash('Moderator access required.', 'error')
        return redirect(url_for('home'))
    
    log_activity('moderator_dashboard_access')
    return render_template('moderator.html')

@app.route('/logout')
def logout():
    username = session.get('username', 'unknown')
    log_activity('user_logout', username)
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('home'))

@app.route('/game/<username>')
@login_required
def game(username):
    if session['username'] == username:
        log_activity('game_access', username)
        return render_template('game.html', username=username)
    flash('Access denied.', 'error')
    return redirect(url_for('home'))

@app.route('/generate_qr')
def generate_qr():
    try:
        url = request.host_url
        
        # Enhanced QR code with styling
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(url)
        qr.make(fit=True)
        
        # Create QR code with custom colors
        img = qr.make_image(fill_color="black", back_color="white")

        buf = BytesIO()
        img.save(buf, format='PNG')
        buf.seek(0)
        
        log_activity('qr_code_generated')
        return send_file(buf, mimetype='image/png', as_attachment=True, download_name='website_qr.png')
    except Exception as e:
        logger.error(f"Error generating QR code: {e}")
        return abort(500)

@app.route('/qr')
def qr_page():
    log_activity('qr_page_visit')
    return render_template('qr.html')

# Creative Enhancement: User profile page
@app.route('/profile')
@login_required
def profile():
    try:
        username = session['username']
        user = users_collection.find_one({'username': username}, {'_id': 0, 'password': 0})
        
        # Get recent activities for this user
        recent_activities = list(activities_collection.find(
            {'username': username},
            {'_id': 0}
        ).sort('timestamp', -1).limit(10))
        
        log_activity('profile_viewed')
        return render_template('profile.html', user=user, activities=recent_activities)
    except Exception as e:
        logger.error(f"Error loading profile: {e}")
        flash('Error loading profile.', 'error')
        return redirect(url_for('home'))

# Creative Enhancement: API endpoint for user activities
@app.route('/api/activities')
@admin_required
def get_activities():
    try:
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 50)), 100)  # Max 100 per page
        
        skip = (page - 1) * per_page
        
        activities = list(activities_collection.find(
            {},
            {'_id': 0}
        ).sort('timestamp', -1).skip(skip).limit(per_page))
        
        total = activities_collection.count_documents({})
        
        return jsonify({
            'activities': activities,
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': (total + per_page - 1) // per_page
        })
    except Exception as e:
        logger.error(f"Error fetching activities: {e}")
        return jsonify({'error': 'Failed to fetch activities'}), 500

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    log_activity('page_not_found')
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    log_activity('forbidden_access')
    return render_template('403.html'), 403

@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"Internal server error: {e}")
    log_activity('internal_server_error')
    return render_template('500.html'), 500

@app.errorhandler(429)
def rate_limit_exceeded(e):
    log_activity('rate_limit_exceeded')
    return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429

# Production WSGI entry point
if __name__ == '__main__':
    # This will only run in development
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
else:
    # Production mode
    app.logger.setLevel(logging.INFO)