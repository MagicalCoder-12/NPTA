from flask import Flask, render_template, request, redirect, url_for, session, send_file, abort, jsonify
from pymongo import MongoClient
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
import os
import qrcode
from io import BytesIO
from dotenv import load_dotenv
import logging
from datetime import timedelta

# Load environment variables
load_dotenv()

# Configure logging for production
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder='Templates', static_folder='static')

# Production-ready configuration
app.secret_key = os.getenv('SECRET_KEY', os.urandom(24))
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'game_app:'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# Security headers for production
@app.after_request
def after_request(response):
    # Security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Only add HSTS in production (when using HTTPS)
    if not app.debug:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response

Session(app)

# MongoDB setup with error handling
mongo_uri = os.getenv('MONGO_URI')
if not mongo_uri:
    logger.error("MONGO_URI not set. Add it to your environment variables.")
    raise RuntimeError("MONGO_URI not set. Add it to your .env or Render environment.")

try:
    client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
    # Test the connection
    client.server_info()
    db = client['game_db']
    users_collection = db['users']
    logger.info("Successfully connected to MongoDB")
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
            if not existing_user:
                users_collection.insert_one({
                    'username': INITIAL_ADMIN_USERNAME,
                    'password': hashed_pw,
                    'role': 'admin',
                    'email': f"{INITIAL_ADMIN_USERNAME}@example.com"
                })
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

# Reusable error rendering
def render_error(template, message, status_code=400):
    return render_template(template, error=message), status_code

# Health check endpoint for Render
@app.route('/health')
def health_check():
    try:
        # Test database connection
        client.server_info()
        return jsonify({'status': 'healthy', 'database': 'connected'}), 200
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 503

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')

            if not username or not password:
                return render_error('admin_login.html', 'Username and password are required')

            user = users_collection.find_one({'username': username})

            if user and check_password_hash(user['password'], password) and user.get('role') == 'admin':
                session['is_admin'] = True
                session['username'] = username
                session.permanent = True
                logger.info(f"Admin login successful: {username}")
                return redirect(url_for('admin_dashboard'))

            logger.warning(f"Failed admin login attempt: {username}")
            return render_error('admin_login.html', 'Invalid admin credentials', 401)

        except Exception as e:
            logger.error(f"Error in admin login: {e}")
            return render_error('admin_login.html', 'An error occurred during login', 500)

    return render_template('admin_login.html')

@app.route('/admin')
def admin_dashboard():
    if not session.get('is_admin'):
        return redirect(url_for('admin_login'))
    return render_template('admin.html')

@app.route('/admin/users')
def view_users():
    if not session.get('is_admin'):
        return redirect(url_for('admin_login'))
    
    try:
        users = list(users_collection.find({}, {'_id': 0, 'password': 0}))
        return render_template('users.html', users=users)
    except Exception as e:
        logger.error(f"Error fetching users: {e}")
        return render_error('admin.html', 'Error loading users', 500)

@app.route('/admin/delete_user/<username>', methods=['DELETE'])
def delete_user(username):
    if not session.get('is_admin'):
        return abort(403)
    
    try:
        result = users_collection.delete_one({'username': username})
        if result.deleted_count > 0:
            logger.info(f"User deleted: {username}")
            return jsonify({'success': True, 'message': 'User deleted successfully'})
        else:
            return jsonify({'success': False, 'message': 'User not found'}), 404
    except Exception as e:
        logger.error(f"Error deleting user {username}: {e}")
        return jsonify({'success': False, 'message': 'Error deleting user'}), 500

@app.route('/admin/edit_user/<username>', methods=['PUT'])
def edit_user(username):
    if not session.get('is_admin'):
        return abort(403)
    
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
        
        logger.info(f"User updated: {username}")
        return jsonify({'success': True, 'message': 'User updated successfully'}), 200
    except Exception as e:
        logger.error(f"Error updating user {username}: {e}")
        return jsonify({'message': 'Error updating user'}), 500

@app.route('/admin/recover_user/<username>', methods=['PUT'])
def recover_user(username):
    if not session.get('is_admin'):
        return abort(403)
    
    try:
        data = request.get_json()
        if not data or not data.get('password'):
            return jsonify({'message': 'Password is required'}), 400
            
        hashed_pw = generate_password_hash(data['password'])
        result = users_collection.update_one({'username': username}, {'$set': {'password': hashed_pw}})
        
        if result.matched_count == 0:
            return jsonify({'message': 'User not found'}), 404
            
        logger.info(f"Password recovered for user: {username}")
        return jsonify({'success': True, 'message': 'Password updated successfully'})
    except Exception as e:
        logger.error(f"Error recovering password for {username}: {e}")
        return jsonify({'message': 'Error updating password'}), 500

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')

            # Validation
            if not all([username, email, password, confirm_password]):
                return render_error('register.html', 'All fields are required.')

            if password != confirm_password:
                return render_error('register.html', 'Passwords do not match.')

            if len(password) < 6:
                return render_error('register.html', 'Password must be at least 6 characters long.')

            if users_collection.find_one({'username': username}):
                return render_error('register.html', 'Username already exists.')

            if users_collection.find_one({'email': email}):
                return render_error('register.html', 'Email already exists.')

            hashed_pw = generate_password_hash(password)
            users_collection.insert_one({
                'username': username,
                'email': email,
                'password': hashed_pw,
                'role': 'user'
            })
            
            logger.info(f"New user registered: {username}")
            return redirect(url_for('login'))

        except Exception as e:
            logger.error(f"Error in registration: {e}")
            return render_error('register.html', 'An error occurred during registration', 500)

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
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

                if user.get('role') == 'admin':
                    session['is_admin'] = True
                elif user.get('role') == 'moderator':
                    session['is_moderator'] = True

                logger.info(f"User login successful: {username}")
                return redirect(url_for('home'))
            else:
                logger.warning(f"Failed login attempt: {username}")
                return render_error('login.html', 'Invalid credentials', 401)

        except Exception as e:
            logger.error(f"Error in login: {e}")
            return render_error('login.html', 'An error occurred during login', 500)

    return render_template('login.html')

@app.route('/moderator')
def moderator_dashboard():
    if not session.get('is_moderator'):
        return redirect(url_for('home'))
    return render_template('moderator.html')

@app.route('/logout')
def logout():
    username = session.get('username', 'unknown')
    session.clear()
    logger.info(f"User logged out: {username}")
    return redirect(url_for('home'))

@app.route('/game/<username>')
def game(username):
    if 'username' in session and session['username'] == username:
        return render_template('game.html', username=username)
    return redirect(url_for('home'))

@app.route('/generate_qr')
def generate_qr():
    try:
        url = request.host_url
        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        buf = BytesIO()
        img.save(buf, format='PNG')
        buf.seek(0)
        return send_file(buf, mimetype='image/png', as_attachment=True, download_name='website_qr.png')
    except Exception as e:
        logger.error(f"Error generating QR code: {e}")
        return abort(500)

@app.route('/qr')
def qr_page():
    return render_template('qr.html')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"Internal server error: {e}")
    return render_template('500.html'), 500

# Production WSGI entry point
if __name__ == '__main__':
    # This will only run in development
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
else:
    # Production mode
    app.logger.setLevel(logging.INFO)