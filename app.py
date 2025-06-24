from flask import Flask, render_template, request, redirect, url_for, session, send_file, abort, jsonify
from pymongo import MongoClient
from flask_session import Session
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
import os
import qrcode
from io import BytesIO

# Load environment variables
load_dotenv()

app = Flask(__name__, template_folder='Templates', static_folder='static')
app.secret_key = os.getenv('SECRET_KEY', os.urandom(24))
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# MongoDB setup
client = MongoClient(os.getenv('MONGO_URI', 'mongodb://localhost:27017/'))
db = client['game_db']
users_collection = db['users']

ADMIN_USERNAME = os.getenv('ADMIN_USERNAME')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')

# Reusable error rendering
def render_error(template, message):
    return render_template(template, error=message)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['is_admin'] = True
            session['username'] = username
            return redirect(url_for('admin_dashboard'))
        return render_template('admin_login.html', error='Invalid admin credentials')
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
    users = list(users_collection.find({}, {'_id': 0, 'password': 0}))
    return render_template('users.html', users=users)

@app.route('/admin/delete_user/<username>')
def delete_user(username):
    if not session.get('is_admin'): return abort(403)
    users_collection.delete_one({'username': username})
    return jsonify(success=True)

@app.route('/admin/edit_user/<username>', methods=['POST'])
def edit_user(username):
    if not session.get('is_admin'): return abort(403)
    data = request.get_json()
    print(f"Edit request for {username}: {data}")
    users_collection.update_one({'username': username}, {'$set': {'email': data.get('email')}})
    return jsonify(success=True)

@app.route('/admin/recover_user/<username>', methods=['POST'])
def recover_user(username):
    if not session.get('is_admin'): return abort(403)
    data = request.get_json()
    print(f"Recover request for {username}: {data}")
    hashed_pw = generate_password_hash(data.get('password'))
    users_collection.update_one({'username': username}, {'$set': {'password': hashed_pw}})
    return jsonify(success=True)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            return render_error('register.html', 'Passwords do not match.')

        if users_collection.find_one({'username': username}):
            return render_error('register.html', 'Username already exists.')

        if users_collection.find_one({'email': email}):
            return render_error('register.html', 'Email already exists.')

        hashed_pw = generate_password_hash(password)
        users_collection.insert_one({
            'username': username,
            'email': email,
            'password': hashed_pw
        })
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        user = users_collection.find_one({'username': username})
        if user and check_password_hash(user['password'], password):
            session['username'] = username
            return redirect(url_for('game', username=username))
        else:
            return render_error('login.html', 'Invalid credentials')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/game/<username>')
def game(username):
    if 'username' in session and session['username'] == username:
        return render_template('game.html', username=username)
    return redirect(url_for('home'))

@app.route('/generate_qr')
def generate_qr():
    url = request.host_url
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buf = BytesIO()
    img.save(buf)
    buf.seek(0)
    return send_file(buf, mimetype='image/png', download_name='website_qr.png')

@app.route('/qr')
def qr_page():
    return render_template('qr.html')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    return "Access Denied", 403

if __name__ == '__main__':
    app.run(debug=True)
