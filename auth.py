from flask import Blueprint, request, jsonify, session, redirect, url_for, render_template, flash
from pymongo import MongoClient
import os
from werkzeug.security import check_password_hash, generate_password_hash

auth_bp = Blueprint('auth', __name__)

# MongoDB client setup
MONGODB_URI = os.getenv("MONGODB_URI")
client = MongoClient(MONGODB_URI)
db = client["NT219_Cryptography_Project"]

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    data = request.form
    username = data.get('username')
    password = data.get('password')
    user = db.users.find_one({"username": username})
    
    if user and check_password_hash(user['password'], password):
        session['user'] = username
        session['role'] = user.get('role', 'user')
        flash('Login successful!', 'success')
        return redirect(url_for('dashboard.dashboard'))
    
    flash('Invalid username or password', 'danger')
    return redirect(url_for('auth.login'))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not username or not password:
        flash('Username and password are required', 'danger')
        return redirect(url_for('auth.register'))
    
    if db.users.find_one({"username": username}):
        flash('Username already exists', 'danger')
        return redirect(url_for('auth.register'))
    
    hashed_password = generate_password_hash(password)
    db.users.insert_one({
        "username": username,
        "password": hashed_password,
        "role": "user"  # Mặc định là user, có thể nâng cấp sau
    })
    
    flash('Registration successful! Please login.', 'success')
    return redirect(url_for('auth.login'))

@auth_bp.route('/api/roles', methods=['GET'])
def get_roles():
    roles = db.roles.find()
    return jsonify([role for role in roles]), 200

@auth_bp.route('/api/assign-role', methods=['POST'])
def assign_role():
    data = request.json
    username = data.get('username')
    role = data.get('role')

    db.users.update_one({"username": username}, {"$set": {"role": role}})
    return jsonify({"message": "Role assigned successfully"}), 200

@auth_bp.route('/logout')
def logout():
    # Xử lý đăng xuất ở đây, ví dụ:
    session.clear()
    return redirect(url_for('auth.login'))