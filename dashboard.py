from flask import Blueprint, render_template, session, redirect, url_for
from pymongo import MongoClient
import os
from datetime import datetime, timedelta

dashboard_bp = Blueprint('dashboard', __name__)

# MongoDB client setup
MONGODB_URI = os.getenv("MONGODB_URI")
client = MongoClient(MONGODB_URI)
db = client["NT219_Cryptography_Project"]

@dashboard_bp.route('/')
@dashboard_bp.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('auth.login'))
    
    # Lấy thông tin CA
    ca_status = db.ca.count_documents({}) > 0
    
    # Đếm số lượng chứng chỉ
    cert_count = db.certificates.count_documents({})
    
    # Đếm số chứng chỉ bị thu hồi
    revoked_count = db.crl.count_documents({})
    
    # Lấy hoạt động gần đây (7 ngày)
    recent_activities = list(db.audit_logs.find(
        {"timestamp": {"$gte": (datetime.utcnow() - timedelta(days=7)).isoformat()}},
        {"_id": 0}
    ).sort("timestamp", -1).limit(5))
    
    return render_template(
        'dashboard.html',
        user=session['user'],
        role=session.get('role'),
        ca_status=ca_status,
        cert_count=cert_count,
        revoked_count=revoked_count,
        recent_activities=recent_activities
    )