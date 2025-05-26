from flask import Flask, render_template, request, jsonify, flash
from keygen import generate_dilithium_keypair
from csr import generate_csr
from ca import create_ca_cert, sign_csr, revoke_cert, get_ca_cert
from lookup import get_cert_by_orgid, get_all_certs
import os
import certifi
import pymongo
from dotenv import load_dotenv
from flask_cors import CORS
from auth import auth_bp
from dashboard import dashboard_bp
from crl import get_crl
from middleware import ca_required, gov_required, login_required

from filters import datetimeformat

# Load .env file
load_dotenv()

# Read environment variables
MONGODB_URI = os.getenv("MONGODB_URI")
CA_PASSPHRASE = os.getenv("CA_PASSPHRASE")

# Init Flask
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")
app.jinja_env.filters['datetimeformat'] = datetimeformat

app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(dashboard_bp)

# MongoDB client
client = pymongo.MongoClient(
    MONGODB_URI,
    tls=True,
    tlsCAFile=certifi.where()
)

db = client["NT219_Cryptography_Project"]

# API Routes
app.route('/api/crl', methods=['GET'])(get_crl)

# Protect important routes
app.route('/api/generate-keypair', methods=['POST'])(gov_required(generate_dilithium_keypair))
app.route('/api/generate-csr', methods=['POST'])(gov_required(generate_csr))
app.route('/api/ca/init', methods=['POST'])(ca_required(create_ca_cert))
app.route('/api/ca/sign-csr', methods=['POST'])(ca_required(sign_csr))
app.route('/api/ca/revoke-cert', methods=['POST'])(ca_required(revoke_cert))
app.route('/api/get-cert/<org_id>', methods=['GET'])(get_cert_by_orgid)
app.route('/api/get-all-certs', methods=['GET'])(get_all_certs)
app.route('/api/ca/cert', methods=['GET'])(get_ca_cert)

# Tạo các thư mục cần thiết khi khởi động
def create_directories():
    required_dirs = [
        'storage/ca',
        'storage/certs',
        'storage/csr',
        'storage/pfx',
        'storage/templates'
    ]
    for directory in required_dirs:
        os.makedirs(directory, exist_ok=True)

# Thêm các route mới
@app.route('/keygen', methods=['GET', 'POST'])
@login_required
@gov_required
def keygen_page():
    if request.method == 'POST':
        try:
            data = {
                "org_info": request.form.get('org_info'),
                "passphrase": request.form.get('passphrase')
            }
            result = generate_dilithium_keypair(data)
            flash('Key pair generated successfully!', 'success')
            return render_template('keygen.html', pfx_file=result['pfx_file'])
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
    return render_template('keygen.html')

@app.route('/csr', methods=['GET', 'POST'])
@login_required
@gov_required
def csr_page():
    if request.method == 'POST':
        try:
            data = {
                "org_info": request.form.get('org_info'),
                "passphrase": request.form.get('passphrase')
            }
            result = generate_csr(data)
            flash('CSR generated successfully!', 'success')
            return render_template('csr.html', csr_data=result['csr_base64'])
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
    return render_template('csr.html')


@app.route('/ca-operations', methods=['GET', 'POST'])
@login_required
@ca_required
def ca_operations_page():
    ca_cert = None
    cert_base64 = None
    crl_file = None

    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'init_ca':
            passphrase = request.form.get('passphrase')
            try:
                ca_cert = create_ca_cert(passphrase)
                flash('CA initialized successfully!', 'success')
            except Exception as e:
                flash(f'Error initializing CA: {str(e)}', 'danger')
        elif action == 'sign_csr':
            org_info = request.form.get('org_info')
            passphrase = request.form.get('passphrase')
            try:
                cert_base64 = sign_csr(org_info, passphrase)
                flash('Certificate signed successfully!', 'success')
            except Exception as e:
                flash(f'Error signing certificate: {str(e)}', 'danger')
        elif action == 'revoke_cert':
            org_info = request.form.get('org_info')
            passphrase = request.form.get('passphrase')
            reason = request.form.get('reason')
            try:
                crl_file = revoke_cert(org_info, passphrase, reason)
                flash('Certificate revoked successfully!', 'success')
            except Exception as e:
                flash(f'Error revoking certificate: {str(e)}', 'danger')

    return render_template('ca_operations.html', ca_cert=ca_cert, cert_base64=cert_base64, crl_file=crl_file)

@app.route('/cert-lookup', methods=['GET', 'POST'])
@login_required
def cert_lookup_page():
    certs = []
    cert_details = None
    org_id = None

    if request.method == 'POST':
        org_id = request.form.get('org_id')
        if org_id:
            cert_details = get_cert_by_orgid(org_id)
            # Nếu get_cert_by_orgid trả về response Flask, dùng .get_json()
            if hasattr(cert_details, "get_json"):
                cert_details = cert_details.get_json()
    else:
        # GET: lấy tất cả certs
        all_certs = get_all_certs()
        # Nếu trả về response Flask
        if hasattr(all_certs, "get_json"):
            certs = all_certs.get_json().get('certificates', [])
        # Nếu trả về dict
        elif isinstance(all_certs, dict):
            certs = all_certs.get('certificates', [])
        # Nếu trả về list
        elif isinstance(all_certs, list):
            certs = all_certs

    return render_template('cert_lookup.html', certs=certs, cert_details=cert_details, org_id=org_id)

if __name__ == "__main__":
    create_directories()
    app.run(host='0.0.0.0', port=5001, debug=True)