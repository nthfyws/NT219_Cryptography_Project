from flask import Flask, render_template, request, jsonify, flash, session, send_file
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
import glob

# Load .env file
load_dotenv()

# Read environment variables
MONGODB_URI = os.getenv("MONGODB_URI")
CA_PASSPHRASE = os.getenv("CA_PASSPHRASE")

# Init Flask
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(dashboard_bp)

# MongoDB client
client = pymongo.MongoClient(
    MONGODB_URI,
    tls=True,
    tlsCAFile=certifi.where()
)

db = client["NT219_Cryptography_Project"]

# Tạo các thư mục cần thiết khi khởi động
def create_directories():
    required_dirs = [
        'storage/ca',
        'storage/csr',
        'storage/pfx',
    ]
    for directory in required_dirs:
        os.makedirs(directory, exist_ok=True)

@app.route('/keygen', methods=['GET', 'POST'])
@login_required
@gov_required
def keygen_page():
    gov_passphrase_exists = os.path.exists(f'storage/pfx/{session["user"]}.pfx')
    if request.method == 'POST':
        try:
            data = {
                "org_info": session['user'],
                "passphrase": request.form.get('passphrase')
            }
            result = generate_dilithium_keypair(data)
            if hasattr(result, "get_json"):
                result_json = result.get_json()
                pfx_file = result_json.get('pfx_file')
            else:
                pfx_file = result.get('pfx_file')
            flash('Key pair generated successfully!', 'success')
            return render_template('keygen.html', pfx_file=pfx_file, gov_passphrase_exists=gov_passphrase_exists)
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
    return render_template('keygen.html', gov_passphrase_exists=gov_passphrase_exists)

@app.route('/csr', methods=['GET', 'POST'])
@login_required
@gov_required
def csr_page():
    if request.method == 'POST':
        try:
            data = {
                "org_info": session['user'],
                "passphrase": request.form.get('passphrase')
            }
            result = generate_csr(data)
            # Nếu trả về tuple (response, status_code)
            if isinstance(result, tuple):
                response = result[0]
                result_json = response.get_json()
                flash(f"Error: {result_json.get('error')}", 'danger')
                return render_template('csr.html')
            # Nếu trả về response Flask
            elif hasattr(result, "get_json"):
                result_json = result.get_json()
                flash('CSR generated successfully!', 'success')
                return render_template('csr.html', csr_data=result_json['csr_base64'])
            # Nếu trả về dict (hiếm gặp)
            else:
                flash('CSR generated successfully!', 'success')
                return render_template('csr.html', csr_data=result['csr_base64'])
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
    return render_template('csr.html')


@app.route('/ca-operations', methods=['GET', 'POST'])
@login_required
@ca_required
def ca_operations_page():
    active_certs = []
    for cert in db.certificates.find({"status": "ACTIVE"}):
        active_certs.append(cert)
    
    ca_cert = None
    cert_base64 = None
    crl_file = None
    ca_exists = os.path.exists('storage/ca/ca.crt')

    # Lấy danh sách CSR chưa ký và đã ký
    pending_csrs = []
    signed_csrs = []
    if os.path.exists('storage/csr'):
        for csr_file in glob.glob('storage/csr/*.csr'):
            org = os.path.splitext(os.path.basename(csr_file))[0]
            cert_file = f'storage/certs/{org}.crt'
            if os.path.exists(cert_file):
                signed_csrs.append(os.path.basename(csr_file))
            else:
                pending_csrs.append(os.path.basename(csr_file))

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
                flash('Certificate signing failed: Wrong CA passphrase or Organization Information.', 'danger')
        elif action == 'revoke_cert':
            org_info = request.form.get('org_info')
            passphrase = request.form.get('passphrase')
            reason = request.form.get('reason')
            try:
                crl_file = revoke_cert(org_info, passphrase, reason)
                db.certificates.update_one(
                    {"org": org_info},
                    {"$set": {"status": "REVOKED"}}
                )
                flash('Certificate revoked successfully!', 'success')
            except Exception as e:
                flash('Cerificate revoking failed: Wrong CA passphrase/Organization not found/Certificate already revoked.', 'danger')

    return render_template('ca_operations.html', ca_cert=ca_cert, cert_base64=cert_base64, crl_file=crl_file, ca_exists=ca_exists, pending_csrs=pending_csrs, signed_csrs=signed_csrs, active_certs=active_certs)

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
            if hasattr(cert_details, "get_json"):
                cert_details = cert_details.get_json()
    else:
        org_id = request.args.get('org_id')
        if org_id:
            cert_details = get_cert_by_orgid(org_id)
            if hasattr(cert_details, "get_json"):
                cert_details = cert_details.get_json()
        all_certs = get_all_certs()
        if hasattr(all_certs, "get_json"):
            certs = all_certs.get_json().get('certificates', [])
        elif isinstance(all_certs, dict):
            certs = all_certs.get('certificates', [])
        elif isinstance(all_certs, list):
            certs = all_certs

    # Giải mã cert base64 nếu có
    if cert_details and cert_details.get("cert_data"):
        try:
            cert_pem = base64.b64decode(cert_details["cert_data"]).decode()
            cert_details["cert_pem"] = cert_pem
        except Exception:
            cert_details["cert_pem"] = cert_details["cert_data"]

    return render_template('cert_lookup.html', certs=certs, cert_details=cert_details, org_id=org_id)

@app.route('/download-cert/<org_id>')
@login_required
def download_cert(org_id):
    cert_path = f'storage/certs/{org_id}.crt'
    if os.path.exists(cert_path):
        return send_file(cert_path, as_attachment=True)
    else:
        flash('Certificate file not found.', 'danger')
        return redirect(request.referrer or url_for('cert_lookup_page'))

if __name__ == "__main__":
    create_directories()
    app.run(host='0.0.0.0', port=5001, debug=True)