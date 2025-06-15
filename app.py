from flask import Flask, render_template, request, jsonify, flash, session, send_file, redirect, url_for
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
from werkzeug.utils import secure_filename
from signer import extract_private_key, extract_cert, extract_public_key, sign_pdf, embed_qrcode_with_signature_data
import base64
from datetime import datetime
from bson.objectid import ObjectId
from pypdf import PdfReader, PdfWriter
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from verify import verify_pdf, extract_qr_data_from_pdf, hash_pdf_content

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

@app.route('/download-pfx/<org_id>')
@login_required
def download_pfx(org_id):
    pfx_path = f'storage/pfx/{org_id}.pfx'
    if os.path.exists(pfx_path):
        return send_file(pfx_path, as_attachment=True)
    else:
        flash('PFX file not found.', 'danger')
        return redirect(request.referrer or url_for('csr_page'))
    
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
    ca_cert = None

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

    # Lấy CA cert (dạng PEM) từ bất kỳ cert hoặc từ DB
    if cert_details and cert_details.get("ca_cert"):
        ca_cert = cert_details["ca_cert"]
    elif certs and certs[0].get("ca_cert"):
        ca_cert = certs[0]["ca_cert"]
    else:
        from db.mongo_setup import db
        ca = db.ca.find_one({}, {'_id': 0, 'ca_cert': 1})
        ca_cert = ca.get("ca_cert") if ca else None

    # Giải mã cert base64 nếu có
    if cert_details and cert_details.get("cert_data"):
        try:
            cert_pem = base64.b64decode(cert_details["cert_data"]).decode()
            cert_details["cert_pem"] = cert_pem
        except Exception:
            cert_details["cert_pem"] = cert_details["cert_data"]

    # Parse CA cert để lấy thông tin chi tiết
    ca_cert_details = None
    if ca_cert:
        try:
            ca_cert_obj = x509.load_pem_x509_certificate(ca_cert.encode())
            ca_cert_details = {
                "cert_subject": ca_cert_obj.subject.rfc4514_string(),
                "cert_issuer": ca_cert_obj.issuer.rfc4514_string(),
                "cert_valid_from": ca_cert_obj.not_valid_before.strftime('%d/%m/%Y %H:%M:%S'),
                "cert_valid_to": ca_cert_obj.not_valid_after.strftime('%d/%m/%Y %H:%M:%S')
            }
        except Exception:
            ca_cert_details = None

    return render_template(
        'cert_lookup.html',
        certs=certs,
        cert_details=cert_details,
        org_id=org_id,
        ca_cert_pem=ca_cert,  # Gán ca_cert_pem = ca_cert (PEM string)
        ca_cert_details=ca_cert_details
    )

@app.route('/download-cert/<org_id>')
@login_required
def download_cert(org_id):
    cert_path = f'storage/certs/{org_id}.crt'
    if os.path.exists(cert_path):
        return send_file(cert_path, as_attachment=True)
    else:
        flash('Certificate file not found.', 'danger')
        return redirect(request.referrer or url_for('cert_lookup_page'))
    
@app.route('/docs/sign', methods=['GET', 'POST'])
@login_required  
@gov_required   
def sign_page():
    if request.method == 'POST':
        try:
            pdf_file = request.files['pdf_file']
            pfx_file = request.files['pfx_file']
            passphrase = request.form['passphrase']

            signer_name = session.get('user', 'Unknown')
            user_data = db.users.find_one({"username": signer_name})
            display_name = user_data.get("display_name", signer_name)
            position = user_data.get("position", "")

            cert_path = f'storage/certs/{signer_name}.crt'
            if not os.path.exists(cert_path):
                flash(f"Không tìm thấy chứng chỉ đã được CA cấp cho '{signer_name}'. Vui lòng yêu cầu CA cấp chứng chỉ trước.", 'danger')
                return render_template('sign.html')

            filename = secure_filename(pdf_file.filename)
            pfx_filename = secure_filename(pfx_file.filename)

            os.makedirs('storage/sign', exist_ok=True)
            pdf_path = os.path.join('storage/sign', filename)
            pfx_path = os.path.join('storage/sign', pfx_filename)

            pdf_file.save(pdf_path)
            pfx_file.save(pfx_path)

            # Trích xuất private key từ file PFX
            private_key_pem = extract_private_key(pfx_path, passphrase)

            # Ký PDF
            signature_bytes, original_hash_bytes = sign_pdf(pdf_path, private_key_pem)
            signature_b64_str = base64.b64encode(signature_bytes).decode('utf-8')
            original_hash_b64_str = base64.b64encode(original_hash_bytes).decode('utf-8')

            with open(cert_path, 'rb') as f:
                cert_pem_bytes = f.read()

            cert_pem_str = cert_pem_bytes.decode('utf-8')
            public_key_pem = extract_public_key(cert_pem_bytes)

            # Tạo file đầu ra trước
            os.makedirs('storage/signed', exist_ok=True)
            signed_pdf_path = os.path.join('storage/signed', f'signed_{filename}')

            # Gọi hàm embed QR code và nhận về signature_id + full_data
            signature_id, full_signature_data = embed_qrcode_with_signature_data(
                pdf_path=pdf_path,
                signer_name=display_name,
                signer_position=position,
                signature_b64=signature_b64_str,
                public_key_pem=public_key_pem,
                certificate_pem=cert_pem_str,
                original_hash_b64=original_hash_b64_str,
                output_pdf_path=signed_pdf_path,
                file_id=None
            )

            # Lưu thông tin vào database với signature_id
            inserted = db.signed_files.insert_one({
                'signature_id': signature_id,
                'filename': f'signed_{filename}',
                'original_filename': filename,
                'signer': display_name,
                'position': position,
                'signed_time': datetime.utcnow(),
                'signature_b64': signature_b64_str,
                'original_hash_b64': original_hash_b64_str,
                'public_key_pem': public_key_pem,
                'certificate_pem': cert_pem_str,
                'ispublic': False
            })

            file_id = str(inserted.inserted_id)

            # Lưu thông tin signature đầy đủ vào collection riêng
            db.signatures.insert_one({
                'signature_id': signature_id,
                'file_id': file_id,
                **full_signature_data
            })

            os.remove(pdf_path)
            os.remove(pfx_path)

            return redirect(url_for('signed_files_page'))
        except Exception as e:
            flash(f"Lỗi khi ký PDF: {e}", 'danger')

    return render_template('sign.html')



@app.route('/docs/signed_files')
def signed_files_page():
    files = list(db.signed_files.find().sort('signed_time', -1))  # Lấy mới nhất trước
    return render_template('signed_files.html', files=files)

from flask import send_from_directory

@app.route('/docs/make_public/<file_id>', methods=['POST'])
def make_file_public(file_id):
    db.signed_files.update_one(
        {'_id': ObjectId(file_id)},
        {'$set': {'ispublic': True}}
    )
    return redirect(url_for('signed_files_page'))

@app.route('/download/<filename>')
def download_signed_pdf(filename):
    record = db.signed_files.find_one({'filename': filename})

    if record and record.get('ispublic'):
        filepath = os.path.join('storage/signed', filename)
        if os.path.exists(filepath):
            return send_file(filepath, as_attachment=True)
        else:
            return "File not found on server", 404
    else:
        return "File not found or not public", 404

@app.route('/docs/public')
@login_required 
def public_files_page():
    files = list(db.signed_files.find({'ispublic': True}).sort('signed_time', -1))
    return render_template('public_files.html', files=files)

@app.route('/verify')
def verify_from_qr():
    signature_id = request.args.get('id')
    if not signature_id:
        return "Thiếu signature ID", 400
    
    try:
        print(f"🔍 DEBUG: signature_id = {signature_id}")
        
        signature_data = db.signatures.find_one({'signature_id': signature_id})
        if not signature_data:
            return "Không tìm thấy thông tin chữ ký", 404
                    
        file_data = db.signed_files.find_one({'signature_id': signature_id})
        verification_result = None
        
        if file_data and file_data.get('ispublic'):
            filename = file_data.get('filename')
            file_path = os.path.join('storage/signed', filename)
            
            
            if os.path.exists(file_path):
                try:
                    qr_data = extract_qr_data_from_pdf(file_path)
                    
                    current_hash = hash_pdf_content(file_path)
                    db_original_hash = base64.b64decode(signature_data['original_hash'])
                
                    is_valid, reason, details = verify_pdf(file_path)
                    print(f"🔍 DEBUG: verify_pdf result: is_valid={is_valid}, reason={reason}")

                    details['signer'] = signature_data.get('signer')
                    details['position'] = signature_data.get('position', '')

                    result = {
                        'is_valid': is_valid,
                        'reason': reason,
                        'details': details
                    }
                except Exception as e:
                    print(f"🔍 DEBUG: Exception during verification: {str(e)}")
                    result = {
                        'is_valid': False,
                        'reason': f'Lỗi khi xác minh: {str(e)}',
                        'details': {}
                    }
            else:
                result = {
                    'is_valid': False,
                    'reason': 'File không tồn tại trên server.',
                    'details': signature_data
                }
        else:
            result = {
                'is_valid': None,
                'reason': 'File không public hoặc không tồn tại.',
                'details': signature_data
            }
        
        return render_template(
            "verify.html",
            signature_data=signature_data,
            file_data=file_data,
            result=result,
            details=result['details'],
            from_qr=True
        )
    except Exception as e:
        print(f"🔍 DEBUG: Route exception: {str(e)}")
        return f"Lỗi xác minh: {str(e)}", 500

@app.route('/verify/upload', methods=['GET', 'POST'])
def verify_page():
    result = None
    message = ''
    details = None
    users = list(db.users.find({"role": "Government"}, {'_id': 0, 'username': 1, 'display_name': 1}))

    if request.method == 'POST':
        pdf_file = request.files.get('signed_pdf')
        selected_user = request.form.get('selected_user')
        
        if not pdf_file or pdf_file.filename == '':
            result = False
            message = 'Please select a PDF file to verify.'
        else:
            os.makedirs("temp_uploads", exist_ok=True)
            filename = secure_filename(pdf_file.filename)
            file_path = os.path.join("temp_uploads", filename)
            pdf_file.save(file_path)

            try:
                # Bạn có thể dùng selected_user để thay đổi cách xác minh
                is_valid, reason, verification_details = verify_pdf(file_path)

                # Truy xuất public key của người được chọn
                selected_user_data = db.users.find_one({"username": selected_user})
                selected_user_cert_path = f"storage/certs/{selected_user}.crt"

                if selected_user_data and os.path.exists(selected_user_cert_path):
                    with open(selected_user_cert_path, "rb") as f:
                        cert_pem_bytes = f.read()

                    selected_pubkey = extract_public_key(cert_pem_bytes).strip()
                    actual_pubkey = verification_details.get("public_key", "").strip()
                    actual_signer = verification_details.get("signer", "").strip()
                    selected_display_name = selected_user_data.get("display_name", "").strip()

                    # So sánh tên người ký & public key
                    if selected_pubkey != actual_pubkey or selected_display_name != actual_signer:
                        is_valid = False
                        reason = "Người được chọn không phải là người ký thật sự trong tài liệu."
                else:
                    is_valid = False
                    reason = "Không tìm thấy chứng chỉ hợp lệ cho người dùng được chọn."

                verification_details['signer'] = verification_details.get('signer', '')
                verification_details['position'] = verification_details.get('position', '')

                result = is_valid
                message = reason
                details = verification_details
            except Exception as e:
                result = False
                message = f"An unknown error occurred: {e}"
            finally:
                if os.path.exists(file_path):
                    os.remove(file_path)

    return render_template('verify.html', result=result, message=message, details=details, users=users)


if __name__ == "__main__":
    create_directories()
    app.run(host='0.0.0.0', port=5001, debug=True)