import os
import base64
import hashlib
import subprocess
import tempfile
from datetime import datetime, timezone, timedelta
from PyPDF2 import PdfReader, PdfWriter
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from io import BytesIO
from dateutil import parser
from db.mongo_setup import db
import requests
import pymongo
import json
import fitz  # PyMuPDF
import cv2
import numpy as np
from pyzbar.pyzbar import decode

# Đường dẫn tới các file của CA
CA_CERT_PATH = 'storage/ca/ca.crt'

def download_file(url):
    """Download file from URL with proper error handling"""
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        return resp.content
    except requests.RequestException as e:
        raise Exception(f"Failed to download file from {url}: {str(e)}")

def verify_pdf_without_upload(qr_data):
    """Verify PDF from QR data containing download URL"""
    if 'download_url' not in qr_data:
        return False, "No download_url in QR data to verify file.", {}

    try:
        file_bytes = download_file(qr_data['download_url'])
        
        # Lưu tạm file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmpf:
            tmpf.write(file_bytes)
            tmp_path = tmpf.name

        result = verify_pdf(tmp_path)
        
        # Cleanup
        os.remove(tmp_path)
        return result
        
    except Exception as e:
        return False, f"Error processing file: {str(e)}", {}

def extract_qr_data_from_pdf(pdf_path):
    """
    Trích xuất và giải mã dữ liệu từ mã QR trong file PDF.
    Improved version with better error handling and support for both formats
    """
    try:
        # Mở PDF và duyệt từng trang để tìm QR code
        doc = fitz.open(pdf_path)
        for page_index in range(len(doc)):
            page = doc.load_page(page_index)
            pix = page.get_pixmap()
            img = np.frombuffer(pix.samples, dtype=np.uint8).reshape(pix.height, pix.width, pix.n)

            # Nếu ảnh có alpha channel (4 kênh), bỏ kênh alpha
            if img.shape[2] == 4:
                img = cv2.cvtColor(img, cv2.COLOR_BGRA2BGR)

            qr_codes = decode(img)
            for qr in qr_codes:
                try:
                    data = qr.data.decode('utf-8')
                    
                    # Try to parse as JSON first
                    try:
                        return json.loads(data)
                    except json.JSONDecodeError:
                        # If not JSON, might be a URL - try to extract signature_id
                        if 'verify?id=' in data:
                            signature_id = data.split('verify?id=')[-1]
                            return {'signature_id': signature_id, 'verify_url': data}
                        else:
                            # Return as plain text
                            return {'raw_data': data}
                            
                except Exception as e:
                    print(f"Error decoding QR code: {e}")
                    continue

        doc.close()
        raise ValueError("No valid QR code found in PDF")
        
    except Exception as e:
        raise Exception(f"Error extracting QR data: {str(e)}")

def get_signature_data_from_server(signature_id):
    """
    Retrieve full signature data from server using signature_id
    This function should be implemented based on your server API
    """
    # This is a placeholder - implement based on your server architecture
    try:
        # Example: GET request to your server
        # response = requests.get(f"http://localhost:5001/api/signature/{signature_id}")
        # return response.json()
        
        # For now, try to get from database if available
        if db is not None:
            signature_record = db.signatures.find_one({'signature_id': signature_id})
            if signature_record:
                return signature_record
        
        return None
    except Exception as e:
        print(f"Error retrieving signature data: {e}")
        return None

def safe_subprocess_run(cmd, input_data=None, timeout=30):
    """Safe subprocess execution with proper error handling"""
    try:
        if input_data:
            result = subprocess.run(cmd, input=input_data, capture_output=True, text=False, timeout=timeout)
        else:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result
    except subprocess.TimeoutExpired:
        raise Exception(f"Command timed out: {' '.join(cmd)}")
    except Exception as e:
        raise Exception(f"Command failed: {' '.join(cmd)}, Error: {str(e)}")

def verify_pdf(signed_pdf_path):
    """
    PDF signature verification using Dilithium.
    File được xác minh là bản đã có QR code (vì QR đã được ký chung).
    """
    details = {
        'signer': None,
        'signed_at': None,
        'algorithm': None,
        'cert_subject': None,
        'cert_issuer': None,
        'cert_valid_from': None,
        'cert_valid_to': None,
        'signature_id': None
    }

    try:
        # Extract QR data
        qr_data = extract_qr_data_from_pdf(signed_pdf_path)

        # Retrieve signature data
        if 'signature_id' in qr_data:
            details['signature_id'] = qr_data['signature_id']
            signature_data = get_signature_data_from_server(qr_data['signature_id'])
            if not signature_data:
                return False, "Không thể lấy dữ liệu chữ ký từ server.", details
        elif all(k in qr_data for k in ['signature', 'public_key', 'certificate']):
            signature_data = qr_data
        else:
            return False, "QR code không chứa đủ dữ liệu xác minh.", details

        # Validate fields
        required = ['signature', 'public_key', 'certificate', 'signer', 'signed_at', 'algorithm']
        missing = [f for f in required if f not in signature_data]
        if missing:
            return False, f"Thiếu các trường: {', '.join(missing)}", details

        # Lưu thông tin vào details
        details.update({
            'signer': signature_data['signer'],
            'algorithm': signature_data['algorithm'],
            'position': signature_data.get('position', '')
        })
        try:
            dt_obj = parser.isoparse(signature_data['signed_at'])
            dt_vn = dt_obj.astimezone(timezone(timedelta(hours=7)))
            details['signed_at'] = dt_vn.strftime('%Y-%m-%d %H:%M:%S %Z')
        except:
            details['signed_at'] = signature_data['signed_at']

        # Decode & parse
        signature = base64.b64decode(signature_data['signature'])
        public_key_pem = signature_data['public_key']
        certificate_pem = signature_data['certificate']
        details['public_key'] = public_key_pem.strip()

        # Load certificate
        try:
            signer_cert = x509.load_pem_x509_certificate(certificate_pem.encode())
            details['cert_subject'] = signer_cert.subject.rfc4514_string()
            details['cert_issuer'] = signer_cert.issuer.rfc4514_string()
            vn_tz = timezone(timedelta(hours=7))
            details['cert_valid_from'] = signer_cert.not_valid_before.replace(tzinfo=timezone.utc).astimezone(vn_tz).strftime('%Y-%m-%d %H:%M:%S %Z')
            details['cert_valid_to'] = signer_cert.not_valid_after.replace(tzinfo=timezone.utc).astimezone(vn_tz).strftime('%Y-%m-%d %H:%M:%S %Z')
        except Exception as e:
            return False, f"Lỗi khi đọc certificate: {e}", details

        # Verify CA
        if not os.path.exists(CA_CERT_PATH):
            return False, "Không tìm thấy CA certificate.", details
        try:
            with tempfile.NamedTemporaryFile('w+', delete=False) as cert_file:
                cert_file.write(certificate_pem)
                cert_path = cert_file.name
            result = safe_subprocess_run(['openssl', 'verify', '-CAfile', CA_CERT_PATH, cert_path])
            os.remove(cert_path)
            if result.returncode != 0:
                return False, f"Chứng chỉ không được CA tin cậy: {result.stderr}", details
        except Exception as e:
            return False, f"Lỗi khi xác minh CA: {e}", details

        # Kiểm tra revoked (CRL)
        if db is not None:
            crl_record = db.crl.find_one(sort=[('last_update', pymongo.DESCENDING)])
            if crl_record and 'crl_pem' in crl_record:
                crl = x509.load_pem_x509_crl(crl_record['crl_pem'].encode())
                for revoked in crl:
                    if revoked.serial_number == signer_cert.serial_number:
                        revoked_date = revoked.revocation_date.strftime('%H:%M:%S ngày %d-%m-%Y')
                        return False, f"Chứng chỉ đã bị thu hồi lúc {revoked_date}.", details

        # Kiểm tra public key khớp
        with tempfile.NamedTemporaryFile('w+', delete=False) as f:
            f.write(certificate_pem)
            cert_path = f.name
        result = safe_subprocess_run(['openssl', 'x509', '-pubkey', '-noout', '-in', cert_path])
        os.remove(cert_path)
        if result.returncode != 0 or result.stdout.strip() != public_key_pem.strip():
            return False, "Public key không khớp với chứng chỉ.", details

        # Xác minh chữ ký trên chính file đã ký (không xóa QR nữa)
        msg_file = tempfile.NamedTemporaryFile(delete=False)
        sig_file = tempfile.NamedTemporaryFile(delete=False)
        pub_file = tempfile.NamedTemporaryFile('w+', delete=False)

        with open(signed_pdf_path, 'rb') as f:
            msg_file.write(f.read())
        msg_file.flush()  # Rất quan trọng

        sig_file.write(signature)
        sig_file.flush()

        pub_file.write(public_key_pem)
        pub_file.flush()  # Quan trọng nhất với public key

        cmd = [
            'openssl', 'pkeyutl', '-verify',
            '-pubin',
            '-inkey', pub_file.name,
            '-provider', 'oqsprovider',
            '-provider', 'default',
            '-in', msg_file.name,
            '-sigfile', sig_file.name,
            '-rawin'
        ]
        result = safe_subprocess_run(cmd)

        for tmp in [msg_file, sig_file, pub_file]:
            if tmp and os.path.exists(tmp.name):
                os.remove(tmp.name)

        if result.returncode != 0:
            return False, f"Chữ ký không hợp lệ: {result.stderr}", details

        return True, "Chữ ký hợp lệ.", details

    except Exception as e:
        return False, f"Lỗi không xác định: {e}", details

