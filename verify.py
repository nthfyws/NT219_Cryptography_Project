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

def hash_pdf_content(pdf_path):
    """
    Tạo hash CHỈ từ nội dung text của file PDF.
    """
    try:
        reader = PdfReader(pdf_path)
        hasher = hashlib.sha256()
        
        for page in reader.pages:
            # Lấy text và chuẩn hóa để loại bỏ các khác biệt nhỏ
            text = page.extract_text()
            # Thay thế nhiều ký tự xuống dòng/khoảng trắng thành một và loại bỏ khoảng trắng ở đầu/cuối
            normalized_text = " ".join(text.split())
            hasher.update(normalized_text.encode('utf-8'))
                
        return hasher.digest()
    except Exception as e:
        raise Exception(f"Error hashing PDF content: {str(e)}")

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
    Improved PDF verification with better error handling and support for both QR formats
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
        
        # Handle different QR data formats
        signature_data = None
        
        if 'signature_id' in qr_data:
            # New format - retrieve from server/database
            details['signature_id'] = qr_data['signature_id']
            signature_data = get_signature_data_from_server(qr_data['signature_id'])
            
            if not signature_data:
                return False, "Could not retrieve signature data from server.", details
                
        elif all(field in qr_data for field in ['signature', 'public_key', 'certificate', 'original_hash']):
            # Old format - all data in QR
            signature_data = qr_data
        else:
            return False, "QR code format not recognized or missing required information.", details

        # Validate required fields
        required_fields = ['signature', 'public_key', 'certificate', 'original_hash', 'signer', 'signed_at', 'algorithm']
        missing_fields = [field for field in required_fields if field not in signature_data]
        if missing_fields:
            return False, f"Missing required fields: {', '.join(missing_fields)}", details

        details['signer'] = signature_data['signer']
        details['algorithm'] = signature_data['algorithm']
        details['position'] = signature_data.get('position', '')
        
        # Parse signing time
        try:
            dt_obj = parser.isoparse(signature_data['signed_at'])
            vn_timezone = timezone(timedelta(hours=7))
            dt_obj_vn = dt_obj.astimezone(vn_timezone)
            details['signed_at'] = dt_obj_vn.strftime('%Y-%m-%d %H:%M:%S %Z')
        except (ValueError, TypeError) as e:
            details['signed_at'] = signature_data['signed_at']
            print(f"Warning: Could not parse signing time: {e}")

        # Decode signature components
        try:
            signature = base64.b64decode(signature_data['signature'])
            public_key_pem = signature_data['public_key']
            certificate_pem = signature_data['certificate']
            original_hash = base64.b64decode(signature_data['original_hash'])
        except Exception as e:
            return False, f"Error decoding signature components: {str(e)}", details

        # Verify document integrity
        current_hash = hash_pdf_content(signed_pdf_path)
        if current_hash != original_hash:
            return False, "The document's content has been altered after it was signed.", details

        # Load and validate certificate
        try:
            signer_cert_obj = x509.load_pem_x509_certificate(certificate_pem.encode())
            details['cert_subject'] = signer_cert_obj.subject.rfc4514_string()
            details['cert_issuer'] = signer_cert_obj.issuer.rfc4514_string()
            
            vn_timezone = timezone(timedelta(hours=7))
            # Properly handle timezone for certificate dates
            cert_valid_from = signer_cert_obj.not_valid_before
            cert_valid_to = signer_cert_obj.not_valid_after
            
            if cert_valid_from.tzinfo is None:
                cert_valid_from = cert_valid_from.replace(tzinfo=timezone.utc)
            if cert_valid_to.tzinfo is None:
                cert_valid_to = cert_valid_to.replace(tzinfo=timezone.utc)
                
            details['cert_valid_from'] = cert_valid_from.astimezone(vn_timezone).strftime('%Y-%m-%d %H:%M:%S %Z')
            details['cert_valid_to'] = cert_valid_to.astimezone(vn_timezone).strftime('%Y-%m-%d %H:%M:%S %Z')
            
        except Exception as e:
            return False, f"Error loading certificate: {str(e)}", details

        # Verify certificate chain
        if not os.path.exists(CA_CERT_PATH):
            return False, "The CA certificate could not be found.", details

        try:
            with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.pem') as cert_file:
                cert_file.write(certificate_pem)
                cert_filepath = cert_file.name

            cmd_verify_chain = ['openssl', 'verify', '-CAfile', CA_CERT_PATH, cert_filepath]
            result = safe_subprocess_run(cmd_verify_chain)
            
            os.remove(cert_filepath)
            
            if result.returncode != 0:
                return False, f"Certificate chain verification failed: {result.stderr}", details
                
        except Exception as e:
            return False, f"Error verifying certificate chain: {str(e)}", details

        # Check certificate validity period
        now = datetime.now(timezone.utc)
        if not (cert_valid_from <= now <= cert_valid_to):
            return False, "The signer's certificate has expired or is not yet valid.", details

        # Check certificate revocation list (CRL)
        if db is not None:
            try:
                crl_record = db.crl.find_one(sort=[('last_update', pymongo.DESCENDING)])
                if crl_record and 'crl_pem' in crl_record:
                    crl = x509.load_pem_x509_crl(crl_record['crl_pem'].encode('utf-8'))
                    for revoked_cert in crl:
                        if revoked_cert.serial_number == signer_cert_obj.serial_number:
                            revoked_date = revoked_cert.revocation_date.strftime('%H:%M:%S ngày %d-%m-%Y')
                            return False, f"The signer's certificate was revoked on {revoked_date}.", details
            except Exception as e:
                print(f"Warning: Could not check CRL: {e}")
        else:
            print("Warning: Skipping CRL check due to no database connection.")

        # Verify public key matches certificate
        try:
            with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.pem') as cert_file:
                cert_file.write(certificate_pem)
                cert_filepath = cert_file.name

            cmd_extract_pubkey = ['openssl', 'x509', '-pubkey', '-noout', '-in', cert_filepath]
            result = safe_subprocess_run(cmd_extract_pubkey)
            
            os.remove(cert_filepath)
            
            if result.returncode != 0:
                return False, f"Could not extract public key from certificate: {result.stderr}", details

            pubkey_from_cert_pem = result.stdout.strip()
            if pubkey_from_cert_pem != public_key_pem.strip():
                return False, "The public key does not match the certificate.", details
                
        except Exception as e:
            return False, f"Error verifying public key: {str(e)}", details

        # Verify digital signature
        try:
            with tempfile.NamedTemporaryFile(delete=False) as hash_file, \
                 tempfile.NamedTemporaryFile(delete=False) as sig_file, \
                 tempfile.NamedTemporaryFile(mode='w+', delete=False) as pubkey_file:

                hash_file.write(original_hash)
                sig_file.write(signature)
                pubkey_file.write(public_key_pem)

                hash_filepath = hash_file.name
                sig_filepath = sig_file.name
                pubkey_filepath = pubkey_file.name

            cmd_verify_sig = [
                'openssl', 'pkeyutl', '-verify',
                '-pubin',
                '-inkey', pubkey_filepath,
                '-provider', 'oqsprovider',
                '-provider', 'default',
                '-in', hash_filepath,
                '-sigfile', sig_filepath
            ]
            
            result = safe_subprocess_run(cmd_verify_sig)

            # Cleanup temp files
            for filepath in [hash_filepath, sig_filepath, pubkey_filepath]:
                if os.path.exists(filepath):
                    os.remove(filepath)

            if "Signature Verified Successfully" not in result.stdout:
                return False, f"The signature is invalid. Error: {result.stderr}", details
                
        except Exception as e:
            return False, f"Error verifying signature: {str(e)}", details
        
        # Add more details for display
        details['public_key'] = public_key_pem
        details['certificate'] = certificate_pem
        details['original_hash'] = base64.b64encode(original_hash).decode()  # for display purposes
        details['signature'] = signature_data['signature']  # base64 string for debugging (optional)
        details['signer'] = signature_data.get('signer', '')
        details['position'] = signature_data.get('position', '')

    except Exception as e:
        return False, f"An unexpected error occurred during verification: {str(e)}", details

    return True, "Verification successful: The signature is valid and the document has not been altered.", details