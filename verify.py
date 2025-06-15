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
import pymongo
# Đường dẫn tới các file của CA
CA_CERT_PATH = 'storage/ca/ca.crt'
# CA_CRL_PATH = 'storage/ca/crl.pem'

def hash_pdf_content(pdf_path):
    """
    Tạo hash CHỈ từ nội dung text của file PDF.
    """
    reader = PdfReader(pdf_path)
    hasher = hashlib.sha256()
    
    for page in reader.pages:
        # Lấy text và chuẩn hóa để loại bỏ các khác biệt nhỏ
        text = page.extract_text()
        # Thay thế nhiều ký tự xuống dòng/khoảng trắng thành một và loại bỏ khoảng trắng ở đầu/cuối
        normalized_text = " ".join(text.split())
        hasher.update(normalized_text.encode('utf-8'))
            
    return hasher.digest()

def verify_pdf(signed_pdf_path):
    """
    Xác minh chữ ký số trên file PDF.
    Trả về: (bool, str) -> (is_valid, message)
    """
    details = {
        'signer': None,
        'signed_at': None,
        'algorithm': None,
        'cert_subject': None,
        'cert_issuer': None,
        'cert_valid_from': None,
        'cert_valid_to': None
    }

    try:
        # Trích xuất metadata từ PDF
        reader = PdfReader(signed_pdf_path)
        metadata = reader.metadata
        if not all(k in metadata for k in ['/Signature', '/PublicKey', '/Certificate', '/OriginalHash']):
            return False, "Verification failed: PDF is missing required signature information (Signature, PublicKey, Certificate, OriginalHash).", details
        
        details['signer'] = metadata.get('/SignedBy')
        # details['signed_at'] = metadata.get('/SignedAt')
        signed_at_iso = metadata.get('/SignedAt')
        if signed_at_iso:
            try:
                # Parse chuỗi ISO thành đối tượng datetime
                dt_obj = parser.isoparse(signed_at_iso)
                # Định dạng lại theo kiểu Việt Nam
                vn_timezone = timezone(timedelta(hours=7))
                dt_obj_vn = dt_obj.astimezone(vn_timezone)
                details['signed_at'] = dt_obj_vn.strftime('%Y-%m-%d %H:%M:%S %Z')
            except (ValueError, TypeError):
                details['signed_at'] = signed_at_iso # Giữ nguyên nếu không parse được
        details['algorithm'] = metadata.get('/SignatureAlgorithm')

        signature_b64 = metadata['/Signature']
        public_key_pem = metadata['/PublicKey']
        certificate_pem = metadata['/Certificate']
        original_hash_b64 = metadata['/OriginalHash']

        signature = base64.b64decode(signature_b64)
        original_hash = base64.b64decode(original_hash_b64)
        
        current_hash = hash_pdf_content(signed_pdf_path)
        
        if current_hash != original_hash:
            return False, "Verification failed: The document's content has been altered after it was signed.", details
        # Kiểm tra Certificate của người ký
        # Load Certificate của người ký (từ metadata) và của CA (từ file)
        if not os.path.exists(CA_CERT_PATH):
            return False, "Verification failed: The Certificate Authority (CA) certificate could not be found.", details
            
        signer_cert_obj = x509.load_pem_x509_certificate(certificate_pem.encode())
        details['cert_subject'] = signer_cert_obj.subject.rfc4514_string()
        details['cert_issuer'] = signer_cert_obj.issuer.rfc4514_string()
        

        valid_from_dt = signer_cert_obj.not_valid_before
        valid_to_dt = signer_cert_obj.not_valid_after
        vn_timezone = timezone(timedelta(hours=7))
        valid_from_vn = valid_from_dt.astimezone(vn_timezone)
        valid_to_vn = valid_to_dt.astimezone(vn_timezone)

        details['cert_valid_from'] = valid_from_vn.strftime('%Y-%m-%d %H:%M:%S %Z')
        details['cert_valid_to'] = valid_to_vn.strftime('%Y-%m-%d %H:%M:%S %Z')

        # details['cert_valid_from'] = signer_cert_obj.not_valid_before.isoformat()
        # details['cert_valid_to'] = signer_cert_obj.not_valid_after.isoformat()

        # Kiểm tra xem Certificate có được ký bởi CA không (dùng OpenSSL)
        # Dùng file tạm để OpenSSL có thể đọc
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.pem') as signer_cert_file:
            signer_cert_file.write(certificate_pem)
            signer_cert_filepath = signer_cert_file.name

        cmd_verify_chain = [
            'openssl', 'verify',
            '-CAfile', CA_CERT_PATH,
            signer_cert_filepath
        ]
        result = subprocess.run(cmd_verify_chain, capture_output=True, text=True)
        os.remove(signer_cert_filepath) # Dọn dẹp file tạm
        
        if result.returncode != 0:
            message = f"Certificate chain verification failed: The certificate was not signed by a trusted CA."
            return False, message, details

        # Kiểm tra thời hạn của Certificate
        now = datetime.now(timezone.utc)
        not_valid_before = signer_cert_obj.not_valid_before
        not_valid_after = signer_cert_obj.not_valid_after
        if not_valid_before.tzinfo is None:
            not_valid_before = not_valid_before.replace(tzinfo=timezone.utc)
        if not_valid_after.tzinfo is None:
            not_valid_after = not_valid_after.replace(tzinfo=timezone.utc)

        if not (not_valid_before <= now <= not_valid_after):
            return False, "Verification failed: The signer's certificate has expired or is not yet valid.", details
        
        # Kiểm tra Certificate có trong danh sách thu hồi (CRL) không
        # if os.path.exists(CA_CRL_PATH):
        #     with open(CA_CRL_PATH, 'rb') as f:
        #         crl_data = f.read()
        #         crl = x509.load_pem_x509_crl(crl_data)
        #         for revoked_cert in crl:
        #             if revoked_cert.serial_number == signer_cert_obj.serial_number:
        #                 return False, f"Certificate đã bị thu hồi vào ngày {revoked_cert.revocation_date_utc}.", details
        if db is not None: # Chỉ thực hiện nếu kết nối DB thành công
        # Lấy bản ghi CRL mới nhất từ DB
            crl_record = db.crl.find_one(sort=[('last_update', pymongo.DESCENDING)])
        
            if crl_record and 'crl_pem' in crl_record:
                crl_pem_str = crl_record['crl_pem']
                try:
                # Load CRL từ chuỗi PEM lấy từ DB
                    crl = x509.load_pem_x509_crl(crl_pem_str.encode('utf-8'))
                
                # Kiểm tra xem certificate hiện tại có trong CRL không
                    for revoked_cert in crl:
                        if revoked_cert.serial_number == signer_cert_obj.serial_number:
                            revocation_dt_str = revoked_cert.revocation_date.strftime('%H:%M:%S ngày %d-%m-%Y')
                            return False, f"Verification failed: The signer's certificate was revoked on {revocation_dt_str}.", details
                except Exception as e:
                # Ghi nhận lỗi nếu không parse được CRL, nhưng không làm dừng quá trình xác minh
                    print(f"Could not parse CRL from database. Error: {e}")
        else:
            print("Warning: Skipping CRL check due to no database connection.")

        # Kiểm tra Public Key có khớp không
        # Lấy public key từ certificate đã được xác minh
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.pem') as signer_cert_file:
            signer_cert_file.write(certificate_pem)
            signer_cert_filepath = signer_cert_file.name

        cmd_extract_pubkey = [
            'openssl', 'x509',
            '-pubkey',
            '-noout',
            '-in', signer_cert_filepath
        ]
        result = subprocess.run(cmd_extract_pubkey, capture_output=True, text=True)
        os.remove(signer_cert_filepath) # Dọn dẹp file tạm

        if result.returncode != 0:
            return False, f"Verification failed: Could not extract public key from the certificate. Error: {result.stderr}", details

        # Lấy public key đã trích xuất từ certificate
        pubkey_from_cert_pem = result.stdout

        # So sánh với public key trong metadata
        if pubkey_from_cert_pem.strip() != public_key_pem.strip():
            return False, "Verification failed: The public key in the metadata does not match the public key in the certificate.", details


        # Xác minh chữ ký bằng Public Key (dùng OpenSSL)
        # Tạo các file tạm để chứa hash, signature, và public key
        with tempfile.NamedTemporaryFile(delete=False) as hash_file, \
             tempfile.NamedTemporaryFile(delete=False) as sig_file, \
             tempfile.NamedTemporaryFile(mode='w+', delete=False) as pubkey_file:
            
            # hash_file.write(current_hash)
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
        
        result = subprocess.run(cmd_verify_sig, capture_output=True, text=True)

        # Dọn dẹp file tạm
        os.remove(hash_filepath)
        os.remove(sig_filepath)
        os.remove(pubkey_filepath)
        
        if "Signature Verified Successfully" not in result.stdout:
            return False, f"Verification failed: The signature is invalid or corrupted. Error: {result.stderr}", details
        

    except Exception as e:
        return False, f"An unexpected error occurred during verification: {str(e)}", details

    # Nếu tất cả các bước đều thành công
    return True, "Verification successful: The signature is valid and the document has not been altered.", details