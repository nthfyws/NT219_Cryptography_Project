import os
import base64
import hashlib
import subprocess
import tempfile
from datetime import datetime, timezone
from PyPDF2 import PdfReader, PdfWriter
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from io import BytesIO
from dateutil import parser

# Đường dẫn tới các file của CA
CA_CERT_PATH = 'storage/ca/ca.crt'
CA_CRL_PATH = 'storage/ca/crl.pem'

def hash_pdf_content(pdf_path):

    reader = PdfReader(pdf_path)
    hasher = hashlib.sha256()
    
    for page in reader.pages:
        hasher.update(page.extract_text().encode('utf-8'))
            
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
        if not all(k in metadata for k in ['/Signature', '/PublicKey', '/Certificate']):
            return False, "PDF không chứa đủ thông tin chữ ký (Signature, PublicKey, Certificate)."
        
        details['signer'] = metadata.get('/SignedBy')
        # details['signed_at'] = metadata.get('/SignedAt')
        signed_at_iso = metadata.get('/SignedAt')
        if signed_at_iso:
            try:
                # Parse chuỗi ISO thành đối tượng datetime
                dt_obj = parser.isoparse(signed_at_iso)
                # Định dạng lại theo kiểu Việt Nam
                details['signed_at'] = dt_obj.strftime('%H:%M:%S ngày %d-%m-%Y')
            except (ValueError, TypeError):
                details['signed_at'] = signed_at_iso # Giữ nguyên nếu không parse được
        details['algorithm'] = metadata.get('/SignatureAlgorithm')

        signature_b64 = metadata['/Signature']
        public_key_pem = metadata['/PublicKey']
        certificate_pem = metadata['/Certificate']
        signature = base64.b64decode(signature_b64)
        
        
        current_hash = hash_pdf_content(signed_pdf_path)

        # Kiểm tra Certificate của người ký
        # Load Certificate của người ký (từ metadata) và của CA (từ file)
        if not os.path.exists(CA_CERT_PATH):
            return False, "Không tìm thấy Certificate của CA để xác minh."
            
        signer_cert_obj = x509.load_pem_x509_certificate(certificate_pem.encode())
        details['cert_subject'] = signer_cert_obj.subject.rfc4514_string()
        details['cert_issuer'] = signer_cert_obj.issuer.rfc4514_string()

        valid_from_dt = signer_cert_obj.not_valid_before
        valid_to_dt = signer_cert_obj.not_valid_after
        
        details['cert_valid_from'] = valid_from_dt.strftime('%H:%M:%S ngày %d-%m-%Y')
        details['cert_valid_to'] = valid_to_dt.strftime('%H:%M:%S ngày %d-%m-%Y')

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
            message = f"Xác minh chuỗi chứng chỉ thất bại: Certificate không được CA tin cậy ký. Lỗi: {result.stderr}"
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
            return False, "Certificate đã hết hạn hoặc chưa có hiệu lực.", details
        
        # Kiểm tra Certificate có trong danh sách thu hồi (CRL) không
        if os.path.exists(CA_CRL_PATH):
            with open(CA_CRL_PATH, 'rb') as f:
                crl_data = f.read()
                crl = x509.load_pem_x509_crl(crl_data)
                for revoked_cert in crl:
                    if revoked_cert.serial_number == signer_cert_obj.serial_number:
                        return False, f"Certificate đã bị thu hồi vào ngày {revoked_cert.revocation_date_utc}."

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
            return False, f"Không thể trích xuất public key từ certificate. Lỗi: {result.stderr}"

        # Lấy public key đã trích xuất từ certificate
        pubkey_from_cert_pem = result.stdout

        # So sánh với public key trong metadata
        if pubkey_from_cert_pem.strip() != public_key_pem.strip():
            return False, "Public Key trong metadata không khớp với Public Key trong Certificate."


        # Xác minh chữ ký bằng Public Key (dùng OpenSSL)
        # Tạo các file tạm để chứa hash, signature, và public key
        with tempfile.NamedTemporaryFile(delete=False) as hash_file, \
             tempfile.NamedTemporaryFile(delete=False) as sig_file, \
             tempfile.NamedTemporaryFile(mode='w+', delete=False) as pubkey_file:
            
            hash_file.write(current_hash)
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
            return False, f"Chữ ký không hợp lệ. Lỗi: {result.stderr}"

    except Exception as e:
        return False, f"Đã xảy ra lỗi trong quá trình xác minh: {str(e)}"

    # Nếu tất cả các bước đều thành công
    return True, "Xác minh thành công! Chữ ký trên tài liệu là hợp lệ.", details