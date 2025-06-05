import base64
import hashlib
import subprocess
import os
from PyPDF2 import PdfReader, PdfWriter
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime
import requests

# Các hằng số cấu hình
CA_PUBLIC_KEY_PATH = 'storage/ca_publickey.pem'
CRL_API_URL = 'http://localhost:5001/api/crl'

def extract_pdf_metadata(pdf_path):
    """Trích xuất tất cả metadata liên quan đến chữ ký từ PDF."""
    try:
        reader = PdfReader(pdf_path)
        meta = reader.metadata
        return {
            'SignedBy': meta.get('/SignedBy'),
            'SignedAt': meta.get('/SignedAt'),
            'SignatureAlgorithm': meta.get('/SignatureAlgorithm'),
            'Signature': meta.get('/Signature'),
            'PublicKey': meta.get('/PublicKey'),
            'Certificate': meta.get('/Certificate'), # Trích xuất thêm certificate
        }
    except Exception as e:
        print(f"Error reading PDF metadata: {e}")
        return {}

def remove_signature_metadata(pdf_path, output_path):
    """Tạo một bản sao của PDF nhưng đã loại bỏ các trường metadata chữ ký."""
    reader = PdfReader(pdf_path)
    writer = PdfWriter()

    for page in reader.pages:
        writer.add_page(page)

    metadata = dict(reader.metadata or {})
    # Các key cần xóa để hash nội dung gốc
    keys_to_remove = [
        '/Signature', '/PublicKey', '/SignedBy', '/SignedAt', 
        '/SignatureAlgorithm', '/Certificate'
    ]
    for key in keys_to_remove:
        metadata.pop(key, None)

    writer.add_metadata(metadata)
    with open(output_path, 'wb') as f_out:
        writer.write(f_out)

def extract_pdf_hash_without_signature(pdf_path):
    """Băm nội dung của file PDF sau khi đã loại bỏ metadata chữ ký."""
    temp_clean_pdf = f"temp_clean_{os.path.basename(pdf_path)}"
    try:
        remove_signature_metadata(pdf_path, temp_clean_pdf)
        with open(temp_clean_pdf, 'rb') as f:
            data = f.read()
        return hashlib.sha256(data).digest()
    finally:
        if os.path.exists(temp_clean_pdf):
            os.remove(temp_clean_pdf)

def extract_public_key_from_cert(cert_pem_str: str) -> str:
    """Trích xuất public key từ một chuỗi certificate PEM."""
    cert_pem_bytes = cert_pem_str.encode('utf-8')
    cmd = ['openssl', 'x509', '-pubkey', '-noout']
    result = subprocess.run(cmd, input=cert_pem_bytes, capture_output=True, check=True)
    return result.stdout.decode('utf-8')

def verify_signature(pdf_hash, signature_b64, public_key_pem):
    """
    Sử dụng OpenSSL để xác minh chữ ký.
    Trả về True nếu hợp lệ, False nếu không.
    """
    temp_dir = "temp_verify_files"
    os.makedirs(temp_dir, exist_ok=True)
    
    sig_file = os.path.join(temp_dir, 'signature.sig')
    hash_file = os.path.join(temp_dir, 'data.hash')
    pub_file = os.path.join(temp_dir, 'public_key.pem')

    try:
        with open(sig_file, 'wb') as f:
            f.write(base64.b64decode(signature_b64))
        with open(hash_file, 'wb') as f:
            f.write(pdf_hash)
        with open(pub_file, 'w') as f:
            f.write(public_key_pem)

        cmd = [
            'openssl', 'pkeyutl', '-verify',
            '-pubin', '-inkey', pub_file,
            '-in', hash_file,
            '-sigfile', sig_file,
            '-provider', 'oqsprovider', '-provider', 'default'
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"OpenSSL verify error: {result.stderr}")
            return False
        
        # OpenSSL pkeyutl -verify trả về "Signature Verified Successfully" ra stdout khi thành công
        return "Signature Verified Successfully" in result.stdout

    finally:
        # Dọn dẹp file tạm
        for f in [sig_file, hash_file, pub_file]:
            if os.path.exists(f):
                os.remove(f)
        if os.path.exists(temp_dir):
            try:
                os.rmdir(temp_dir)
            except OSError:
                pass

def verify_certificate_chain(cert_pem: str) -> bool:
    """Kiểm tra xem certificate có được ký bởi CA tin cậy không."""
    temp_cert_file = "temp_cert_to_verify.pem"
    try:
        with open(temp_cert_file, "w") as f:
            f.write(cert_pem)
        
        cmd = ["openssl", "verify", "-CAfile", CA_PUBLIC_KEY_PATH, temp_cert_file]
        result = subprocess.run(cmd, capture_output=True)
        
        return result.returncode == 0
    finally:
        if os.path.exists(temp_cert_file):
            os.remove(temp_cert_file)

def check_cert_validity_and_crl(cert_pem: str) -> (bool, str):
    """Kiểm tra ngày hiệu lực và trạng thái thu hồi (CRL) của certificate."""
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())

        # 1. Kiểm tra ngày hiệu lực
        now = datetime.utcnow()
        if cert.not_valid_before > now:
            return False, "Chứng chỉ chưa có hiệu lực."
        if cert.not_valid_after < now:
            return False, "Chứng chỉ đã hết hạn."

        # 2. Kiểm tra CRL
        serial_to_check = hex(cert.serial_number)[2:].lower() # chuyển sang hex string, bỏ '0x'
        response = requests.get(CRL_API_URL)
        if response.status_code == 200:
            crl_data = response.json()
            revoked_serials = [s.lower() for s in crl_data.get("revoked_serials", [])]
            if serial_to_check in revoked_serials:
                return False, "Chứng chỉ đã bị thu hồi (nằm trong CRL)."
        else:
            # Nếu không lấy được CRL, coi như là một lỗi
            return False, f"Không thể lấy được danh sách thu hồi (CRL) từ {CRL_API_URL}."

        return True, "Chứng chỉ còn hiệu lực và không bị thu hồi."
    except Exception as e:
        return False, f"Lỗi khi kiểm tra hiệu lực chứng chỉ: {e}"

def verify_pdf(pdf_path: str) -> (bool, str):
    """
    Hàm tổng hợp, thực hiện toàn bộ quy trình xác minh PDF theo yêu cầu.
    """
    # Trích xuất metadata từ PDF
    metadata = extract_pdf_metadata(pdf_path)
    if not all([metadata.get(k) for k in ['Signature', 'PublicKey', 'Certificate']]):
        return False, "Thất bại: PDF thiếu metadata chữ ký (Chữ ký, Khóa công khai, hoặc Chứng chỉ)."

    cert_pem = metadata['Certificate']
    
    # Xác minh chuỗi tin cậy của chứng chỉ (dùng CA)
    if not verify_certificate_chain(cert_pem):
        return False, "Thất bại: Chứng chỉ không được ký bởi CA tin cậy."

    # Kiểm tra hiệu lực (ngày tháng và CRL) của chứng chỉ
    is_valid, reason = check_cert_validity_and_crl(cert_pem)
    if not is_valid:
        return False, f"Thất bại: {reason}"

    # Kiểm tra tính nhất quán của public key
    try:
        pubkey_from_cert = extract_public_key_from_cert(cert_pem)
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        return False, f"Thất bại: Không thể trích xuất khóa công khai từ chứng chỉ. Lỗi: {e}"
    
    pubkey_from_meta = metadata['PublicKey']
    if pubkey_from_cert.strip() != pubkey_from_meta.strip():
        return False, "Thất bại: Khóa công khai trong chứng chỉ không khớp với khóa công khai trong metadata PDF."

    # Băm nội dung tài liệu
    pdf_hash = extract_pdf_hash_without_signature(pdf_path)

    # Xác minh chữ ký bằng public key từ chứng chỉ đã được tin cậy
    signature_b64 = metadata['Signature']
    signature_valid = verify_signature(pdf_hash, signature_b64, pubkey_from_cert)

    if not signature_valid:
        return False, "Thất bại: Chữ ký không hợp lệ. Nội dung tài liệu có thể đã bị thay đổi."

    signer = metadata.get('SignedBy', 'Không rõ')
    signed_at = metadata.get('SignedAt', 'Không rõ')
    return True, f"Thành công: Tài liệu hợp lệ. Được ký bởi '{signer}' vào lúc {signed_at}."