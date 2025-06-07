import subprocess
from datetime import datetime
from PyPDF2 import PdfReader, PdfWriter
import qrcode
from io import BytesIO
import base64
import os
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import ImageReader
import hashlib


def extract_private_key(pfx_path, passphrase):
    # Trích private key ra chuỗi PEM, không lưu file để đảm bảo an toàn
    cmd = [
        'openssl', 'pkcs12',
        '-in', pfx_path,
        '-nocerts',
        '-nodes',
        '-passin', f'pass:{passphrase}'
    ]
    result = subprocess.run(cmd, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(f"Failed to extract private key: {result.stderr.decode()}")
    return result.stdout  # private key PEM bytes

def extract_cert(pfx_path, passphrase):
    # Trích cert tự ký ra chuỗi PEM, không lưu file
    cmd = [
        'openssl', 'pkcs12',
        '-in', pfx_path,
        '-clcerts',
        '-nokeys',
        '-passin', f'pass:{passphrase}'
    ]
    result = subprocess.run(cmd, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(f"Failed to extract cert: {result.stderr.decode()}")
    return result.stdout  # cert PEM bytes

def extract_public_key(cert_pem_bytes):
    # Dùng openssl để lấy public key từ cert PEM bytes (truyền qua stdin)
    cmd = ['openssl', 'x509', '-pubkey', '-noout']
    result = subprocess.run(cmd, input=cert_pem_bytes, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(f"Failed to extract public key: {result.stderr.decode()}")
    return result.stdout.decode()

def hash_pdf_content(pdf_path):
    """
    Tạo hash từ nội dung text và hình ảnh của file PDF.
    Cách này ổn định hơn việc hash toàn bộ file.
    """
    reader = PdfReader(pdf_path)
    hasher = hashlib.sha256()
    
    for page in reader.pages:
        # Hash nội dung text của trang
        hasher.update(page.extract_text().encode('utf-8'))

            
    return hasher.digest()

def sign_pdf(pdf_path, private_key_pem_bytes):
    import hashlib, subprocess, os
    digest = hash_pdf_content(pdf_path)

    # # 1. Đọc nội dung PDF
    # with open(pdf_path, 'rb') as f:
    #     pdf_data = f.read()

    # # 2. Băm SHA256
    # digest = hashlib.sha256(pdf_data).digest()

    # 3. Ghi hash ra file tạm
    hash_file = 'temp_hash.bin'
    with open(hash_file, 'wb') as f:
        f.write(digest)

    # 4. Ghi private key ra file tạm
    key_file = 'temp_key.pem'
    with open(key_file, 'wb') as f:
        f.write(private_key_pem_bytes)

    sig_file = 'temp_sig.bin'

    # 5. Dùng OpenSSL để ký hash
    cmd = [
        'openssl', 'pkeyutl', '-sign',
        '-inkey', key_file,
        '-provider', 'oqsprovider', '-provider', 'default',
        '-in', hash_file,
        '-out', sig_file
    ]

    result = subprocess.run(cmd, capture_output=True)

    # 6. Dọn dẹp
    os.remove(key_file)
    os.remove(hash_file)

    if result.returncode != 0:
        raise RuntimeError(f"OpenSSL sign error: {result.stderr.decode()}")

    with open(sig_file, 'rb') as f:
        signature = f.read()
    os.remove(sig_file)

    return signature

def draw_qr_on_pdf(original_pdf_path, qr_img, output_path):
    # Tạo một PDF chứa QR code
    qr_pdf_path = "temp_qr_overlay.pdf"
    c = canvas.Canvas(qr_pdf_path, pagesize=letter)
    img_reader = ImageReader(qr_img)
    c.drawImage(img_reader, 450, 50, width=100, height=100)  # vị trí (x=450, y=50)
    c.save()

    # Overlay QR PDF lên PDF gốc
    reader = PdfReader(original_pdf_path)
    overlay = PdfReader(qr_pdf_path)
    writer = PdfWriter()

    for i, page in enumerate(reader.pages):
        if i == 0:
            page.merge_page(overlay.pages[0])
        writer.add_page(page)

    with open(output_path, 'wb') as f_out:
        writer.write(f_out)

    os.remove(qr_pdf_path)

def embed_qrcode_and_metadata(pdf_path, qr_data, output_pdf_path, signer_name, signature_b64, public_key_pem, certificate_pem):
    # QR tạo từ qrcode lib
    qr = qrcode.QRCode(box_size=3, border=1)
    qr.add_data(qr_data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    # Lưu QR vào buffer để dùng
    qr_buffer = BytesIO()
    img.save(qr_buffer, format='PNG')
    qr_buffer.seek(0)

    # Vẽ QR lên trang PDF
    draw_qr_on_pdf(pdf_path, qr_buffer, output_pdf_path)

    # Thêm metadata
    reader = PdfReader(output_pdf_path)
    writer = PdfWriter()

    for page in reader.pages:
        writer.add_page(page)

    metadata = dict(reader.metadata or {})
    metadata['/SignedBy'] = signer_name
    metadata['/SignedAt'] = datetime.utcnow().isoformat() + "Z"
    metadata['/SignatureAlgorithm'] = 'mldsa65'
    metadata['/Signature'] = signature_b64
    metadata['/PublicKey'] = public_key_pem.strip()
    metadata['/Certificate'] = certificate_pem.strip() 

    writer.add_metadata(metadata)

    with open(output_pdf_path, "wb") as f_out:
        writer.write(f_out)

