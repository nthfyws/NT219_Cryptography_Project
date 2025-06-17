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
import shutil

def extract_private_key(pfx_path, passphrase):
    cmd = [
        'openssl', 'pkcs12',
        '-in', pfx_path,
        '-nocerts',
        '-nodes',
        '-passin', f'pass:{passphrase}',
        '-provider', 'oqsprovider',
        '-provider', 'default'
    ]
    result = subprocess.run(cmd, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(f"Failed to extract private key: {result.stderr.decode()}")
    return result.stdout


def extract_cert(pfx_path, passphrase):
    cmd = [
        'openssl', 'pkcs12',
        '-in', pfx_path,
        '-clcerts',
        '-nokeys',
        '-passin', f'pass:{passphrase}',
        '-provider', 'oqsprovider',
        '-provider', 'default'
    ]
    result = subprocess.run(cmd, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(f"Failed to extract cert: {result.stderr.decode()}")
    return result.stdout


def extract_public_key(cert_pem_bytes):
    cmd = ['openssl', 'x509', '-pubkey', '-noout']
    result = subprocess.run(cmd, input=cert_pem_bytes, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(f"Failed to extract public key: {result.stderr.decode()}")
    return result.stdout.decode()


def sign_pdf(pdf_path, private_key_pem_bytes):
    # Ghi private key ra file tạm
    key_file = 'temp_key.pem'
    with open(key_file, 'wb') as f:
        f.write(private_key_pem_bytes)

    sig_file = 'temp_sig.bin'

    # Ký toàn bộ file, để Dilithium tự hash
    cmd = [
        'openssl', 'pkeyutl', '-sign',
        '-inkey', key_file,
        '-provider', 'oqsprovider', '-provider', 'default',
        '-out', sig_file,
        '-in', pdf_path,
        '-rawin'
    ]
    result = subprocess.run(cmd, capture_output=True)

    os.remove(key_file)

    if result.returncode != 0:
        raise RuntimeError(f"OpenSSL sign error: {result.stderr.decode()}")

    with open(sig_file, 'rb') as f:
        signature = f.read()
    os.remove(sig_file)

    return signature


def draw_qr_on_pdf(original_pdf_path, qr_img, output_path):
    img_buffer = BytesIO()
    qr_img.save(img_buffer, format='PNG')
    img_buffer.seek(0)

    qr_pdf_path = "temp_qr_overlay.pdf"
    c = canvas.Canvas(qr_pdf_path, pagesize=letter)
    img_reader = ImageReader(img_buffer)
    c.drawImage(img_reader, 450, 50, width=100, height=100)
    c.save()

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


def embed_qrcode_with_signature_data(
    pdf_path,
    signer_name,
    signer_position,
    private_key_pem,
    public_key_pem,
    certificate_pem,
    output_pdf_path,
    file_id=None
):
    import json, urllib.parse
    import uuid

    # Tạo signature_id duy nhất
    signature_id = str(uuid.uuid4())

    # B1. Tạo QR code từ URL xác minh
    verify_url = f"http://192.168.1.33:5001/verify?id={signature_id}"
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=4,
        border=2
    )
    qr.add_data(verify_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    # B2. Nhúng QR vào PDF → output là file có QR
    pdf_with_qr_path = "temp_with_qr.pdf"
    draw_qr_on_pdf(pdf_path, img, pdf_with_qr_path)

    # B3. Ký file đã có QR
    signature_bin = sign_pdf(pdf_with_qr_path, private_key_pem)
    signature_b64 = base64.b64encode(signature_bin).decode()

    # B4. Ghi PDF đã có QR ra output
    shutil.move(pdf_with_qr_path, output_pdf_path)

    # B5. Trả về metadata cho trang xác minh
    full_signature_data = {
        "signature_id": signature_id,
        "signer": signer_name,
        "position": signer_position,
        "signed_at": datetime.utcnow().isoformat() + "Z",
        "algorithm": "mldsa65",
        "signature": signature_b64,
        "public_key": public_key_pem.strip(),
        "certificate": certificate_pem.strip(),
        "file_id": file_id
    }

    return signature_id, full_signature_data
