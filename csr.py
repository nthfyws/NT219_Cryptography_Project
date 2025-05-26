import os
import subprocess
from flask import request, jsonify
from base64 import b64encode

def generate_csr(data):
    org = data.get("org_info")
    passphrase = data.get("passphrase")

    pfx_path = f"storage/pfx/{org}.pfx"
    key_path = f"/tmp/{org}.key"
    crt_path = f"/tmp/{org}.crt"
    csr_path = f"storage/csr/{org}.csr"

    os.makedirs("storage/csr", exist_ok=True)

    try:
        # Giải mã file PFX để lấy private key (sử dụng oqsprovider)
        subprocess.run([
            "openssl", "pkcs12", "-in", pfx_path, "-nocerts", "-nodes",
            "-out", key_path, "-passin", f"pass:{passphrase}",
            "-provider", "oqsprovider", "-provider", "default"
        ], check=True)

        # Tạo CSR từ private key (sử dụng oqsprovider)
        subprocess.run([
            "openssl", "req", "-new", "-key", key_path, "-out", csr_path,
            "-subj", f"/CN={org}",
            "-provider", "oqsprovider", "-provider", "default"
        ], check=True)

        # Đọc nội dung CSR và mã hóa base64
        with open(csr_path, "rb") as f:
            csr_content = f.read()
        csr_base64 = b64encode(csr_content).decode()

        # Xóa file tạm
        os.remove(key_path)

        return jsonify({
            "message": "CSR created with oqsprovider",
            "csr_file": csr_path,
            "csr_base64": csr_base64
        })

    except subprocess.CalledProcessError as e:
        return jsonify({
            "error": "CSR generation failed",
            "details": str(e)
        }), 500