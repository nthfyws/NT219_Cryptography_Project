import os
import subprocess
from flask import request, jsonify

def generate_dilithium_keypair(data):
    org = data.get("org_info")
    passphrase = data.get("passphrase")

    base = f"storage/pfx/{org}"
    key_path = f"{base}.key"
    crt_path = f"{base}.crt"
    pfx_path = f"{base}.pfx"

    os.makedirs("storage/pfx", exist_ok=True)

    try:
        # Tạo private key với oqsprovider
        subprocess.run([
            "openssl", "genpkey",
            "-provider", "oqsprovider",
            "-provider", "default",
            "-algorithm", "mldsa65",
            "-out", key_path
        ], check=True)

        # Tạo CSR và self-signed cert
        subprocess.run([
            "openssl", "req", "-new", "-x509",
            "-provider", "oqsprovider",
            "-provider", "default",
            "-key", key_path,
            "-out", crt_path,
            "-subj", f"/CN={org}"
        ], check=True)

        # Xuất file PKCS#12 (PFX)
        subprocess.run([
            "openssl", "pkcs12", "-export",
            "-provider", "oqsprovider",
            "-provider", "default",
            "-out", pfx_path,
            "-inkey", key_path,
            "-in", crt_path,
            "-passout", f"pass:{passphrase}"
        ], check=True)

        # Xóa file tạm
        os.remove(key_path)
        os.remove(crt_path)

        return jsonify({
            "message": "Dilithium keypair created with oqsprovider",
            "pfx_file": pfx_path
        })

    except subprocess.CalledProcessError as e:
        return jsonify({
            "error": "Key generation failed",
            "details": str(e)
        }), 500