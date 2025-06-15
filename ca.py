import os
import subprocess
from flask import request, jsonify
from base64 import b64encode
from db.mongo_setup import insert_cert, db
import logging
from getpass import getpass
from datetime import datetime
import tempfile

# Cấu hình logging
logging.basicConfig(filename='ca_operations.log', level=logging.INFO)

CA_KEY = "storage/ca/ca.key"
CA_CERT = "storage/ca/ca.crt"

def log_operation(operation, org=None, success=True, details=None):
    log_entry = {
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "operation": operation,
        "organization": org,
        "status": "SUCCESS" if success else "FAILED"
    }
    if details:
        log_entry["details"] = str(details)
    
    db.audit_logs.insert_one(log_entry)

def create_ca_cert(passphrase):
    """Create a self-signed CA certificate with a passphrase."""
    if not passphrase or len(passphrase) < 12:
        return jsonify({"error": "Passphrase must be at least 12 characters"}), 400

    try:
        os.makedirs("storage/ca", mode=0o700, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode='w+', delete=True) as pf:
            pf.write(passphrase)
            pf.flush()
            # 1. Tạo key CA với passphrase bảo vệ
            subprocess.run([
                "openssl", "genpkey",
                "-algorithm", "mldsa65",
                "-out", CA_KEY,
                "-aes-256-cbc",
                "-pass", f"file:{pf.name}"
            ], check=True)

            # 2. Tạo self-signed cert
            subprocess.run([
                "openssl", "req",
                "-x509",
                "-new",
                "-key", CA_KEY,
                "-out", CA_CERT,
                "-subj", "/CN=CA Root",
                "-passin", f"file:{pf.name}"
            ], check=True)

            os.chmod(CA_KEY, 0o600)
            os.chmod(CA_CERT, 0o644)

            # 3. Trích xuất public key
            ca_pubkey_path = "storage/ca/ca_pubkey.pem"
            subprocess.run([
                "openssl", "pkey",
                "-in", CA_KEY,
                "-pubout",
                "-out", ca_pubkey_path,
                "-passin", f"file:{pf.name}"
            ], check=True)

        # Đọc nội dung cert và pubkey
        with open(CA_CERT, "r") as f:
            ca_cert = f.read()
        with open(ca_pubkey_path, "r") as f:
            ca_pubkey = f.read()

        # Lưu vào DB nếu chưa có (KHÔNG lưu private key)
        ca_info_col = db["ca"]
        if not ca_info_col.find_one({"subject": "/CN=RootCA"}):
            ca_info_col.insert_one({
                "subject": "/CN=CA Root",
                "ca_cert": ca_cert,
                "ca_pubkey": ca_pubkey,
                "status": "ACTIVE"
            })
            
        log_operation("CA Initialization", success=True)
        return jsonify({"message": "CA certificate created", "ca_cert": CA_CERT})

    except subprocess.CalledProcessError as e:
        log_operation("CA Initialization", success=False, details=str(e))
        return jsonify({"error": "CA creation failed", "details": str(e)}), 500

def sign_csr(org, passphrase):
    if not org or not passphrase:
        return jsonify({"error": "Missing required parameters"}), 400

    csr_path = f"storage/csr/{org}.csr"
    cert_path = f"storage/certs/{org}.crt"

    try:
        os.makedirs("storage/certs", mode=0o755, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode='w+', delete=True) as pf:
            pf.write(passphrase)
            pf.flush()
            subprocess.run([
                "openssl", "x509", "-req", "-in", csr_path,
                "-CA", CA_CERT,
                "-CAkey", CA_KEY,
                "-CAcreateserial",
                "-out", cert_path,
                "-days", "365",
                "-passin", f"file:{pf.name}"
            ], check=True)
        os.chmod(cert_path, 0o644)

        with open(cert_path, "rb") as f:
            cert_data = b64encode(f.read()).decode()
            
        user = db.users.find_one({"username": org})
        display_name = user.get("display_name", org) if user else org
        position = user.get("position", "") if user else ""

        cert_doc = {
            "org": org,
            "org_name": display_name,
            "position": position,
            "cert": cert_data,
            "status": "ACTIVE",
            "path": cert_path,
            "issued_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }
        db.certificates.insert_one(cert_doc)
        log_operation("Sign CSR", org=org, success=True)
        return cert_data  # Trả về base64 string để render template
    except subprocess.CalledProcessError as e:
        log_operation("Sign CSR", org=org, success=False, details=str(e))
        raise Exception(f"Certificate signing failed: {str(e)}")

def revoke_cert(org, passphrase, reason):
    if not org or not passphrase:
        raise Exception("Missing required parameters")

    cert_path = f"storage/certs/{org}.crt"
    crl_path = "storage/ca/crl.pem"
    openssl_cnf = "storage/ca/openssl.cnf"

    try:
        with tempfile.NamedTemporaryFile(mode='w+', delete=True) as pf:
            pf.write(passphrase)
            pf.flush()
            subprocess.run([
                "openssl", "ca",
                "-config", openssl_cnf,
                "-revoke", cert_path,
                "-keyfile", CA_KEY,
                "-cert", CA_CERT,
                "-passin", f"file:{pf.name}",
                "-crl_reason", reason
            ], check=True)

            # Sinh lại file CRL
            subprocess.run([
                "openssl", "ca",
                "-config", openssl_cnf,
                "-gencrl",
                "-keyfile", CA_KEY,
                "-cert", CA_CERT,
                "-out", crl_path,
                "-passin", f"file:{pf.name}"
            ], check=True)

        # Update status in certificates collection
        db.certificates.update_one(
            {"org_id": org},
            {"$set": {"status": "REVOKED"}}
        )

        log_operation("Revoke Certificate", org=org, success=True)
        return crl_path
    except subprocess.CalledProcessError as e:
        log_operation("Revoke Certificate", org=org, success=False, details=str(e))
        raise Exception(f"Certificate revocation failed: {str(e)}")

def get_ca_cert():
    """Retrieve the CA certificate information"""
    try:
        # Read CA certificate file
        with open(CA_CERT, "r") as f:
            ca_cert = f.read()
        
        # Get CA info from database
        ca_info = db.ca.find_one({"subject": "/CN=RootCA"})
        if not ca_info:
            return jsonify({"error": "CA information not found"}), 404
            
        return jsonify({
            "ca_cert": ca_cert,
            "ca_pubkey": ca_info.get("ca_pubkey"),
            "status": ca_info.get("status", "ACTIVE")
        })
        
    except FileNotFoundError:
        logging.error("CA certificate file not found")
        return jsonify({"error": "CA certificate not found"}), 404
    except Exception as e:
        logging.error(f"Error retrieving CA certificate: {str(e)}")
        return jsonify({"error": "Failed to retrieve CA certificate", "details": str(e)}), 500