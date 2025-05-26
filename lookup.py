from flask import jsonify
from db.mongo_setup import get_cert_by_org
from db.mongo_setup import db

def get_cert_by_orgid(org_id):
    cert = db.certificates.find_one({"org_id": org}, {'_id': 0})
    if cert:
        return {
            "org_id": cert.get("org_id"),
            "status": cert.get("status", "UNKNOWN"),
            "issued_at": cert.get("issued_at"),
            "cert_data": cert.get("cert_data"),
            "path": cert.get("path")
        }
    return None

def get_all_certs():
    certs = list(db.certificates.find({}, {'_id': 0}))
    return [{
        "org_id": cert.get("org_id"),
        "status": cert.get("status", "UNKNOWN"),
        "issued_at": cert.get("issued_at"),
        "path": cert.get("path")
    } for cert in certs]