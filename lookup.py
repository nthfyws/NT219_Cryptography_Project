from flask import jsonify
from db.mongo_setup import get_cert_by_org
from db.mongo_setup import db

def get_cert_by_orgid(org_id):
    cert = db.certificates.find_one({"org": org_id}, {'_id': 0})
    ca_cert = db.ca.find_one({}, {'_id': 0, 'ca_cert': 1})
    if cert:
        return {
            "org": cert.get("org"),
            "status": cert.get("status", "UNKNOWN"),
            "issued_at": cert.get("issued_at"),
            "cert_data": cert.get("cert"),
            "path": cert.get("path"),
            "ca_cert": cert.get("ca_cert") or (ca_cert.get("ca_cert") if ca_cert else None),
            "updated_at": cert.get("updated_at"),
        }
    return None

def get_all_certs():
    certs = list(db.certificates.find({}, {'_id': 0}))
    ca_cert = db.ca.find_one({}, {'_id': 0, 'ca_cert': 1})
    ca_cert_value = ca_cert.get("ca_cert") if ca_cert else None
    return [{
        "org": cert.get("org"),
        "status": cert.get("status", "UNKNOWN"),
        "issued_at": cert.get("issued_at"),
        "path": cert.get("path"),
        "ca_cert": cert.get("ca_cert") or ca_cert_value
    } for cert in certs]