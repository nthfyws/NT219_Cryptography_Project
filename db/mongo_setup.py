import os
import certifi
import pymongo
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI")

client = pymongo.MongoClient(MONGODB_URI, tlsCAFile=certifi.where())
db = client["NT219_Cryptography_Project"]
certs = db["certificates"]
ca_info = db["ca_info"]

def insert_cert(org, path, base64_cert):
    """Lưu chứng chỉ vào database"""
    certs.replace_one(
        {"org": org},
        {
            "org": org,
            "path": path,
            "cert": base64_cert,
            "status": "ACTIVE",
            "issued_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        },
        upsert=True
    )

def get_cert_by_org(org):
    """Lấy chứng chỉ theo tổ chức"""
    return certs.find_one({"org": org}, {"_id": 0})

def get_all_certs():
    """Lấy tất cả chứng chỉ"""
    return list(certs.find({}, {"_id": 0}))

def get_ca_info():
    """Lấy thông tin CA"""
    return ca_info.find_one({}, {"_id": 0})