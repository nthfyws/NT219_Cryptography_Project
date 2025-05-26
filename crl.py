from flask import Blueprint, jsonify
from pymongo import MongoClient
import certifi
import os

crl_bp = Blueprint('crl', __name__)

# Load environment variables
MONGODB_URI = os.getenv("MONGODB_URI")

# MongoDB client
client = MongoClient(MONGODB_URI, tlsCAFile=certifi.where())
db = client["NT219_Cryptography_Project"]

@crl_bp.route('/api/crl', methods=['GET'])
def get_crl():
    crl_data = db.crl.find_one()
    if crl_data:
        return jsonify(crl_data), 200
    return jsonify({"message": "CRL not found"}), 404