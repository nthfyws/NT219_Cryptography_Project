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
    crl_data = db.crl.find_one()  # Assuming 'crl' is the collection name
    if crl_data:
        return jsonify(crl_data), 200
    return jsonify({"message": "CRL not found"}), 404

@crl_bp.route('/api/verify-crl/<serial_number>', methods=['GET'])
def verify_crl(serial_number):
    crl_data = db.crl.find_one({"serial_number": serial_number})  # Adjust query as needed
    if crl_data:
        return jsonify({"valid": True}), 200
    return jsonify({"valid": False}), 404