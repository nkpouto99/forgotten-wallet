from flask import Flask, Response, redirect, url_for, render_template
import threading
import time
from app import app
from main import process_wallets
from dotenv import load_dotenv
import os
from pymongo import MongoClient
load_dotenv()

uri = os.getenv("MONGO_URI")
client = MongoClient(uri)
db = client['wallet_db']
stats_collection = db['scanner_stats']

stats = stats_collection.find_one({"name": "wallet_check_count"})
wallet_check_count = stats["value"] if stats else 0
scanning_active = True

@app.route('/')
def index():
    return redirect(url_for("home"))

@app.route("/cc")
def cc():
    status = "Scanning Active ✅" if scanning_active else "Scanning Stopped ⏸️"
    return f"✅ {status} | Total Wallets Checked: {wallet_check_count}"

@app.route("/home")
def home():
    status = "Scanning Active ✅" if scanning_active else "Scanning Stopped ⏸️"
    response = Response(render_template("index.html", scan_status=status))
    return response

@app.route('/start_scan', methods=['POST'])
def start_scan():
    """Admin starts the wallet scanning process."""
    global scanning_active
    scanning_active = True
    return jsonify({"message": "Scanning started ✅"})

@app.route('/stop_scan', methods=['POST'])
def stop_scan():
    """Admin stops the wallet scanning process."""
    global scanning_active
    scanning_active = False
    return jsonify({"message": "Scanning stopped ⏸️"})

def start_flask():
    """Start Flask & signal it's ready."""
    app.run(host='0.0.0.0', port=10000, threaded=True)
    print("✅ Flask has started!")
    
def run_wallet_script():
    global wallet_check_count
    time.sleep(5)  # ⏳ Give Flask time to start
    print("✅ Flask is running! Starting wallet processing...")

    while True:
        if scanning_active:
            print("🔄 Scanning wallets now...")
            process_wallets()
            process_wallets()
            wallet_check_count += 2

            stats_collection.update_one(
                {"name": "wallet_check_count"},
                {"$set": {"value": wallet_check_count}},
                upsert=True
            )
            
            print(f"✅ Wallets Checked: {wallet_check_count}")
        else:
            print("⏸️ Scanning paused. Waiting for activation...")
        time.sleep(3)
if __name__ == '__main__':
    flask_thread = threading.Thread(target=start_flask, daemon=True)
    flask_thread.start()
    threading.Thread(target=run_wallet_script, daemon=True).start()

