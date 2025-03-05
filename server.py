from flask import Flask, Response, redirect, url_for, render_template
import threading
import time
from app import app
from main import process_wallets
from dotenv import load_dotenv
import os
from pymongo import MongoClient
import asyncio
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
    
def run_wallet_script():
    global wallet_check_count
    print("✅ Flask is running! Starting wallet processing...")

    loop = asyncio.new_event_loop()  # ✅ Create an event loop
    asyncio.set_event_loop(loop)  # ✅ Set this as the active event loop

    while True:
        if scanning_active:
            print("🔄 Scanning wallets now...")
            loop.run_until_complete(process_wallets())
            wallet_check_count += 1

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
    print("🚀 Starting Flask server first...")
    flask_thread = threading.Thread(target=app.run, kwargs={"host": "0.0.0.0", "port": 10000, "threaded": True}, daemon=True)
    flask_thread.start()

    print("⏳ Waiting 5 seconds to ensure Flask is ready...")
    time.sleep(5)  # ✅ Ensure Flask starts first
    
    print("🔄 Starting Wallet Scanning...")
    run_wallet_script()

