from flask import Flask, Response, render_template, request, redirect, url_for, session
import pymongo
from flask_bcrypt import Bcrypt
from datetime import timedelta
from bson.objectid import ObjectId
from dotenv import load_dotenv
import os
import logging
import traceback

# Load environment variables
load_dotenv()


app = Flask(__name__, template_folder="templates")
app.secret_key =os.getenv("SECRET_KEY")
app.permanent_session_lifetime = timedelta(minutes=30)
scanning_active = True

# 🔹 Connect to MongoDB (Updated to Your Cluster)
MONGO_URI = os.getenv("MONGO_URI")
try:
    client = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)  # 5-second timeout
    db = client["wallet_db"]
    admin_collection = db["admin_users"]
    config_collection = db["config"]
    wallets_collection = db["wallets"]
    stats_collection = db['scanner_stats']
    db.admin_users.find_one()  # Test connection
    print("✅ Connected to MongoDB!")
except pymongo.errors.ServerSelectionTimeoutError:
    print("🚨 MongoDB Connection Failed! Check credentials & internet.")

bcrypt = Bcrypt(app)

# 🔹 Check & Create Admin User (Auto-runs when app starts)
#DEFAULT_USERNAME = "Francis"
#DEFAULT_PASSWORD = "Macrobt1992@"  # Store hashed password

#existing_admin = admin_collection.find_one({"username": DEFAULT_USERNAME})

#if not existing_admin:
  #  hashed_password = bcrypt.generate_password_hash(DEFAULT_PASSWORD).decode('utf-8')
 #   admin_collection.insert_one({"username": DEFAULT_USERNAME, "password": hashed_password})
   # print("✅ Default admin user created successfully!")
#else:
  #  print("✅ Admin user already exists in MongoDB.")

LOG_FILE = "app_errors.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.ERROR,  # Only log errors
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

@app.errorhandler(500)
def internal_error(error):
    """Catch internal errors & log details to a file."""
    error_details = traceback.format_exc()
    
    # 🔹 Print to console & log to file
    print(f"🚨 INTERNAL SERVER ERROR:\n{error_details}")
    logging.error(f"🚨 INTERNAL SERVER ERROR:\n{error_details}")  # Log to file
    
    return "❌ Internal Server Error! Check logs.", 500


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user" in session:  # ✅ If already logged in, go to dashboard
        return redirect(url_for("dashboard"))
        
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # 🔹 Fetch user from MongoDB
        user = admin_collection.find_one({"username": username})

        if user and bcrypt.check_password_hash(user["password"], password):
            session["user"] = username
            return redirect(url_for("dashboard"))

        return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    try:
        wallets = list(wallets_collection.find({
            "coins": {"$elemMatch": {"balance": {"$gt": 0}}}  # Show only wallets with balance > 0
        }).sort("timestamp_iso", -1))
    except Exception as e:
        print(f"🚨 MongoDB Query Error: {e}")
        wallets = []  # Return empty list to avoid crash

    return render_template("dashboard.html", wallets=wallets)

@app.route("/delete_wallet/<wallet_id>", methods=["POST"])
def delete_wallet(wallet_id):
    """Admin deletes a wallet"""
    if "user" not in session:
        return redirect(url_for("login"))

    wallets_collection.delete_one({"_id": ObjectId(wallet_id)})
    return redirect(url_for("dashboard"))

@app.route("/update_api_key", methods=["POST"])
def update_api_key():
    """Admin updates ETH API key"""
    if "user" not in session:
        return redirect(url_for("login"))

    new_api_key = request.form["new_api_key"]
    config_collection.update_one({"name": "eth_api_key"}, {"$set": {"value": new_api_key}}, upsert=True)
    return redirect(url_for("dashboard"))

@app.route("/logs")
def view_logs():
    """View the last 100 lines of the log file (for debugging)."""
    try:
        with open(LOG_FILE, "r") as log_file:
            logs = log_file.readlines()[-100:]  # Show last 100 lines
        return "<br>".join(logs).replace("\n", "<br>")
    except Exception as e:
        return f"❌ Error reading logs: {e}"


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))
