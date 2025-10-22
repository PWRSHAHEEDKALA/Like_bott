import os
import urllib3
import warnings
import time
from functools import wraps
from datetime import datetime, timedelta
import pytz

# Suppress all warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")
os.environ['PYTHONWARNINGS'] = 'ignore'

import base64
import asyncio
import binascii
import json
import requests
import aiohttp
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
from google.protobuf.message import DecodeError
import random
import threading

app = Flask(__name__)

# === SIMPLE COUNTER SYSTEM (Local files) ===
def get_counter(server_name):
    """Get counter from local file"""
    file_map = {
        "IND": "ind_remain.json", 
        "BR": "br_remain.json", 
        "SG": "sg_remain.json",
        "BD": "bd_remain.json",
        "ME": "me_remain.json",
        "NA": "na_remain.json"
    }
    file_path = file_map.get(server_name, "bd_remain.json")
    
    try:
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                data = json.load(f)
                counter_value = int(data.get("counter", 0))
                app.logger.info(f"Loaded counter for {server_name}: {counter_value}")
                return counter_value
        else:
            # Create file with default value
            with open(file_path, 'w') as f:
                json.dump({"counter": 0}, f)
            app.logger.info(f"Created new counter file for {server_name}")
            return 0
    except Exception as e:
        app.logger.error(f"Error reading counter for {server_name}: {e}")
        return 0

def update_counter(server_name, new_value):
    """Update counter in local file"""
    file_map = {
        "IND": "ind_remain.json", 
        "BR": "br_remain.json", 
        "SG": "sg_remain.json",
        "BD": "bd_remain.json", 
        "ME": "me_remain.json",
        "NA": "na_remain.json"
    }
    file_path = file_map.get(server_name, "bd_remain.json")
    
    try:
        with open(file_path, 'w') as f:
            json.dump({"counter": new_value}, f, indent=2)
        app.logger.info(f"Updated counter for {server_name} to {new_value}")
        return True
    except Exception as e:
        app.logger.error(f"Error updating counter for {server_name}: {e}")
        return False

def reset_all_counters():
    """Reset all counters to 0"""
    try:
        servers = ["IND", "BR", "SG", "BD", "ME", "NA"]
        for server in servers:
            update_counter(server, 0)
        app.logger.info("Reset all counters to 0")
        return True
    except Exception as e:
        app.logger.error(f"Error resetting counters: {e}")
        return False

# === DAILY RESET SCHEDULER ===
def reset_scheduler():
    """Reset counters daily at 4:30 AM India time"""
    india_tz = pytz.timezone('Asia/Kolkata')
    
    while True:
        try:
            now = datetime.now(india_tz)
            
            # Set target time to 4:30 AM
            target_time = now.replace(hour=4, minute=30, second=0, microsecond=0)
            
            # If it's already past 4:30 AM, schedule for next day
            if now > target_time:
                target_time += timedelta(days=1)
            
            # Calculate sleep time
            sleep_seconds = (target_time - now).total_seconds()
            
            app.logger.info(f"Next counter reset scheduled at: {target_time} (in {sleep_seconds/3600:.2f} hours)")
            
            # Sleep until 4:30 AM
            time.sleep(sleep_seconds)
            
            # Reset all counters
            app.logger.info("🕧 4:30 AM - Resetting all counters to 0")
            reset_all_counters()
            
            # Sleep for a minute to avoid multiple resets
            time.sleep(60)
            
        except Exception as e:
            app.logger.error(f"Error in reset scheduler: {e}")
            time.sleep(300)  # Wait 5 minutes before retrying

# Start the reset scheduler in a background thread
reset_thread = threading.Thread(target=reset_scheduler, daemon=True)
reset_thread.start()

# === LOCAL TOKEN FILES ===
TOKEN_FILES = {
    "IND": "token_ind.json",
    "BD": "token_bd.json", 
    "ME": "token_bd.json",
    "EU": "token_bd.json", 
    "SG": "token_bd.json",
    "NA": "token_bd.json",
    "BR": "token_br.json",
    "cis": "token_br.json",
    "VN": "token_vn.json"
}

# === Request Throttler for FreeFire API ===
class RequestThrottler:
    def __init__(self, max_concurrent=50, delay_between_batches=0.1):
        self.max_concurrent = max_concurrent
        self.delay_between_batches = delay_between_batches
        self.semaphore = asyncio.Semaphore(max_concurrent)
    
    async def throttle_request(self, coro):
        async with self.semaphore:
            return await coro

# Initialize request throttler
request_throttler = RequestThrottler(max_concurrent=50, delay_between_batches=0.1)

# === LOCAL TOKEN CACHE ===
class TokenCache:
    def __init__(self):
        self.cache = {}
        self.cache_time = {}
        self.cache_duration = 3600  # 1 hour cache
        
    def get_tokens(self, server_name):
        current_time = time.time()
        if (server_name in self.cache and 
            current_time - self.cache_time.get(server_name, 0) < self.cache_duration):
            return self.cache[server_name]
        
        # Load from LOCAL file
        tokens = load_tokens_from_file(server_name)
        if tokens:
            self.cache[server_name] = tokens
            self.cache_time[server_name] = current_time
        return tokens

# Initialize token cache
token_cache = TokenCache()

# === LOCAL TOKEN LOADING ===
def load_tokens_from_file(server_name):
    """Load tokens directly from local JSON files"""
    try:
        file_path = TOKEN_FILES.get(server_name, "token_bd.json")
        
        if not os.path.exists(file_path):
            app.logger.error(f"Token file not found: {file_path}")
            return None
            
        with open(file_path, 'r') as f:
            tokens_dict = json.load(f)
        
        # Convert dictionary values to a list (sorted by key)
        sorted_keys = sorted(tokens_dict.keys(), key=lambda k: int(k))
        token_list = [tokens_dict[k] for k in sorted_keys]
        
        app.logger.info(f"Loaded {len(token_list)} tokens for {server_name} from {file_path}")
        return token_list
        
    except Exception as e:
        app.logger.error(f"Error loading tokens for server {server_name}: {e}")
        return None

def get_token_range_for_server(server_name):
    """Get token range based on counter - USING LOCAL FILES"""
    try:
        counter = get_counter(server_name)
        app.logger.info(f"Current counter for {server_name}: {counter}")
        
        # Calculate which bucket we're in (each bucket = 30 uses)
        bucket = counter // 30
        start = bucket * 100
        end = start + 100
        
        # Use cached tokens (loaded from local files)
        tokens_all = token_cache.get_tokens(server_name)
        if not tokens_all:
            app.logger.error(f"No tokens found for server {server_name}")
            return []
        
        app.logger.info(f"Token range for {server_name}: start={start}, end={end}, total_tokens={len(tokens_all)}")
        
        # If we've exceeded available tokens, reset counter
        if start >= len(tokens_all):
            app.logger.warning(f"Start index {start} exceeds token list length {len(tokens_all)}, resetting counter")
            update_counter(server_name, 0)
            return tokens_all[0:100]
        
        # Adjust end if it exceeds available tokens
        if end > len(tokens_all):
            end = len(tokens_all)
        
        token_range = tokens_all[start:end]
        app.logger.info(f"Selected {len(token_range)} tokens for {server_name} (bucket {bucket})")
        return token_range
    except Exception as e:
        app.logger.error(f"Error getting token range for {server_name}: {e}")
        return []

# === ORIGINAL ENCRYPTION/PROTOBUF FUNCTIONS ===
def encrypt_message(plaintext):
    try:
        key_bytes = b'Yg&tc%DEuh6%Zc^8'
        iv_bytes = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting message: {e}")
        return None

def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating protobuf message: {e}")
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating uid protobuf: {e}")
        return None

def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    return encrypt_message(protobuf_data)

async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 12; SM-G988B Build/SP1A.210812.016)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2021.3.18f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                if response.status != 200:
                    app.logger.error(f"Request failed with status: {response.status} for token: {token[:10]}...")
                    return response.status
                return await response.text()
    except Exception as e:
        app.logger.error(f"Exception in send_request: {e}")
        return None

async def send_multiple_requests(uid, server_name, url):
    try:
        region = server_name
        protobuf_message = create_protobuf_message(uid, region)
        if protobuf_message is None:
            app.logger.error("Failed to create protobuf message.")
            return None
        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None:
            app.logger.error("Encryption failed.")
            return None
        
        # Get token range based on current counter - LOCAL FILES
        tokens = get_token_range_for_server(server_name)
        if tokens is None or len(tokens) == 0:
            app.logger.error("Failed to load tokens from the specified range.")
            return None
        
        app.logger.info(f"Sending {len(tokens)} requests for {server_name}")
        
        tasks = []
        # Send ALL requests using ALL tokens (up to 100)
        for i in range(len(tokens)):
            token = tokens[i]
            task = request_throttler.throttle_request(send_request(encrypted_uid, token, url))
            tasks.append(task)
            
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Count successful requests (status 200)
        successful_requests = sum(1 for result in results if result == 200)
        app.logger.info(f"Request completion: {successful_requests}/{len(tokens)} successful")
        
        return successful_requests
    except Exception as e:
        app.logger.error(f"Exception in send_multiple_requests: {e}")
        return None

def make_request(encrypt_val, server_name, token):
    try:
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
        edata = bytes.fromhex(encrypt_val)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 12; SM-G988B Build/SP1A.210812.016)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2021.3.18f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }
        response = requests.post(url, data=edata, headers=headers, verify=False)
        hex_data = response.content.hex()
        binary = bytes.fromhex(hex_data)
        decode = decode_protobuf(binary)
        if decode is None:
            app.logger.error("Protobuf decoding returned None.")
        return decode
    except Exception as e:
        app.logger.error(f"Error in make_request: {e}")
        return None

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except DecodeError as e:
        app.logger.error(f"Error decoding Protobuf data: {e}")
        return None
    except Exception as e:
        app.logger.error(f"Unexpected error during protobuf decoding: {e}")
        return None

# === Main /like Endpoint ===
@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    if not uid or not server_name:
        return jsonify({"error": "UID and server_name are required"}), 400

    try:
        def process_request():
            app.logger.info(f"Starting request processing for UID: {uid}, Server: {server_name}")
            
            # Get current counter BEFORE processing - LOCAL FILE
            current_counter = get_counter(server_name)
            app.logger.info(f"Current counter for {server_name}: {current_counter}")
            
            tokens_all = token_cache.get_tokens(server_name)
            if tokens_all is None:
                raise Exception("Failed to load tokens.")
            
            token = tokens_all[0]
            encrypted_uid = enc(uid)
            if encrypted_uid is None:
                raise Exception("Encryption of UID failed.")

            # Retrieve initial player info
            before = make_request(encrypted_uid, server_name, token)
            if before is None:
                raise Exception("Failed to retrieve initial player info.")
            try:
                jsone = MessageToJson(before)
                data_before = json.loads(jsone)
            except Exception as e:
                raise Exception(f"Error converting 'before' protobuf to JSON: {e}")
            before_like = data_before.get('AccountInfo', {}).get('Likes', 0)
            try:
                before_like = int(before_like)
            except Exception:
                before_like = 0
            app.logger.info(f"Likes before command: {before_like}")

            if server_name == "IND":
                url = "https://client.ind.freefiremobile.com/LikeProfile"
            elif server_name in {"BR", "US", "SAC", "NA"}:
                url = "https://client.us.freefiremobile.com/LikeProfile"
            else:
                url = "https://clientbp.ggblueshark.com/LikeProfile"

            # Perform like requests asynchronously using ALL 100 tokens
            successful_requests = asyncio.run(send_multiple_requests(uid, server_name, url))

            after = make_request(encrypted_uid, server_name, token)
            if after is None:
                raise Exception("Failed to retrieve player info after like requests.")
            try:
                jsone_after = MessageToJson(after)
                data_after = json.loads(jsone_after)
            except Exception as e:
                raise Exception(f"Error converting 'after' protobuf to JSON: {e}")
            after_like = int(data_after.get('AccountInfo', {}).get('Likes', 0))
            player_uid = int(data_after.get('AccountInfo', {}).get('UID', 0))
            player_name = str(data_after.get('AccountInfo', {}).get('PlayerNickname', ''))
            like_given = after_like - before_like
            status = 1 if like_given != 0 else 2
            
            result = {
                "LikesGivenByAPI": like_given,
                "LikesbeforeCommand": before_like,
                "LikesafterCommand": after_like,
                "PlayerNickname": player_name,
                "UID": player_uid,
                "status": status
            }
            app.logger.info(f"Request processed successfully for UID: {uid}. Result: {result}")
            
            # Update counter based on successful requests - LOCAL FILE
            if successful_requests and successful_requests > 0:
                new_counter = current_counter + successful_requests
                app.logger.info(f"Updating counter for {server_name} from {current_counter} to {new_counter} ({successful_requests} successful requests)")
                if update_counter(server_name, new_counter):
                    app.logger.info(f"Successfully updated counter for {server_name} to {new_counter}")
                else:
                    app.logger.error(f"Failed to update counter for {server_name}")
            else:
                app.logger.info(f"No successful requests, counter remains at {current_counter}")
                
            return result

        result = process_request()
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Error processing request: {e}")
        return jsonify({"error": str(e)}), 500

# === Manual Reset Endpoint ===
@app.route('/reset-counters', methods=['POST'])
def reset_counters():
    """Manual endpoint to reset all counters"""
    try:
        if reset_all_counters():
            return jsonify({"message": "All counters reset successfully!"})
        else:
            return jsonify({"error": "Failed to reset counters"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/')
def home():
    return jsonify({"message": "Like Bot API is running with LOCAL FILES & Auto Reset!", "status": "active"})

if __name__ == '__main__':
    app.logger.info("🚀 Server started with LOCAL FILES & Daily 4:30 AM Reset!")
    app.run(debug=True, host='0.0.0.0', port=5001)
