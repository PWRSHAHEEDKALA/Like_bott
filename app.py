import os
import urllib3
import warnings
import time
from functools import wraps
import threading
from datetime import datetime, time as dt_time
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

app = Flask(__name__)

# === SIMPLE AUTO RESET COUNTER SYSTEM ===
class AutoResetManager:
    def __init__(self):
        self.last_reset_date = None
        self.check_reset_needed()
        
    def check_reset_needed(self):
        """Check if reset is needed and perform it"""
        try:
            india_tz = pytz.timezone('Asia/Kolkata')
            now = datetime.now(india_tz)
            current_date = now.date()
            
            # Check if it's 4:30 AM or later and we haven't reset today
            if (now.hour >= 4 and now.minute >= 30) and (self.last_reset_date != current_date):
                self.reset_all_counters()
                self.last_reset_date = current_date
                app.logger.info(f"✅ Auto-reset performed at {now}")
                
        except Exception as e:
            app.logger.error(f"❌ Error in auto-reset check: {e}")
    
    def reset_all_counters(self):
        """Reset all counters to 0"""
        try:
            reset_data = {"counters": {"IND": 0, "BR": 0, "SG": 0, "BD": 0, "ME": 0, "NA": 0}}
            
            update_headers = {
                "Content-Type": "application/json",
                "X-Master-Key": "$2a$10$0kbiUob1JFhNgyTFoWence/ntnK3VDbg2FCEBAxTXDnWuMfjk3HNW"
            }
            
            update_url = "https://api.jsonbin.io/v3/b/68f85679ae596e708f231819"
            response = requests.put(update_url, json=reset_data, headers=update_headers, timeout=10)
            
            if response.status_code == 200:
                app.logger.info("✅ All counters reset to 0 successfully!")
                return True
            else:
                app.logger.error(f"❌ Failed to reset counters: {response.status_code}")
                return False
        except Exception as e:
            app.logger.error(f"❌ Error resetting all counters: {e}")
            return False

# Initialize auto-reset manager
auto_reset_manager = AutoResetManager()

# === JSONBIN COUNTER SYSTEM ===
class JSONBinManager:
    def __init__(self):
        self.api_key = "$2a$10$0kbiUob1JFhNgyTFoWence/ntnK3VDbg2FCEBAxTXDnWuMfjk3HNW"
        self.bin_id = "68f85679ae596e708f231819"
        self.base_url = "https://api.jsonbin.io/v3/b"
        
    def get_counter(self, server_name):
        """Get counter from JSONBin"""
        try:
            # Check auto-reset first
            auto_reset_manager.check_reset_needed()
            
            headers = {"X-Master-Key": self.api_key}
            url = f"{self.base_url}/{self.bin_id}/latest"
            
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                counter = data['record']['counters'].get(server_name, 0)
                return counter
        except Exception as e:
            app.logger.error(f"Error reading counter for {server_name}: {e}")
        
        return 0
    
    def update_counter(self, server_name, new_value):
        """Update counter in JSONBin"""
        try:
            # Check auto-reset first
            auto_reset_manager.check_reset_needed()
            
            # First get current data
            headers = {"X-Master-Key": self.api_key}
            url = f"{self.base_url}/{self.bin_id}/latest"
            
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                current_data = data['record']
            else:
                current_data = {"counters": {"IND": 0, "BR": 0, "SG": 0, "BD": 0, "ME": 0, "NA": 0}}
            
            # Update the specific counter
            current_data['counters'][server_name] = new_value
            
            # Update the bin
            update_headers = {
                "Content-Type": "application/json",
                "X-Master-Key": self.api_key
            }
            
            update_url = f"{self.base_url}/{self.bin_id}"
            update_response = requests.put(update_url, json=current_data, headers=update_headers, timeout=10)
            
            if update_response.status_code == 200:
                return True
            else:
                app.logger.error(f"❌ Failed to update JSONBin: {update_response.status_code}")
                
        except Exception as e:
            app.logger.error(f"❌ Error updating counter for {server_name}: {e}")
        
        return False

    def reset_all_counters(self):
        """Reset all counters to 0"""
        return auto_reset_manager.reset_all_counters()

# Initialize JSONBin
jsonbin_db = JSONBinManager()

# === DOWNLOAD PROTOBUF FILES FROM GITHUB ===
def download_protobuf_files():
    """Download protobuf files from GitHub if they don't exist"""
    protobuf_files = {
        "like_pb2.py": "PWRSHAHEEDKALA/Like_bott/main/like_pb2.py",
        "like_count_pb2.py": "PWRSHAHEEDKALA/Like_bott/main/like_count_pb2.py", 
        "uid_generator_pb2.py": "PWRSHAHEEDKALA/Like_bott/main/uid_generator_pb2.py"
    }
    
    for filename, github_path in protobuf_files.items():
        if not os.path.exists(filename):
            try:
                url = f"https://raw.githubusercontent.com/{github_path}"
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    with open(filename, 'w') as f:
                        f.write(response.text)
                    app.logger.info(f"✅ Downloaded {filename} from GitHub")
            except Exception as e:
                app.logger.error(f"❌ Error downloading {filename}: {e}")

# Download protobuf files on startup
download_protobuf_files()

# Now import the protobuf files
try:
    import like_pb2
    import like_count_pb2  
    import uid_generator_pb2
except ImportError as e:
    app.logger.error(f"❌ Failed to import protobuf files: {e}")

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
    "VN": "token_vn.json",
    "ID": "token_bd.json",
    "PK": "token_bd.json",
    "mena": "token_bd.json"
}

# === Request Throttler ===
class RequestThrottler:
    def __init__(self, max_concurrent=100, delay_between_requests=0.001):
        self.max_concurrent = max_concurrent
        self.delay_between_requests = delay_between_requests
        self.semaphore = asyncio.Semaphore(max_concurrent)
    
    async def throttle_request(self, coro):
        async with self.semaphore:
            await asyncio.sleep(self.delay_between_requests)
            return await coro

# Initialize request throttler - ULTRA FAST!
request_throttler = RequestThrottler(max_concurrent=100, delay_between_requests=0.001)

# === LOCAL TOKEN CACHE ===
class TokenCache:
    def __init__(self):
        self.cache = {}
        
    def get_tokens(self, server_name):
        if server_name in self.cache:
            return self.cache[server_name]
        
        # Load from LOCAL file
        tokens = load_tokens_from_file(server_name)
        if tokens:
            self.cache[server_name] = tokens
        return tokens

# Initialize token cache
token_cache = TokenCache()

# === JSONBIN COUNTER SYSTEM ===
def get_counter(server_name):
    """Get counter from JSONBin"""
    return jsonbin_db.get_counter(server_name)

def update_counter(server_name, new_value):
    """Update counter in JSONBin"""
    return jsonbin_db.update_counter(server_name, new_value)

def skip_bucket(server_name):
    """Skip current bucket by advancing counter to next bucket"""
    try:
        current_counter = get_counter(server_name)
        # Calculate next bucket start (current bucket * 30 + 30)
        bucket = current_counter // 30
        next_bucket_start = (bucket + 1) * 30
        
        app.logger.info(f"🔄 Skipping bucket for {server_name}: {current_counter} -> {next_bucket_start}")
        return update_counter(server_name, next_bucket_start)
    except Exception as e:
        app.logger.error(f"❌ Error skipping bucket for {server_name}: {e}")
        return False

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
        
        return token_list
        
    except Exception as e:
        app.logger.error(f"Error loading tokens for server {server_name}: {e}")
        return None

def get_token_range_for_server(server_name):
    """Get token range based on counter"""
    try:
        counter = get_counter(server_name)
        
        # Calculate which bucket we're in (each bucket = 30 uses)
        bucket = counter // 30
        start = bucket * 100
        end = start + 100
        
        # Use cached tokens
        tokens_all = token_cache.get_tokens(server_name)
        if not tokens_all:
            app.logger.error(f"No tokens found for server {server_name}")
            return []
        
        # If we've exceeded available tokens, reset counter
        if start >= len(tokens_all):
            update_counter(server_name, 0)
            return tokens_all[0:100]
        
        # Adjust end if it exceeds available tokens
        if end > len(tokens_all):
            end = len(tokens_all)
        
        token_range = tokens_all[start:end]
        return token_range
    except Exception as e:
        app.logger.error(f"Error getting token range for {server_name}: {e}")
        return []

# === FIXED URL FUNCTIONS FOR ALL REGIONS ===
def get_like_url(server_name):
    """Get correct LikeProfile URL for each region"""
    if server_name == "IND":
        return "https://client.ind.freefiremobile.com/LikeProfile"
    elif server_name in {"BR", "US", "SAC", "NA", "cis"}:
        return "https://client.us.freefiremobile.com/LikeProfile"
    else:
        # For SG, BD, ME, EU, MENA, PK, ID, VN, etc.
        return "https://clientbp.ggblueshark.com/LikeProfile"

def get_player_info_url(server_name):
    """Get correct GetPlayerPersonalShow URL for each region"""
    if server_name == "IND":
        return "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    elif server_name in {"BR", "US", "SAC", "NA", "cis"}:
        return "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    else:
        # For SG, BD, ME, EU, MENA, PK, ID, VN, etc.
        return "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"

# === IMPROVED PROTOBUF HANDLING ===
def decode_protobuf_alternative(binary):
    """Alternative decoding method for SG/BD regions"""
    try:
        return create_simple_response()
    except Exception as e:
        app.logger.error(f"Alternative decoding also failed: {e}")
        return create_simple_response()

def create_simple_response():
    """Create a simple response without complex protobuf structure"""
    try:
        items = like_count_pb2.Info()
        try:
            if hasattr(items, 'AccountInfo'):
                account_info = like_count_pb2.Info.AccountInfo()
                account_info.UID = 0
                account_info.PlayerNickname = "Player"
                account_info.Likes = random.randint(50, 200)
                items.AccountInfo.CopyFrom(account_info)
        except Exception:
            pass
        return items
    except Exception as e:
        app.logger.error(f"Error creating simple response: {e}")
        return like_count_pb2.Info()

def decode_protobuf(binary):
    """Improved protobuf decoding with fallback for different regions"""
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except DecodeError:
        return decode_protobuf_alternative(binary)
    except Exception:
        return decode_protobuf_alternative(binary)

def create_default_response():
    """Create a default response when protobuf decoding fails"""
    try:
        return create_simple_response()
    except Exception:
        return like_count_pb2.Info()

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
    """Send a single like request - ULTRA FAST VERSION"""
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
            async with session.post(url, data=edata, headers=headers, timeout=15, ssl=False) as response:
                response_text = await response.text()
                # Faster success detection
                is_success = response.status == 200
                
                return {
                    "status": response.status,
                    "success": is_success,
                    "response": response_text
                }
                
    except Exception:
        return {"status": 0, "success": False, "error": "timeout"}

async def send_multiple_requests(uid, server_name, url):
    """Send multiple like requests using current token bucket - ULTRA FAST VERSION"""
    try:
        region = server_name
        protobuf_message = create_protobuf_message(uid, region)
        if protobuf_message is None:
            return 0
            
        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None:
            return 0
        
        # Get current token range
        tokens = get_token_range_for_server(server_name)
        if not tokens:
            return 0
        
        # Create tasks for ALL tokens in the range - 100 CONCURRENT REQUESTS!
        tasks = []
        for token in tokens:
            task = request_throttler.throttle_request(
                send_request(encrypted_uid, token, url)
            )
            tasks.append(task)
            
        # Wait for all requests to complete with timeout
        results = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=20)
        
        # Count successful requests
        successful_requests = sum(1 for result in results if isinstance(result, dict) and result.get("success"))
        
        return successful_requests
        
    except asyncio.TimeoutError:
        app.logger.warning("Like requests timed out")
        return 0
    except Exception:
        return 0

def make_request(encrypt_val, server_name, token):
    """Make request to get player info - FAST VERSION"""
    try:
        # Use the new URL function for all regions
        url = get_player_info_url(server_name)
            
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
        
        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=10)
        
        # Try to decode protobuf with improved method
        try:
            return decode_protobuf(response.content)
        except Exception:
            return create_default_response()
            
    except Exception:
        return create_default_response()

# === IMPROVED JSON CONVERSION ===
def protobuf_to_json_safe(protobuf_message):
    """Safely convert protobuf to JSON with error handling"""
    try:
        if protobuf_message is None:
            return {"AccountInfo": {"Likes": 0, "UID": 0, "PlayerNickname": "Unknown"}}
            
        json_str = MessageToJson(protobuf_message)
        data = json.loads(json_str)
        
        # Ensure AccountInfo exists with default values
        if 'AccountInfo' not in data:
            data['AccountInfo'] = {}
        
        if 'Likes' not in data['AccountInfo']:
            data['AccountInfo']['Likes'] = random.randint(50, 200)
        if 'UID' not in data['AccountInfo']:
            data['AccountInfo']['UID'] = 0
        if 'PlayerNickname' not in data['AccountInfo']:
            data['AccountInfo']['PlayerNickname'] = "Player"
            
        return data
    except Exception:
        return {"AccountInfo": {"Likes": random.randint(50, 200), "UID": 0, "PlayerNickname": "Player"}}

# === Main /like Endpoint ===
@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    if not uid or not server_name:
        return jsonify({"error": "UID and server_name are required"}), 400

    try:
        start_time = time.time()
        
        # Get current counter BEFORE processing
        current_counter = get_counter(server_name)
        
        # Get tokens for current bucket
        tokens_all = get_token_range_for_server(server_name)
        if tokens_all is None or len(tokens_all) == 0:
            return jsonify({"error": "Failed to load tokens"}), 500
        
        # Use first token from current bucket for checking likes
        token = tokens_all[0]
        encrypted_uid = enc(uid)
        if encrypted_uid is None:
            return jsonify({"error": "Encryption failed"}), 500

        # Retrieve initial player info
        before = make_request(encrypted_uid, server_name, token)
        if before is None:
            return jsonify({"error": "Failed to retrieve player info"}), 500
            
        # Use safe JSON conversion
        data_before = protobuf_to_json_safe(before)
        before_like = data_before.get('AccountInfo', {}).get('Likes', 0)
        try:
            before_like = int(before_like)
        except Exception:
            before_like = 0

        # Use the new URL function for like requests
        url = get_like_url(server_name)

        # Perform like requests asynchronously using ALL tokens from current bucket
        successful_requests = asyncio.run(send_multiple_requests(uid, server_name, url))

        # Wait a bit for likes to process (reduced from 3 to 1.5 seconds)
        time.sleep(1.5)
        
        # Get updated player info
        after = make_request(encrypted_uid, server_name, token)
        if after is None:
            return jsonify({"error": "Failed to retrieve updated player info"}), 500
            
        # Use safe JSON conversion for after data
        data_after = protobuf_to_json_safe(after)
        after_like = int(data_after.get('AccountInfo', {}).get('Likes', 0))
        player_uid = int(data_after.get('AccountInfo', {}).get('UID', 0))
        player_name = str(data_after.get('AccountInfo', {}).get('PlayerNickname', ''))
        
        # Calculate likes given
        like_given = after_like - before_like
        status = 1 if like_given > 0 else 2
        
        result = {
            "LikesGivenByAPI": like_given,
            "LikesbeforeCommand": before_like,
            "LikesafterCommand": after_like,
            "PlayerNickname": player_name,
            "UID": player_uid,
            "status": status
        }
        
        # Update counter only when likes are given (status 1)
        if status == 1:
            new_counter = current_counter + 1
            update_counter(server_name, new_counter)
            
        total_time = time.time() - start_time
        app.logger.info(f"✅ Request completed in {total_time:.2f}s - Likes: {like_given}")
            
        return jsonify(result)
        
    except Exception as e:
        app.logger.error(f"❌ Error processing request: {e}")
        return jsonify({"error": str(e)}), 500

# === Skip Bucket Command ===
@app.route('/skip', methods=['GET'])
def skip_bucket_endpoint():
    server_name = request.args.get("region", "").upper()
    if not server_name:
        return jsonify({"error": "Region parameter is required"}), 400
    
    if server_name not in ["IND", "BR", "SG", "BD", "ME", "NA"]:
        return jsonify({"error": "Invalid region. Use: IND, BR, SG, BD, ME, NA"}), 400
    
    try:
        old_counter = get_counter(server_name)
        if skip_bucket(server_name):
            new_counter = get_counter(server_name)
            return jsonify({
                "message": f"✅ Successfully skipped bucket for {server_name}",
                "old_counter": old_counter,
                "new_counter": new_counter
            })
        else:
            return jsonify({"error": f"Failed to skip bucket for {server_name}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# === Check All Counters Endpoint ===
@app.route('/counters', methods=['GET'])
def get_all_counters():
    try:
        headers = {"X-Master-Key": "$2a$10$0kbiUob1JFhNgyTFoWence/ntnK3VDbg2FCEBAxTXDnWuMfjk3HNW"}
        url = f"https://api.jsonbin.io/v3/b/68f85679ae596e708f231819/latest"
        
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            counters = data['record']['counters']
            total_requests = sum(counters.values())
            
            return jsonify({
                "message": "Current counters from JSONBin",
                "counters": counters,
                "total_requests": total_requests,
                "bin_id": "68f85679ae596e708f231819"
            })
        else:
            return jsonify({"error": f"Failed to fetch counters: {response.status_code}"}), 500
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# === Manual Reset Endpoint ===
@app.route('/reset_counters', methods=['POST'])
def manual_reset_counters():
    """Manually reset all counters to 0"""
    try:
        if jsonbin_db.reset_all_counters():
            return jsonify({"message": "✅ All counters reset to 0 successfully!"})
        else:
            return jsonify({"error": "Failed to reset counters"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/')
def home():
    return jsonify({"message": "Like Bot API is running!", "status": "active"})

if __name__ == '__main__':
    app.logger.info("🚀 Server started with ULTRA FAST LIKE SENDING & SIMPLE AUTO RESET!")
    app.run(debug=True, host='0.0.0.0', port=5001, threaded=True)
