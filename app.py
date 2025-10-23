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
            
            # Map BD, SG, EU, ME, PK regions to BD counter
            if server_name in ["BD", "SG", "EU", "ME", "PK"]:
                server_name = "BD"
            
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
            
            # Map BD, SG, EU, ME, PK regions to BD counter
            if server_name in ["BD", "SG", "EU", "ME", "PK"]:
                server_name = "BD"
            
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
        self.last_request_time = 0
        
    async def throttle_request(self):
        """Throttle requests to avoid rate limiting"""
        async with self.semaphore:
            current_time = time.time()
            time_since_last = current_time - self.last_request_time
            if time_since_last < self.delay_between_requests:
                await asyncio.sleep(self.delay_between_requests - time_since_last)
            self.last_request_time = time.time()

throttler = RequestThrottler()

# === AES ENCRYPTION ===
def aes_encrypt(data, key):
    """AES encryption function"""
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        encrypted = cipher.encrypt(pad(data, AES.block_size))
        return base64.b64encode(encrypted).decode('utf-8')
    except Exception as e:
        app.logger.error(f"❌ AES encryption error: {e}")
        return None

# === LOAD TOKENS ===
def load_tokens(server_name):
    """Load tokens from JSON file"""
    try:
        filename = TOKEN_FILES.get(server_name)
        if not filename:
            app.logger.error(f"❌ No token file configured for server: {server_name}")
            return []
        
        if not os.path.exists(filename):
            app.logger.error(f"❌ Token file not found: {filename}")
            return []
        
        with open(filename, 'r') as f:
            data = json.load(f)
        
        tokens = data.get('tokens', [])
        app.logger.info(f"✅ Loaded {len(tokens)} tokens for {server_name}")
        return tokens
        
    except Exception as e:
        app.logger.error(f"❌ Error loading tokens for {server_name}: {e}")
        return []

# === GENERATE UID ===
def generate_uid():
    """Generate UID using protobuf"""
    try:
        uid_request = uid_generator_pb2.UIDRequest()
        uid_request.type = "default"
        serialized_uid = uid_request.SerializeToString()
        return serialized_uid
    except Exception as e:
        app.logger.error(f"❌ Error generating UID: {e}")
        return b''

# === LIKE REQUEST HANDLER ===
def create_like_request(video_id, token):
    """Create like request using protobuf"""
    try:
        like_request = like_pb2.LikeRequest()
        like_request.videoId = video_id
        like_request.token = token
        like_request.uid = generate_uid()
        return like_request.SerializeToString()
    except Exception as e:
        app.logger.error(f"❌ Error creating like request: {e}")
        return None

# === LIKE COUNT REQUEST HANDLER ===
def create_like_count_request(video_id):
    """Create like count request using protobuf"""
    try:
        like_count_request = like_count_pb2.LikeCountRequest()
        like_count_request.videoId = video_id
        return like_count_request.SerializeToString()
    except Exception as e:
        app.logger.error(f"❌ Error creating like count request: {e}")
        return None

# === ASYNC LIKE FUNCTION ===
async def send_like_request(session, video_id, token, server_name):
    """Send like request to server"""
    try:
        await throttler.throttle_request()
        
        # Create protobuf request
        serialized_request = create_like_request(video_id, token)
        if not serialized_request:
            return False
        
        # Encrypt request
        aes_key = binascii.unhexlify("a5f8f14b4c7c9e5b1a2d3c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4")
        encrypted_request = aes_encrypt(serialized_request, aes_key)
        if not encrypted_request:
            return False
        
        # Prepare headers
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'LikeBot/1.0',
            'X-Encrypted-Request': 'true'
        }
        
        # Send request
        payload = {"data": encrypted_request}
        url = f"https://like-{server_name.lower()}.likeevideo.com/like"
        
        async with session.post(url, json=payload, headers=headers, ssl=False) as response:
            if response.status == 200:
                response_data = await response.json()
                if 'data' in response_data:
                    encrypted_response = response_data['data']
                    try:
                        decoded_response = base64.b64decode(encrypted_response)
                        like_response = like_pb2.LikeResponse()
                        like_response.ParseFromString(decoded_response)
                        
                        if like_response.success:
                            app.logger.info(f"✅ Like sent successfully to {server_name}")
                            return True
                    except Exception as e:
                        app.logger.error(f"❌ Error parsing response from {server_name}: {e}")
            
            app.logger.error(f"❌ Failed to send like to {server_name}: {response.status}")
            return False
            
    except Exception as e:
        app.logger.error(f"❌ Error in send_like_request for {server_name}: {e}")
        return False

# === ASYNC LIKE COUNT FUNCTION ===
async def get_like_count(session, video_id, server_name):
    """Get like count from server"""
    try:
        await throttler.throttle_request()
        
        # Create protobuf request
        serialized_request = create_like_count_request(video_id)
        if not serialized_request:
            return 0
        
        # Encrypt request
        aes_key = binascii.unhexlify("a5f8f14b4c7c9e5b1a2d3c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4")
        encrypted_request = aes_encrypt(serialized_request, aes_key)
        if not encrypted_request:
            return 0
        
        # Prepare headers
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'LikeBot/1.0',
            'X-Encrypted-Request': 'true'
        }
        
        # Send request
        payload = {"data": encrypted_request}
        url = f"https://like-{server_name.lower()}.likeevideo.com/likeCount"
        
        async with session.post(url, json=payload, headers=headers, ssl=False) as response:
            if response.status == 200:
                response_data = await response.json()
                if 'data' in response_data:
                    encrypted_response = response_data['data']
                    try:
                        decoded_response = base64.b64decode(encrypted_response)
                        like_count_response = like_count_pb2.LikeCountResponse()
                        like_count_response.ParseFromString(decoded_response)
                        
                        app.logger.info(f"✅ Like count for {video_id}: {like_count_response.count}")
                        return like_count_response.count
                    except Exception as e:
                        app.logger.error(f"❌ Error parsing like count response from {server_name}: {e}")
            
            app.logger.error(f"❌ Failed to get like count from {server_name}: {response.status}")
            return 0
            
    except Exception as e:
        app.logger.error(f"❌ Error in get_like_count for {server_name}: {e}")
        return 0

# === MAIN LIKE ENDPOINT ===
@app.route('/like', methods=['POST'])
async def like_video():
    """Main endpoint to send likes"""
    try:
        data = request.get_json()
        video_id = data.get('video_id')
        target_likes = int(data.get('target_likes', 50))
        server_name = data.get('server_name', 'IND').upper()
        
        if not video_id:
            return jsonify({"error": "video_id is required"}), 400
        
        app.logger.info(f"🎯 Received request: video_id={video_id}, target_likes={target_likes}, server={server_name}")
        
        # Get current counter
        current_counter = jsonbin_db.get_counter(server_name)
        app.logger.info(f"📊 Current counter for {server_name}: {current_counter}")
        
        # Load tokens
        tokens = load_tokens(server_name)
        if not tokens:
            return jsonify({"error": f"No tokens available for server {server_name}"}), 400
        
        # Get current like count
        async with aiohttp.ClientSession() as session:
            current_likes = await get_like_count(session, video_id, server_name)
            app.logger.info(f"❤️ Current likes for {video_id}: {current_likes}")
            
            likes_needed = max(0, target_likes - current_likes)
            app.logger.info(f"🎯 Likes needed: {likes_needed}")
            
            if likes_needed == 0:
                return jsonify({
                    "message": "Target likes already reached",
                    "current_likes": current_likes,
                    "likes_sent": 0,
                    "counter": current_counter
                })
            
            # Send likes
            successful_likes = 0
            tasks = []
            
            for i in range(likes_needed):
                token = random.choice(tokens)
                task = send_like_request(session, video_id, token, server_name)
                tasks.append(task)
                
                if len(tasks) >= 50:
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    successful_likes += sum(1 for r in results if r is True)
                    tasks = []
                    await asyncio.sleep(0.1)
            
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                successful_likes += sum(1 for r in results if r is True)
            
            # Update counter
            new_counter = current_counter + successful_likes
            jsonbin_db.update_counter(server_name, new_counter)
            
            # Get final like count
            final_likes = await get_like_count(session, video_id, server_name)
            
            app.logger.info(f"✅ Successfully sent {successful_likes} likes to {video_id}")
            app.logger.info(f"📊 Counter updated for {server_name}: {new_counter}")
            
            return jsonify({
                "message": "Likes sent successfully",
                "video_id": video_id,
                "initial_likes": current_likes,
                "final_likes": final_likes,
                "likes_sent": successful_likes,
                "counter": new_counter,
                "server": server_name
            })
            
    except Exception as e:
        app.logger.error(f"❌ Error in like_video endpoint: {e}")
        return jsonify({"error": str(e)}), 500

# === COUNTER RESET ENDPOINT ===
@app.route('/reset_counter', methods=['POST'])
def reset_counter():
    """Reset counter manually with key authentication"""
    try:
        data = request.get_json()
        reset_key = data.get('reset_key')
        
        if reset_key != "aruu_1":
            return jsonify({"error": "Invalid reset key"}), 401
        
        if jsonbin_db.reset_all_counters():
            return jsonify({"message": "All counters reset successfully!"})
        else:
            return jsonify({"error": "Failed to reset counters"}), 500
            
    except Exception as e:
        app.logger.error(f"❌ Error in reset_counter endpoint: {e}")
        return jsonify({"error": str(e)}), 500

# === COUNTER STATUS ENDPOINT ===
@app.route('/counter_status', methods=['GET'])
def counter_status():
    """Get current counter status for all regions"""
    try:
        # Check auto-reset first
        auto_reset_manager.check_reset_needed()
        
        headers = {"X-Master-Key": jsonbin_db.api_key}
        url = f"{jsonbin_db.base_url}/{jsonbin_db.bin_id}/latest"
        
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            counters = data['record']['counters']
            
            return jsonify({
                "message": "Counter status retrieved successfully",
                "counters": counters,
                "last_updated": datetime.now().isoformat()
            })
        else:
            return jsonify({"error": "Failed to fetch counter status"}), 500
            
    except Exception as e:
        app.logger.error(f"❌ Error in counter_status endpoint: {e}")
        return jsonify({"error": str(e)}), 500

# === HEALTH CHECK ENDPOINT ===
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "Like Bot API"
    })

# === BACKGROUND AUTO-RESET CHECKER ===
def background_reset_checker():
    """Background thread to check for auto-reset"""
    while True:
        try:
            auto_reset_manager.check_reset_needed()
            time.sleep(60)  # Check every minute
        except Exception as e:
            app.logger.error(f"❌ Error in background reset checker: {e}")
            time.sleep(60)

# Start background thread
reset_thread = threading.Thread(target=background_reset_checker, daemon=True)
reset_thread.start()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
