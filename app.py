import os
import base64
import asyncio
import binascii
import json
import requests
import aiohttp
import time
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
from google.protobuf.message import DecodeError
import random
from functools import wraps

app = Flask(__name__)

# === GitHub configuration ===
GITHUB_TOKENS = [
    "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",
    "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",
    # Add more tokens here if needed for counter updates
]

# Token manager for COUNTER UPDATES only
class GitHubTokenManager:
    def __init__(self, tokens):
        self.tokens = tokens
        self.current_index = 0
        self.last_used = 0
        self.rate_limit_delay = 2  # 2 seconds between counter updates
        
    def get_token(self):
        # Rate limiting for counter updates
        elapsed = time.time() - self.last_used
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        
        token = self.tokens[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.tokens)
        self.last_used = time.time()
        return token

# Initialize token manager (only for counter updates)
token_manager = GitHubTokenManager(GITHUB_TOKENS)

MAIN_REPO_OWNER = "PWRSHAHEEDKALA"
MAIN_REPO_NAME = "Like_bott"
COUNTER_REPO_OWNER = "PWRSHAHEEDKALA"
COUNTER_REPO_NAME = "Telegram-likebot"

# === DOWNLOAD PROTOBUF FILES FIRST ===
def download_protobuf_files():
    """Download required protobuf files"""
    protobuf_files = {
        "like_pb2.py": "like_pb2.py",
        "like_count_pb2.py": "like_count_pb2.py", 
        "uid_generator_pb2.py": "uid_generator_pb2.py"
    }
    
    for filename, github_path in protobuf_files.items():
        if not os.path.exists(filename):
            app.logger.info(f"Downloading {filename}...")
            headers = {
                "Authorization": f"Bearer {GITHUB_TOKENS[0]}",
                "Accept": "application/vnd.github.v3.raw",
            }
            url = f"https://api.github.com/repos/{MAIN_REPO_OWNER}/{MAIN_REPO_NAME}/contents/{github_path}"
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                with open(filename, "w") as f:
                    f.write(response.text)
                app.logger.info(f"✅ Downloaded {filename}")
            else:
                app.logger.error(f"❌ Failed to download {filename}: {response.status_code}")

# Download protobuf files first
download_protobuf_files()

# Now import the protobuf files
try:
    import like_pb2
    import like_count_pb2
    import uid_generator_pb2
    app.logger.info("✅ All protobuf files imported successfully")
except ImportError as e:
    app.logger.error(f"❌ Failed to import protobuf files: {e}")

# === DOWNLOAD ONLY EXISTING TOKEN FILES ===
def download_existing_token_files():
    """Download only the token files that exist in the repo"""
    # Only these token files exist in your repo
    existing_token_files = [
        "token_ind.json",
        "token_bd.json",
        "token_br.json"
        # Removed token_vn.json and token_eu.json as they don't exist
    ]
    
    for file_name in existing_token_files:
        if not os.path.exists(file_name):
            app.logger.info(f"Downloading {file_name}...")
            headers = {
                "Authorization": f"Bearer {GITHUB_TOKENS[0]}",
                "Accept": "application/vnd.github.v3.raw",
            }
            url = f"https://api.github.com/repos/{MAIN_REPO_OWNER}/{MAIN_REPO_NAME}/contents/{file_name}"
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                with open(file_name, "w") as f:
                    f.write(response.text)
                app.logger.info(f"✅ Downloaded {file_name}")
            else:
                app.logger.warning(f"⚠️ Could not download {file_name}: {response.status_code}")

# Download existing token files
download_existing_token_files()

# === LOCAL TOKEN LOADING (NO GITHUB API NEEDED) ===
def load_tokens_local(server_name):
    """Load tokens from local JSON files - NO GitHub API calls needed"""
    try:
        # Map server names to existing token files
        if server_name == "IND":
            file_path = "token_ind.json"
        elif server_name in {"BD", "ME", "EU", "SG", "NA"}:
            file_path = "token_bd.json"
        elif server_name in {"BR", "cis", "US", "SAC"}:
            file_path = "token_br.json"
        else:
            # Default to BD tokens if server not specified
            file_path = "token_bd.json"
            
        app.logger.info(f"Loading tokens locally from: {file_path}")
        
        # Read directly from local file
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                tokens_dict = json.load(f)
            
            # Convert dictionary values to a list (sorted by key)
            sorted_keys = sorted(tokens_dict.keys(), key=lambda k: int(k))
            token_list = [tokens_dict[k] for k in sorted_keys]
            app.logger.info(f"✅ Loaded {len(token_list)} tokens locally for {server_name}")
            return token_list
        else:
            app.logger.error(f"❌ Token file not found: {file_path}")
            return None
            
    except Exception as e:
        app.logger.error(f"❌ Error loading local tokens for {server_name}: {e}")
        return None

# === COUNTER FUNCTIONS (Still need GitHub API for writes) ===
def get_counter(server_name):
    """Get counter from GitHub - NEEDS API for reading remote counter"""
    file_map = {
        "IND": "ind_remain.json", 
        "BR": "br_remain.json", 
        "SG": "sg_remain.json",
        "BD": "bd_remain.json",
        "ME": "me_remain.json",
        "NA": "na_remain.json"
    }
    file_path = file_map.get(server_name, "bd_remain.json")
    
    token = token_manager.get_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3.raw",
    }
    url = f"https://api.github.com/repos/{COUNTER_REPO_OWNER}/{COUNTER_REPO_NAME}/contents/{file_path}"
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            try:
                content = response.text
                data = json.loads(content)
                counter_value = int(data.get("counter", 0))
                app.logger.info(f"✅ Fetched counter for {server_name}: {counter_value}")
                return counter_value
            except Exception as e:
                app.logger.error(f"❌ Error parsing counter for {server_name}: {e}")
                return 0
        elif response.status_code == 404:
            app.logger.info(f"Counter file {file_path} not found, creating with default 0")
            update_counter(server_name, 0)
            return 0
        else:
            app.logger.error(f"❌ Error fetching counter for {server_name}: {response.status_code}")
            return 0
    except Exception as e:
        app.logger.error(f"❌ Network error fetching counter: {e}")
        return 0

def update_counter(server_name, new_value):
    """Update counter on GitHub - NEEDS API for writing"""
    file_map = {
        "IND": "ind_remain.json", 
        "BR": "br_remain.json", 
        "SG": "sg_remain.json",
        "BD": "bd_remain.json", 
        "ME": "me_remain.json",
        "NA": "na_remain.json"
    }
    file_path = file_map.get(server_name, "bd_remain.json")
    
    token = token_manager.get_token()
    url = f"https://api.github.com/repos/{COUNTER_REPO_OWNER}/{COUNTER_REPO_NAME}/contents/{file_path}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    try:
        # Get current file SHA
        get_response = requests.get(url, headers=headers, timeout=10)
        sha = None
        if get_response.status_code == 200:
            file_info = get_response.json()
            sha = file_info["sha"]
        
        # Prepare update
        content_data = {"counter": new_value}
        content_json = json.dumps(content_data, indent=2)
        new_content_b64 = base64.b64encode(content_json.encode()).decode()
        
        data = {
            "message": f"Update {server_name} counter to {new_value}",
            "content": new_content_b64
        }
        
        if sha:
            data["sha"] = sha
        
        app.logger.info(f"Updating counter for {server_name} to {new_value}")
        put_response = requests.put(url, headers=headers, json=data, timeout=10)
        
        if put_response.status_code in [200, 201]:
            app.logger.info(f"✅ Updated {server_name} counter to {new_value}")
            return True
        else:
            app.logger.error(f"❌ Failed to update counter: {put_response.status_code}")
            return False
    except Exception as e:
        app.logger.error(f"❌ Network error updating counter: {e}")
        return False

# === UPDATED TOKEN RANGE FUNCTION ===
def get_token_range_for_server(server_name):
    """Get token range using LOCAL token files"""
    counter = get_counter(server_name)
    app.logger.info(f"Current counter for {server_name}: {counter}")
    
    bucket = counter // 30
    start = bucket * 100
    end = start + 100
    
    # ✅ USE LOCAL TOKENS - NO GITHUB API
    tokens_all = load_tokens_local(server_name)
    if not tokens_all:
        app.logger.error(f"❌ No tokens found for server {server_name}")
        return []
    
    app.logger.info(f"Token range for {server_name}: start={start}, end={end}, total_tokens={len(tokens_all)}")
    
    # Handle case where start index exceeds available tokens
    if start >= len(tokens_all):
        app.logger.warning(f"Start index {start} exceeds token list, resetting counter")
        update_counter(server_name, 0)
        start = 0
        end = min(100, len(tokens_all))
    
    if end > len(tokens_all):
        end = len(tokens_all)
    
    token_range = tokens_all[start:end]
    app.logger.info(f"Selected {len(token_range)} tokens for {server_name}")
    return token_range

# === LOCAL TOKEN CACHE ===
class TokenCache:
    def __init__(self):
        self.cache = {}
        self.cache_time = {}
        self.cache_duration = 3600  # 1 hour cache (files don't change often)
        
    def get_tokens(self, server_name):
        current_time = time.time()
        if (server_name in self.cache and 
            current_time - self.cache_time.get(server_name, 0) < self.cache_duration):
            return self.cache[server_name]
        
        # Load from local file
        tokens = load_tokens_local(server_name)
        if tokens:
            self.cache[server_name] = tokens
            self.cache_time[server_name] = current_time
        return tokens

# Initialize token cache
token_cache = TokenCache()

# === ENCRYPTION AND PROTOBUF FUNCTIONS ===
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
                    app.logger.error(f"Request failed with status: {response.status}")
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
        tasks = []
        # ✅ This now uses LOCAL tokens without GitHub API
        tokens = get_token_range_for_server(server_name)
        if tokens is None or len(tokens) == 0:
            app.logger.error("Failed to load tokens from the specified range.")
            return None
        
        app.logger.info(f"Sending {len(tokens)} requests for {server_name}")
        for i in range(len(tokens)):
            token = tokens[i]
            tasks.append(send_request(encrypted_uid, token, url))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
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
            
            # Get current counter (only GitHub API call needed)
            current_counter = get_counter(server_name)
            app.logger.info(f"Current counter for {server_name}: {current_counter}")
            
            # ✅ Use LOCAL tokens without GitHub API
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

            # Perform like requests (uses LOCAL tokens)
            asyncio.run(send_multiple_requests(uid, server_name, url))

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
            
            # Update counter if needed (only GitHub API call for writes)
            if status == 1:
                new_counter = current_counter + 1
                app.logger.info(f"Updating counter for {server_name} from {current_counter} to {new_counter}")
                if update_counter(server_name, new_counter):
                    app.logger.info(f"✅ Updated counter for {server_name} to {new_counter}")
                else:
                    app.logger.error(f"❌ Failed to update counter for {server_name}")
            else:
                app.logger.info(f"No likes given, counter remains at {current_counter}")
                
            return result

        result = process_request()
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Error processing request: {e}")
        return jsonify({"error": str(e)}), 500

# Root endpoint
@app.route('/')
def home():
    return jsonify({"message": "Like Bot API is running!", "status": "active"})

if __name__ == '__main__':
    app.logger.info("🚀 Server started with LOCAL token loading!")
    app.run(debug=True, host='0.0.0.0', port=5001)
