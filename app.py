import os
import urllib3
import warnings
# COMPLETELY SUPPRESS ALL WARNINGS
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")
os.environ['PYTHONWARNINGS'] = 'ignore'

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
]

# Token manager for COUNTER UPDATES only
class GitHubTokenManager:
    def __init__(self, tokens):
        self.tokens = tokens
        self.current_index = 0
        self.last_used = 0
        self.rate_limit_delay = 2
        
    def get_token(self):
        elapsed = time.time() - self.last_used
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        
        token = self.tokens[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.tokens)
        self.last_used = time.time()
        return token

token_manager = GitHubTokenManager(GITHUB_TOKENS)

MAIN_REPO_OWNER = "PWRSHAHEEDKALA"
MAIN_REPO_NAME = "Like_bott"
COUNTER_REPO_OWNER = "PWRSHAHEEDKALA"
COUNTER_REPO_NAME = "Telegram-likebot"

# === DOWNLOAD PROTOBUF FILES FIRST ===
def download_protobuf_files():
    protobuf_files = {
        "like_pb2.py": "like_pb2.py",
        "like_count_pb2.py": "like_count_pb2.py", 
        "uid_generator_pb2.py": "uid_generator_pb2.py"
    }
    
    for filename, github_path in protobuf_files.items():
        if not os.path.exists(filename):
            app.logger.info(f"Downloading {filename}...")
            headers = {"Authorization": f"Bearer {GITHUB_TOKENS[0]}"}
            url = f"https://api.github.com/repos/{MAIN_REPO_OWNER}/{MAIN_REPO_NAME}/contents/{github_path}"
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                with open(filename, "w") as f:
                    f.write(response.text)
                app.logger.info(f"✅ Downloaded {filename}")
            else:
                app.logger.error(f"❌ Failed to download {filename}: {response.status_code}")

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
    existing_token_files = ["token_ind.json", "token_bd.json", "token_br.json"]
    
    for file_name in existing_token_files:
        if not os.path.exists(file_name):
            app.logger.info(f"Downloading {file_name}...")
            headers = {"Authorization": f"Bearer {GITHUB_TOKENS[0]}"}
            url = f"https://api.github.com/repos/{MAIN_REPO_OWNER}/{MAIN_REPO_NAME}/contents/{file_name}"
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                with open(file_name, "w") as f:
                    f.write(response.text)
                app.logger.info(f"✅ Downloaded {file_name}")
            else:
                app.logger.warning(f"⚠️ Could not download {file_name}: {response.status_code}")

download_existing_token_files()

# === LOCAL TOKEN LOADING ===
def load_tokens_local(server_name):
    try:
        if server_name == "IND":
            file_path = "token_ind.json"
        elif server_name in {"BD", "ME", "EU", "SG", "NA"}:
            file_path = "token_bd.json"
        elif server_name in {"BR", "cis", "US", "SAC"}:
            file_path = "token_br.json"
        else:
            file_path = "token_bd.json"
            
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                tokens_dict = json.load(f)
            
            sorted_keys = sorted(tokens_dict.keys(), key=lambda k: int(k))
            token_list = [tokens_dict[k] for k in sorted_keys]
            app.logger.info(f"✅ Loaded {len(token_list)} tokens for {server_name}")
            return token_list
        else:
            app.logger.error(f"❌ Token file not found: {file_path}")
            return None
            
    except Exception as e:
        app.logger.error(f"❌ Error loading tokens for {server_name}: {e}")
        return None

# === COUNTER FUNCTIONS ===
def get_counter(server_name):
    file_map = {
        "IND": "ind_remain.json", "BR": "br_remain.json", "SG": "sg_remain.json",
        "BD": "bd_remain.json", "ME": "me_remain.json", "NA": "na_remain.json"
    }
    file_path = file_map.get(server_name, "bd_remain.json")
    
    token = token_manager.get_token()
    headers = {"Authorization": f"Bearer {token}"}
    url = f"https://api.github.com/repos/{COUNTER_REPO_OWNER}/{COUNTER_REPO_NAME}/contents/{file_path}"
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = json.loads(response.text)
            counter_value = int(data.get("counter", 0))
            return counter_value
        elif response.status_code == 404:
            update_counter(server_name, 0)
            return 0
        else:
            return 0
    except Exception:
        return 0

def update_counter(server_name, new_value):
    file_map = {
        "IND": "ind_remain.json", "BR": "br_remain.json", "SG": "sg_remain.json",
        "BD": "bd_remain.json", "ME": "me_remain.json", "NA": "na_remain.json"
    }
    file_path = file_map.get(server_name, "bd_remain.json")
    
    token = token_manager.get_token()
    url = f"https://api.github.com/repos/{COUNTER_REPO_OWNER}/{COUNTER_REPO_NAME}/contents/{file_path}"
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        get_response = requests.get(url, headers=headers, timeout=10)
        sha = None
        if get_response.status_code == 200:
            file_info = get_response.json()
            sha = file_info["sha"]
        
        content_data = {"counter": new_value}
        content_json = json.dumps(content_data, indent=2)
        new_content_b64 = base64.b64encode(content_json.encode()).decode()
        
        data = {
            "message": f"Update {server_name} counter to {new_value}",
            "content": new_content_b64
        }
        
        if sha:
            data["sha"] = sha
        
        put_response = requests.put(url, headers=headers, json=data, timeout=10)
        return put_response.status_code in [200, 201]
    except Exception:
        return False

# === TOKEN RANGE FUNCTION ===
def get_token_range_for_server(server_name):
    counter = get_counter(server_name)
    app.logger.info(f"Current counter for {server_name}: {counter}")
    
    bucket = counter // 30
    start = bucket * 100
    end = start + 100
    
    tokens_all = load_tokens_local(server_name)
    if not tokens_all:
        return []
    
    if start >= len(tokens_all):
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
        self.cache_duration = 3600
        
    def get_tokens(self, server_name):
        current_time = time.time()
        if (server_name in self.cache and 
            current_time - self.cache_time.get(server_name, 0) < self.cache_duration):
            return self.cache[server_name]
        
        tokens = load_tokens_local(server_name)
        if tokens:
            self.cache[server_name] = tokens
            self.cache_time[server_name] = current_time
        return tokens

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
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'X-Unity-Version': "2021.3.18f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                return response.status
    except Exception:
        return None

async def send_multiple_requests(uid, server_name, url):
    try:
        region = server_name
        protobuf_message = create_protobuf_message(uid, region)
        if protobuf_message is None:
            return None
        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None:
            return None
        
        tokens = get_token_range_for_server(server_name)
        if not tokens:
            return None
        
        tasks = []
        for token in tokens:
            tasks.append(send_request(encrypted_uid, token, url))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
    except Exception as e:
        app.logger.error(f"Exception in send_multiple_requests: {e}")
        return None

# === IMPROVED PROTOBUF DECODING WITH BETTER ERROR HANDLING ===
def decode_protobuf(binary):
    try:
        # Try to decode as like_count_pb2.Info first
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except DecodeError:
        try:
            # If that fails, try to decode as like_pb2.like
            items = like_pb2.like()
            items.ParseFromString(binary)
            return items
        except DecodeError:
            try:
                # If that fails, try uid_generator_pb2.uid_generator
                items = uid_generator_pb2.uid_generator()
                items.ParseFromString(binary)
                return items
            except DecodeError as e:
                app.logger.warning(f"All protobuf decoding attempts failed: {e}")
                return None
    except Exception as e:
        app.logger.warning(f"Unexpected error during protobuf decoding: {e}")
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
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'X-Unity-Version': "2021.3.18f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }
        
        # Suppress warnings for this request
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            response = requests.post(url, data=edata, headers=headers, verify=False, timeout=10)
        
        hex_data = response.content.hex()
        binary = bytes.fromhex(hex_data)
        
        # Try multiple decoding approaches
        decode = decode_protobuf(binary)
        if decode is None:
            # If decoding fails, check if response contains error information
            app.logger.warning(f"Protobuf decoding failed for {server_name}, response length: {len(binary)}")
            return None
        
        return decode
    except Exception as e:
        app.logger.error(f"Error in make_request: {e}")
        return None

# === IMPROVED MAIN ENDPOINT WITH BETTER ERROR HANDLING ===
@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    
    if not uid or not server_name:
        return jsonify({"error": "UID and server_name are required"}), 400

    try:
        app.logger.info(f"Starting request for UID: {uid}, Server: {server_name}")
        
        # Get current counter
        current_counter = get_counter(server_name)
        app.logger.info(f"Current counter: {current_counter}")
        
        # Use cached tokens
        tokens_all = token_cache.get_tokens(server_name)
        if not tokens_all:
            return jsonify({"error": "No tokens available for this server"}), 500
        
        # Use first token for initial check
        token = tokens_all[0]
        encrypted_uid = enc(uid)
        if not encrypted_uid:
            return jsonify({"error": "Encryption failed"}), 500

        # Get initial likes count with retry logic
        max_retries = 3
        before = None
        for attempt in range(max_retries):
            before = make_request(encrypted_uid, server_name, token)
            if before is not None:
                break
            app.logger.warning(f"Retry {attempt + 1} for initial player info...")
            time.sleep(1)
        
        if before is None:
            return jsonify({"error": "Could not retrieve player info after retries"}), 500

        try:
            jsone = MessageToJson(before)
            data_before = json.loads(jsone)
            before_like = data_before.get('AccountInfo', {}).get('Likes', 0)
            before_like = int(before_like) if before_like else 0
        except Exception as e:
            app.logger.error(f"Error parsing initial data: {e}")
            return jsonify({"error": "Failed to parse player data"}), 500

        app.logger.info(f"Likes before: {before_like}")

        # Determine URL for like requests
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/LikeProfile"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/LikeProfile"
        else:
            url = "https://clientbp.ggblueshark.com/LikeProfile"

        # Send like requests
        asyncio.run(send_multiple_requests(uid, server_name, url))

        # Get updated likes count with retry logic
        after = None
        for attempt in range(max_retries):
            after = make_request(encrypted_uid, server_name, token)
            if after is not None:
                break
            app.logger.warning(f"Retry {attempt + 1} for updated player info...")
            time.sleep(1)

        if after is None:
            return jsonify({"error": "Could not retrieve updated player info"}), 500

        try:
            jsone_after = MessageToJson(after)
            data_after = json.loads(jsone_after)
            after_like = int(data_after.get('AccountInfo', {}).get('Likes', 0))
            player_uid = int(data_after.get('AccountInfo', {}).get('UID', 0))
            player_name = str(data_after.get('AccountInfo', {}).get('PlayerNickname', ''))
        except Exception as e:
            app.logger.error(f"Error parsing updated data: {e}")
            return jsonify({"error": "Failed to parse updated player data"}), 500

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
        
        app.logger.info(f"Request completed: {result}")
        
        # Update counter if likes were given
        if status == 1:
            new_counter = current_counter + 1
            if update_counter(server_name, new_counter):
                app.logger.info(f"✅ Counter updated to {new_counter}")
            else:
                app.logger.warning(f"⚠️ Counter update failed")
        
        return jsonify(result)
        
    except Exception as e:
        app.logger.error(f"Error processing request: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/')
def home():
    return jsonify({"message": "Like Bot API is running!", "status": "active"})

if __name__ == '__main__':
    app.logger.info("🚀 Server started with improved error handling!")
    app.run(debug=True, host='0.0.0.0', port=5001)
