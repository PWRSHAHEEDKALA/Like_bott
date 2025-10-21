import os
import urllib3
import warnings
import time
from functools import wraps

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

# === MULTIPLE GitHub Tokens for Rotation ===
GITHUB_TOKENS = [
    "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",
    "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",
    # Add more tokens from different GitHub accounts here
]

# Enhanced GitHub Token Manager
class GitHubTokenManager:
    def __init__(self, tokens):
        self.tokens = tokens
        self.current_index = 0
        self.last_used = 0
        self.rate_limit_delay = 3  # Increased to 3 seconds
        self.failed_tokens = set()
        
    def get_token(self):
        # Rate limiting between all calls
        elapsed = time.time() - self.last_used
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        
        # Find next working token
        start_index = self.current_index
        while True:
            token = self.tokens[self.current_index]
            self.current_index = (self.current_index + 1) % len(self.tokens)
            
            if token not in self.failed_tokens:
                break
                
            # If we've tried all tokens and they're all failed
            if self.current_index == start_index:
                raise Exception("All GitHub tokens are rate limited")
        
        self.last_used = time.time()
        return token
    
    def mark_token_failed(self, token):
        self.failed_tokens.add(token)
        app.logger.warning(f"Marked token as rate limited: {token[:10]}...")

# Initialize token manager
token_manager = GitHubTokenManager(GITHUB_TOKENS)

# === Request Throttler for FreeFire API ===
class RequestThrottler:
    def __init__(self, max_concurrent=3, delay_between_requests=0.3):
        self.max_concurrent = max_concurrent
        self.delay_between_requests = delay_between_requests
        self.semaphore = asyncio.Semaphore(max_concurrent)
    
    async def throttle_request(self, coro):
        async with self.semaphore:
            # Add small delay between requests
            await asyncio.sleep(self.delay_between_requests)
            return await coro

# Initialize request throttler
request_throttler = RequestThrottler(max_concurrent=3, delay_between_requests=0.3)

# === GitHub configuration ===
MAIN_REPO_OWNER = "PWRSHAHEEDKALA"
MAIN_REPO_NAME = "Like_bott"
COUNTER_REPO_OWNER = "PWRSHAHEEDKALA"
COUNTER_REPO_NAME = "Telegram-likebot"

# === File Caching System ===
class FileCache:
    def __init__(self, cache_dir=".cache", cache_duration=300):  # 5 minutes
        self.cache_dir = cache_dir
        self.cache_duration = cache_duration
        os.makedirs(cache_dir, exist_ok=True)
    
    def get(self, key):
        cache_file = os.path.join(self.cache_dir, f"{key}.json")
        if os.path.exists(cache_file):
            if time.time() - os.path.getmtime(cache_file) < self.cache_duration:
                with open(cache_file, 'r') as f:
                    return json.load(f)
        return None
    
    def set(self, key, value):
        cache_file = os.path.join(self.cache_dir, f"{key}.json")
        with open(cache_file, 'w') as f:
            json.dump(value, f)

# Initialize file cache
file_cache = FileCache()

# === Rate Limiting Decorator ===
def rate_limit(seconds):
    def decorator(func):
        last_called = [0.0]
        @wraps(func)
        def wrapper(*args, **kwargs):
            elapsed = time.time() - last_called[0]
            if elapsed < seconds:
                time.sleep(seconds - elapsed)
            last_called[0] = time.time()
            return func(*args, **kwargs)
        return wrapper
    return decorator

# === Exponential Backoff for GitHub API ===
def github_api_with_backoff(func, max_retries=3):
    for retry in range(max_retries):
        try:
            result = func()
            return result
        except Exception as e:
            error_str = str(e).lower()
            if "rate limit" in error_str or "403" in error_str:
                wait_time = (2 ** retry) + random.random() * 2
                app.logger.warning(f"GitHub rate limit hit, retrying in {wait_time:.2f} seconds...")
                
                # If it's a 403, mark the current token as failed
                if "403" in error_str:
                    token_manager.mark_token_failed(token_manager.tokens[token_manager.current_index])
                
                time.sleep(wait_time)
            else:
                app.logger.error(f"GitHub API error: {e}")
                raise e
    raise Exception("Max retries exceeded for GitHub API")

# Function to download a file from GitHub if it does not exist locally
def download_file_if_missing(filename, github_path):
    if not os.path.exists(filename):
        def download_attempt():
            token = token_manager.get_token()
            headers = {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github.v3.raw",
            }
            url = f"https://api.github.com/repos/{MAIN_REPO_OWNER}/{MAIN_REPO_NAME}/contents/{github_path}"
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                with open(filename, "w") as f:
                    f.write(response.text)
                app.logger.info(f"Downloaded {filename} from GitHub.")
                return True
            else:
                raise Exception(f"Failed to download {filename} from GitHub: {response.status_code} - {response.text}")
        
        github_api_with_backoff(download_attempt)

# Auto-download required protobuf files from the GitHub repo
download_file_if_missing("like_pb2.py", "like_pb2.py")
download_file_if_missing("like_count_pb2.py", "like_count_pb2.py")
download_file_if_missing("uid_generator_pb2.py", "uid_generator_pb2.py")

# Now import the protobuf files
import like_pb2
import like_count_pb2
import uid_generator_pb2

# === GitHub File Fetching with Token Rotation and Caching ===
@rate_limit(2)  # Increased to 2 seconds
def fetch_file_from_main_repo(file_path):
    # Check cache first
    cached = file_cache.get(file_path)
    if cached is not None:
        app.logger.info(f"Using cached version of {file_path}")
        return cached
    
    def fetch_attempt():
        token = token_manager.get_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3.raw",
        }
        url = f"https://api.github.com/repos/{MAIN_REPO_OWNER}/{MAIN_REPO_NAME}/contents/{file_path}"
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            content = response.text
            # Cache the content
            file_cache.set(file_path, content)
            return content
        else:
            app.logger.error(f"Error fetching file from main repo ({file_path}): {response.status_code} - {response.text}")
            return None
    
    return github_api_with_backoff(fetch_attempt)

# === COUNTER REPO FUNCTIONS with Token Rotation ===
@rate_limit(2)
def get_counter(server_name):
    file_map = {
        "IND": "ind_remain.json", 
        "BR": "br_remain.json", 
        "SG": "sg_remain.json",
        "BD": "bd_remain.json",
        "ME": "me_remain.json",
        "NA": "na_remain.json"
    }
    file_path = file_map.get(server_name, "bd_remain.json")
    
    def get_counter_attempt():
        token = token_manager.get_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3.raw",
        }
        url = f"https://api.github.com/repos/{COUNTER_REPO_OWNER}/{COUNTER_REPO_NAME}/contents/{file_path}"
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            try:
                content = response.text
                data = json.loads(content)
                counter_value = int(data.get("counter", 0))
                app.logger.info(f"Successfully fetched counter for {server_name}: {counter_value}")
                return counter_value
            except Exception as e:
                app.logger.error(f"Error parsing counter for {server_name}: {e}")
                return 0
        elif response.status_code == 404:
            # File doesn't exist, create it
            app.logger.info(f"Counter file {file_path} not found, creating new one with default value 0")
            update_counter(server_name, 0)  # Create file with 0
            return 0
        else:
            app.logger.error(f"Error fetching counter for {server_name}: {response.status_code} - {response.text}")
            return 0
    
    return github_api_with_backoff(get_counter_attempt)

@rate_limit(2)
def update_counter(server_name, new_value):
    file_map = {
        "IND": "ind_remain.json", 
        "BR": "br_remain.json", 
        "SG": "sg_remain.json",
        "BD": "bd_remain.json", 
        "ME": "me_remain.json",
        "NA": "na_remain.json"
    }
    file_path = file_map.get(server_name, "bd_remain.json")
    
    def update_counter_attempt():
        token = token_manager.get_token()
        url = f"https://api.github.com/repos/{COUNTER_REPO_OWNER}/{COUNTER_REPO_NAME}/contents/{file_path}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        # First, try to get the file to get its SHA (if it exists)
        get_response = requests.get(url, headers=headers)
        sha = None
        if get_response.status_code == 200:
            file_info = get_response.json()
            sha = file_info["sha"]
            app.logger.info(f"Found existing file with SHA: {sha}")
        
        # Prepare the content
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
        put_response = requests.put(url, headers=headers, json=data)
        
        if put_response.status_code in [200, 201]:
            app.logger.info(f"Successfully updated {server_name} counter to {new_value}")
            return True
        else:
            app.logger.error(f"Failed to update counter {file_path}: {put_response.status_code} - {put_response.text}")
            return False
    
    return github_api_with_backoff(update_counter_attempt)

# === Token Handling Functions ===
def load_tokens(server_name):
    try:
        if server_name == "IND":
            file_path = "token_ind.json"
        elif server_name in {"ME", "EU", "SG", "NA", "BD"}:
            file_path = "token_bd.json"
        elif server_name in {"BR", "cis"}:
            file_path = "token_br.json"
        elif server_name == "VN":
            file_path = "token_vn.json"
        else:
            file_path = "token_eu.json"
            
        file_content = fetch_file_from_main_repo(file_path)
        if file_content:
            tokens_dict = json.loads(file_content)
            # Convert dictionary values to a list (sorted by key, if needed)
            sorted_keys = sorted(tokens_dict.keys(), key=lambda k: int(k))
            token_list = [tokens_dict[k] for k in sorted_keys]
            app.logger.info(f"Loaded {len(token_list)} tokens for {server_name}")
            return token_list
        else:
            app.logger.error(f"Failed to fetch {file_path} from GitHub.")
            return None
    except Exception as e:
        app.logger.error(f"Error loading tokens for server {server_name}: {e}")
        return None

# === LOCAL TOKEN CACHE to reduce GitHub API calls ===
class TokenCache:
    def __init__(self):
        self.cache = {}
        self.cache_time = {}
        self.cache_duration = 300  # 5 minutes cache
        
    def get_tokens(self, server_name):
        current_time = time.time()
        if (server_name in self.cache and 
            current_time - self.cache_time.get(server_name, 0) < self.cache_duration):
            return self.cache[server_name]
        
        # Fetch from GitHub
        tokens = load_tokens(server_name)
        if tokens:
            self.cache[server_name] = tokens
            self.cache_time[server_name] = current_time
        return tokens

# Initialize token cache
token_cache = TokenCache()

def get_token_range_for_server(server_name):
    try:
        counter = get_counter(server_name)
        app.logger.info(f"Current counter for {server_name}: {counter}")
        
        # Calculate which bucket we're in (each bucket = 30 uses)
        bucket = counter // 30
        start = bucket * 100
        end = start + 100
        
        # Use cached tokens
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
        # Return empty list as fallback
        return []

# === ORIGINAL FUNCTIONS WITH THROTTLING ONLY ===
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
        
        # Get token range based on current counter
        tokens = get_token_range_for_server(server_name)
        if tokens is None or len(tokens) == 0:
            app.logger.error("Failed to load tokens from the specified range.")
            return None
        
        app.logger.info(f"Sending {len(tokens)} requests for {server_name} with throttling")
        
        tasks = []
        # Send requests using the filtered token range WITH THROTTLING
        for i in range(len(tokens)):
            token = tokens[i]
            # Throttle each request
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

# === Main /like Endpoint (FIXED COUNTER LOGIC) ===
@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    if not uid or not server_name:
        return jsonify({"error": "UID and server_name are required"}), 400

    try:
        def process_request():
            app.logger.info(f"Starting request processing for UID: {uid}, Server: {server_name}")
            
            # Get current counter BEFORE processing
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

            # Perform like requests asynchronously using tokens from a specified bucket/range
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
            
            # FIXED: Update counter based on successful requests, not just status
            if successful_requests and successful_requests > 0:
                new_counter = current_counter + successful_requests
                app.logger.info(f"Updating counter for {server_name} from {current_counter} to {new_counter} ({successful_requests} successful requests)")
                if update_counter(server_name, new_counter):
                    app.logger.info(f"Successfully updated counter for {server_name} to {new_counter} in counter repo")
                else:
                    app.logger.error(f"Failed to update counter for {server_name} in counter repo")
            else:
                app.logger.info(f"No successful requests, counter remains at {current_counter}")
                
            return result

        result = process_request()
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Error processing request: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/')
def home():
    return jsonify({"message": "Like Bot API is running!", "status": "active"})

if __name__ == '__main__':
    app.logger.info("🚀 Server started with FIXED COUNTER SYSTEM and REQUEST THROTTLING!")
    app.run(debug=True, host='0.0.0.0', port=5001)
