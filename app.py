# main.py — NIROBxFREExLIKE VIP Backend (LIVE only, MULTI-API)
# Web: http://<server>:5000/
# API: /like?uid=<uid>&server_name=<bd|ind|br|us|sac|na>&key=<key>

import os
import json
import time
import hashlib
import binascii
import asyncio
from threading import RLock
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Flask, request, jsonify, make_response, Response, render_template
from flask_cors import CORS
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson

import requests
import aiohttp
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import orjson
    def _jsonify(data, status=200):
        return Response(orjson.dumps(data), status=status, mimetype='application/json')
except ImportError:
    def _jsonify(data, status=200):
        return Response(json.dumps(data, separators=(',', ':'), ensure_ascii=False),
                        status=status, mimetype='application/json')

import like_pb2
import like_count_pb2
import uid_generator_pb2

app = Flask(__name__)
CORS(app)

# ---------- Branding ----------
OWNER_HANDLE = "TG: @ShadowXSlayer"
DEV_NAME     = "Shadow"
TELEGRAM     = "@Sepnix"
BRAND_NAME   = "ShadowXSarkar"
BADGE_TEXT   = "LIKE • API • KEY"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CLIENT_VERSION = "1.132.1"
OB_VERSION     = "OB55"
LOGIN_URL      = "https://loginbp.ggblueshark.com"

# ============================================================
#  MULTI JWT TOKEN APIs (har API se token generate karega)
# ============================================================
JWT_APIS = [
    {
        "name": "RAGHAV",
        "url": "http://148.113.25.200:6293/Tok",
        "uid_param": "uid",
        "pw_param": "pw",
        "token_keys": ["token", "access_token", "jwt"],
    },
    {
        "name": "KAWSAR",
        "url": "https://kawsarxjwt.lovable.app/api/public/token",
        "uid_param": "uid",
        "pw_param": "password",
        "token_keys": ["token", "access_token", "jwt"],
    },
    {
        "name": "NIROB",
        "url": "https://nirobxjwt.vercel.app/token",
        "uid_param": "uid",
        "pw_param": "password",
        "token_keys": ["access_token", "token", "jwt"],
    },
]

# ---------- Workers / Burst ----------
JWT_WORKERS   = 60
LIKE_CONCUR   = 150

# ---------- Server → account file mapping ----------
SERVER_ACCOUNT_FILES = {
    "BD":  "account_bd.txt",
    "IND": "account_ind.txt",
    "BR":  "account_br.txt",
    "US":  "account_us.txt",
    "SAC": "account_sac.txt",
    "NA":  "account_na.txt",
}

# ---------- Config (only validate key) ----------
CONFIG_RO_PATH = os.path.join(BASE_DIR, "keys.json")
CONFIG_RW_PATH = os.path.join("/tmp", "keys.json")
config_lock = RLock()

def _active_config_path_for_read() -> str:
    return CONFIG_RW_PATH if os.path.exists(CONFIG_RW_PATH) else CONFIG_RO_PATH

def _read_config() -> dict:
    path = _active_config_path_for_read()
    if not os.path.exists(path):
        raise FileNotFoundError("keys.json not found")
    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    if "ALLOWED_KEYS" not in cfg or "ADMIN_KEYS" not in cfg or "RESET_TZ" not in cfg:
        raise ValueError("keys.json must include ALLOWED_KEYS, ADMIN_KEYS, RESET_TZ")
    return cfg

def get_allowed_keys() -> dict:
    with config_lock:
        return _read_config()["ALLOWED_KEYS"]

def get_admin_keys() -> set:
    with config_lock:
        return set(_read_config()["ADMIN_KEYS"])

def is_valid_key(api_key: str) -> bool:
    try:
        return api_key in get_allowed_keys() or api_key in get_admin_keys()
    except Exception:
        return False


# ============================================================
#  ACCOUNT FILE LOADER
# ============================================================
def _account_file_path(server_name: str) -> str:
    fname = SERVER_ACCOUNT_FILES.get(server_name.upper())
    if not fname:
        return ""
    return os.path.join(BASE_DIR, fname)


def _load_accounts_for_server(server_name: str) -> list:
    path = _account_file_path(server_name)
    if not path or not os.path.exists(path):
        return []
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if not ln or ln.startswith("#") or ":" not in ln:
                continue
            uid, pw = ln.split(":", 1)
            uid, pw = uid.strip(), pw.strip()
            if uid and pw:
                out.append((uid, pw))
    return out


# ============================================================
#  JWT GENERATION — MULTI API (har API se try karega)
# ============================================================
def _extract_token_from_response(j, token_keys):
    """Har API ke response format se token nikalta hai."""
    if isinstance(j, str):
        return j if len(j) > 20 else None
    if not isinstance(j, dict):
        return None

    # Direct keys
    for k in token_keys:
        v = j.get(k)
        if v and isinstance(v, str) and len(v) > 20:
            return v

    # Nested data
    data = j.get("data")
    if isinstance(data, dict):
        for k in token_keys:
            v = data.get(k)
            if v and isinstance(v, str) and len(v) > 20:
                return v
    if isinstance(data, str) and len(data) > 20:
        return data

    # result field
    res = j.get("result")
    if isinstance(res, dict):
        for k in token_keys:
            v = res.get(k)
            if v and isinstance(v, str) and len(v) > 20:
                return v
    if isinstance(res, str) and len(res) > 20:
        return res

    return None


def _fetch_single_jwt(uid: str, pw: str, timeout: int = 12):
    """
    Har account ke liye:
      - Har API ko try karega (ek ke baad ek)
      - Pehla valid token mile toh return kar dega
    """
    for api in JWT_APIS:
        try:
            url = f"{api['url']}?{api['uid_param']}={uid}&{api['pw_param']}={pw}"
            r = requests.get(url, timeout=timeout, verify=False)
            if r.status_code != 200:
                continue
            try:
                j = r.json()
            except ValueError:
                text = r.text.strip()
                if text and len(text) > 50:
                    return uid, text
                continue

            token = _extract_token_from_response(j, api["token_keys"])
            if token:
                return uid, token
        except requests.RequestException:
            continue
    return uid, None


def generate_jwts_live(accounts: list, max_workers: int = JWT_WORKERS):
    """
    Generate JWT for EVERY account — live, multi-API, no cache.
    Har account ke liye har API try karega jab tak token na mile.
    """
    if not accounts:
        return []
    tokens = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_fetch_single_jwt, uid, pw): uid for uid, pw in accounts}
        for fut in as_completed(futures):
            uid, token = fut.result()
            if token:
                tokens.append(token)
    return tokens


# ============================================================
#  FREE FIRE LIKE HELPERS
# ============================================================
def encrypt_message(plaintext):
    k = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(k, AES.MODE_CBC, iv)
    padded = pad(plaintext, AES.block_size)
    return binascii.hexlify(cipher.encrypt(padded)).decode("utf-8")


def create_protobuf_message(user_id, region):
    m = like_pb2.like()
    m.uid = int(user_id)
    m.region = region
    return m.SerializeToString()


def create_protobuf(uid):
    m = uid_generator_pb2.uid_generator()
    m.krishna_ = int(uid)
    m.teamXdarks = 1
    return m.SerializeToString()


def enc(uid):
    return encrypt_message(create_protobuf(uid))


async def send_request(encrypted_uid, token, url, session_):
    edata = bytes.fromhex(encrypted_uid)
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB55"
    }
    try:
        async with session_.post(url, data=edata, headers=headers) as resp:
            return resp.status
    except Exception:
        return 0


async def _burst_all_tokens(uid, server_name, url, tokens, concurrency=LIKE_CONCUR):
    """Send ONE like request per token — every token used live."""
    msg = create_protobuf_message(uid, server_name)
    enc_uid = encrypt_message(msg)
    if not tokens:
        return []

    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    sem = asyncio.Semaphore(concurrency)

    async with aiohttp.ClientSession(connector=connector) as sess:
        async def worker(tok):
            async with sem:
                return await send_request(enc_uid, tok, url, sess)
        results = await asyncio.gather(*[worker(t) for t in tokens])
        return results


def send_likes_from_all_tokens(uid, server_name, url, tokens):
    if not tokens:
        return 0
    results = asyncio.run(_burst_all_tokens(uid, server_name, url, tokens,
                                            concurrency=LIKE_CONCUR))
    success = sum(1 for s in results if s == 200)
    return success


def _like_url_for(server_name: str) -> str:
    s = server_name.upper()
    if s == "IND":
        return "https://client.ind.freefiremobile.com/LikeProfile"
    elif s in {"BR", "US", "SAC", "NA"}:
        return "https://client.us.freefiremobile.com/LikeProfile"
    else:
        return "https://clientbp.ppmainecoonghj.com/LikeProfile"


def _show_url_for(server_name: str) -> str:
    s = server_name.upper()
    if s == "IND":
        return "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    elif s in {"BR", "US", "SAC", "NA"}:
        return "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    else:
        return "https://clientbp.ppmainecoonghj.com/GetPlayerPersonalShow"


def make_request(encrypted, server_name, token):
    url = _show_url_for(server_name)
    edata = bytes.fromhex(encrypted)
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB55"
    }
    resp = requests.post(url, data=edata, headers=headers, verify=False, timeout=30)
    binary = bytes.fromhex(resp.content.hex())
    try:
        obj = like_count_pb2.Info()
        obj.ParseFromString(binary)
        return obj
    except Exception:
        return None


def _parse_account_info(pb_obj):
    try:
        if pb_obj is None:
            return None
        js = json.loads(MessageToJson(pb_obj))
        ai = js.get("AccountInfo", {})
        uid = int(ai.get("UID", 0))
        likes = int(ai.get("Likes", 0))
        name = str(ai.get("PlayerNickname", ""))
        if uid <= 0:
            return None
        return {"uid": uid, "likes": likes, "name": name}
    except Exception:
        return None


# ============================================================
#  WEB UI
# ============================================================
@app.get("/")
def index():
    return render_template(
        "index.html",
        brand=BRAND_NAME,
        dev=DEV_NAME,
        tg=TELEGRAM,
        owner=OWNER_HANDLE,
        badge=BADGE_TEXT,
    )


@app.get("/health")
def route_health():
    return _jsonify({
        "status": "ok",
        "service": BRAND_NAME,
        "dev": DEV_NAME,
        "tg": TELEGRAM,
        "badge": BADGE_TEXT,
        "jwt_apis": [a["name"] for a in JWT_APIS],
        "servers": list(SERVER_ACCOUNT_FILES.keys()),
    })


# ============================================================
#  /like — LIVE, no limits, no cache, MULTI-API
# ============================================================
@app.get("/like")
def handle_like():
    try:
        uid = request.args.get("uid")
        server_name = request.args.get("server_name", "").upper()
        api_key = request.args.get("key", "").strip()

        if not api_key or not is_valid_key(api_key):
            return jsonify({"error": "Invalid or missing API key 🔑"}), 403
        if not uid or not server_name:
            return jsonify({"error": "UID and server_name are required"}), 400
        if server_name not in SERVER_ACCOUNT_FILES:
            return jsonify({
                "error": f"Unsupported server_name '{server_name}'",
                "allowed": list(SERVER_ACCOUNT_FILES.keys())
            }), 400

        accounts = _load_accounts_for_server(server_name)
        if not accounts:
            fname = SERVER_ACCOUNT_FILES[server_name]
            return jsonify({
                "error": f"No guest accounts found for server {server_name}",
                "hint": f"Add uid:pass lines into {fname}",
                "Owner": OWNER_HANDLE
            }), 500

        # ---- LIVE JWT (har account, har API se try) ----
        print(f"[*] LIVE JWT for {len(accounts)} accounts ({server_name}) using {len(JWT_APIS)} APIs ...")
        tokens = generate_jwts_live(accounts, max_workers=JWT_WORKERS)
        print(f"[+] Got {len(tokens)} live tokens out of {len(accounts)} accounts")

        if not tokens:
            return jsonify({
                "error": "Failed to generate any JWT tokens from all APIs.",
                "server": server_name,
                "accounts_loaded": len(accounts),
                "apis_tried": [a["name"] for a in JWT_APIS],
                "Owner": OWNER_HANDLE
            }), 500

        token = tokens[0]
        encrypted = enc(uid)

        # ---- BEFORE ----
        before = _parse_account_info(make_request(encrypted, server_name, token))
        if before is None:
            return jsonify({
                "LikesGivenByAPI": 0,
                "LikesafterCommand": 0,
                "LikesbeforeCommand": 0,
                "PlayerNickname": "Unknown",
                "UID": int(uid) if str(uid).isdigit() else uid,
                "GiftCount": 0,
                "accounts_loaded": len(accounts),
                "tokens_generated": len(tokens),
                "server_name": server_name,
                "Owner": OWNER_HANDLE,
                "status": 0
            })

        # ---- LIVE LIKE from all tokens ----
        url = _like_url_for(server_name)
        send_likes_from_all_tokens(uid, server_name, url, tokens)

        # ---- AFTER ----
        after = _parse_account_info(make_request(encrypted, server_name, token)) or {
            "likes": before["likes"], "uid": before["uid"], "name": before["name"]
        }
        like_given = max(0, int(after["likes"]) - int(before["likes"]))
        gift_count = like_given * 2 if like_given > 0 else 0
        status_value = 1 if like_given > 0 else 2

        return jsonify({
            "LikesGivenByAPI": like_given,
            "LikesafterCommand": int(after["likes"]),
            "LikesbeforeCommand": int(before["likes"]),
            "PlayerNickname": str(after["name"]),
            "UID": int(after["uid"]),
            "GiftCount": gift_count,
            "server_name": server_name,
            "accounts_loaded": len(accounts),
            "tokens_generated": len(tokens),
            "Owner": OWNER_HANDLE,
            "status": status_value
        })
    except Exception as e:
        return jsonify({"error": "config_or_runtime_error", "detail": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)