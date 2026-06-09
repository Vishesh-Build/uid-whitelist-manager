import sys
import os
import uuid
import threading
import time
import random
import base64
import binascii
import re
import json
from pathlib import Path
from mitmproxy import http
from mitmproxy.tools.main import mitmdump
from src.core.majorlogin_ob53_pb2 import MajorLoginOb53, MajorLoginResOb53
from src.core.login_pb2 import getUID, LoginReq
from src.utils.proto_utils import ProtobufUtils
from src.utils.decrypt import AESUtils
import requests
import urllib3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_DIR = Path(__file__).parent
UID_FILE = BASE_DIR / "uid.txt"
LOG_FILE = BASE_DIR / "access_token_log.txt"
FIREBASE_URL = "https://uid-bypass-363af-default-rtdb.asia-southeast1.firebasedatabase.app/users.json"

protoUtils = ProtobufUtils()
aesUtils = AESUtils()

UID_CACHE = set()
CACHE_LOCK = threading.Lock()
LAST_REFRESH = 0
REFRESH_INTERVAL = 5

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length"
}

UNK_102_OB53 = bytes.fromhex("655c1616704a0b0f24515e165a13")

# har region ke hisab se alag device profile banai h  

REGION_PROFILES = {
    "IN": {
        "country": "IN",
        "language": "en",
        "carriers": ["40445", "40551", "40552", "40553"],
        "devices": ["SM-S918B", "CPH2581", "Pixel 8 Pro", "2211133G"],
        "network": "5G",
        "user_agent": "Dalvik/2.1.0 (Linux; U; Android 14; SM-S918B Build/UP1A.231005.007)"
    },
    "US": {
        "country": "US",
        "language": "en-US",
        "carriers": ["310260", "310410", "311480", "310150"],
        "devices": ["Pixel 8 Pro", "SM-S928B", "CPH2581", "SM-S918B"],
        "network": "5G",
        "user_agent": "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 8 Pro Build/UP1A.231005.007)"
    },
    "BR": {
        "country": "BR",
        "language": "pt-BR",
        "carriers": ["72405", "72406", "72410", "72415"],
        "devices": ["SM-S918B", "M2007J20CG", "CPH2581", "2211133G"],
        "network": "4G",
        "user_agent": "Dalvik/2.1.0 (Linux; U; Android 14; SM-S918B Build/UP1A.231005.007)"
    },
    "SG": {
        "country": "SG",
        "language": "en-SG",
        "carriers": ["52501", "52502", "52503", "52505"],
        "devices": ["CPH2581", "SM-S918B", "Pixel 8 Pro", "2211133G"],
        "network": "5G",
        "user_agent": "Dalvik/2.1.0 (Linux; U; Android 14; CPH2581 Build/UP1A.231005.007)"
    },
    "EU": {
        "country": "GB",
        "language": "en-GB",
        "carriers": ["23410", "23415", "23420", "23430"],
        "devices": ["SM-S928B", "Pixel 8 Pro", "CPH2581", "SM-S918B"],
        "network": "5G",
        "user_agent": "Dalvik/2.1.0 (Linux; U; Android 14; SM-S928B Build/UP1A.231005.007)"
    },
    "DEFAULT": {
        "country": "IN",
        "language": "en",
        "carriers": ["40445"],
        "devices": ["SM-S918B"],
        "network": "5G",
        "user_agent": "Dalvik/2.1.0 (Linux; U; Android 14; SM-S918B Build/UP1A.231005.007)"
    }
}

# Android versions
ANDROID_VERSIONS = [
    "Android OS 15 / API-35 (TP1A.220905.001/U.R4T2.1c822c2_1_3)",
    "Android OS 14 / API-34 (UP1A.231005.007)",
    "Android OS 13 / API-33 (TQ3A.230805.001)",
]

def get_region_from_jwt(flow):
    """Extract region from JWT token in request"""
    try:
        auth_header = flow.request.headers.get("Authorization", "")
        if auth_header:
            match = re.search(r"Bearer\s+([\w\-\.]+)", auth_header)
            if match:
                token = match.group(1)
                payload = token.split(".")[1]
                payload += "=" * (4 - len(payload) % 4)
                decoded = json.loads(base64.urlsafe_b64decode(payload))
                region = decoded.get("lock_region", decoded.get("region", "DEFAULT"))
                if region in REGION_PROFILES:
                    return region
    except:
        pass
    return "DEFAULT"

def get_region_profile(flow):
    region = get_region_from_jwt(flow)
    return REGION_PROFILES.get(region, REGION_PROFILES["DEFAULT"]), region

def get_random_device(profile):
    return random.choice(profile["devices"])

def get_random_carrier(profile):
    return random.choice(profile["carriers"])

def get_random_android():
    return random.choice(ANDROID_VERSIONS)

def get_random_ram():
    return random.randint(6000, 12000)

def get_random_google_account():
    return f"Google|{uuid.uuid4().hex}"

def get_random_session_id():
    return uuid.uuid4().hex[:32]

def get_random_loading_time():
    return random.randint(15000, 35000)

def get_random_delay():
    return random.uniform(0.05, 0.3)

def get_random_oaid():
    return f"{uuid.uuid4().hex[:8]}-{uuid.uuid4().hex[:4]}-{uuid.uuid4().hex[:4]}-{uuid.uuid4().hex[:4]}-{uuid.uuid4().hex[:12]}"

def load_whitelist():
    global UID_CACHE, LAST_REFRESH
    new_uids = set()
    
    if UID_FILE.exists():
        try:
            with open(UID_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and line.isdigit():
                        new_uids.add(line)
                        print(f"[✓] uid.txt: {line}")
        except:
            pass
    
    try:
        resp = requests.get(FIREBASE_URL, timeout=10)
        if resp.status_code == 200:
            users = resp.json()
            if users:
                for user_data in users.values():
                    uids = user_data.get("uids", {})
                    if isinstance(uids, dict):
                        for uid_data in uids.values():
                            if isinstance(uid_data, dict) and "uid" in uid_data:
                                new_uids.add(str(uid_data["uid"]))
                                print(f"[✓] Firebase: {uid_data['uid']}")
    except Exception as e:
        print(f"[!] Firebase error: {e}")
    
    with CACHE_LOCK:
        UID_CACHE = new_uids
        LAST_REFRESH = time.time()
    print(f"[✓] Total UIDs: {len(UID_CACHE)}")

def check_uid(uid):
    uid = str(uid).strip()
    if uid == "0":
        return True
    with CACHE_LOCK:
        if time.time() - LAST_REFRESH > REFRESH_INTERVAL:
            threading.Thread(target=load_whitelist, daemon=True).start()
        return uid in UID_CACHE

load_whitelist()
threading.Thread(target=load_whitelist, daemon=True).start()

def save_mitmproxy_cert():
    try:
        home = os.path.expanduser("~/.mitmproxy")
        ca_cert = os.path.join(home, "mitmproxy-ca-cert.pem")
        output_file = BASE_DIR / "certificat_mitmproxy.pem"
        if os.path.exists(ca_cert):
            with open(ca_cert, "rb") as src, open(output_file, "wb") as dst:
                dst.write(src.read())
    except:
        pass

def log_access_token(open_id, access_token, platform="", uid="", status=""):
    try:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        line = f"[{ts}] open_id={open_id} | token={access_token} | platform={platform}"
        if uid:
            line += f" | uid={uid}"
        if status:
            line += f" | status={status}"
        line += "\n"
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(line)
    except:
        pass

def build_majorlogin_ob53(open_id, access_token, platform_type, real_ip, profile, region):
    pt = str(platform_type) if platform_type else "3"
    event_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    
    session_device = get_random_device(profile)
    session_carrier = get_random_carrier(profile)
    session_android = get_random_android()
    session_ram = get_random_ram()
    session_google = get_random_google_account()
    session_id = get_random_session_id()
    loading_time = get_random_loading_time()
    oaid = get_random_oaid()
    
    msg = MajorLoginOb53()
    msg.event_time = event_time
    msg.game_name = "free fire"
    msg.client_version = "1.123.6"
    msg.system_software = session_android
    msg.system_hardware = "qcom"
    msg.telecom_operator = session_carrier
    msg.network_type = profile["network"]
    msg.screen_width = 2412
    msg.screen_height = 1080
    msg.screen_dpi = "480"
    msg.processor_details = "ARM64 FP ASIMD AES | 5260 | 8"
    msg.memory = session_ram
    msg.gpu_renderer = "Adreno (TM) 740"
    msg.gpu_version = "OpenGL ES 3.2 V@0676.65"
    msg.unique_device_id = uuid.uuid4().hex
    msg.client_ip = real_ip
    msg.language = profile["language"]
    msg.open_id = open_id
    msg.open_id_type = pt
    msg.device_type = "Handheld"
    msg.device_model = session_device
    msg.country = profile["country"]
    msg.access_token = access_token
    msg.platform_sdk_id = 1
    msg.internal_storage_total = 256000
    msg.internal_storage_available = 128000
    msg.reg_avatar = 1
    msg.library_token = "AndroidDevice"
    msg.channel_type = 3
    msg.cpu_type = 1
    msg.client_version_code = "2019120273"
    msg.graphics_api = "OpenGL ES 3.2"
    msg.supported_astc_bitset = 255
    msg.login_open_id_type = 3
    msg.loading_time = loading_time
    msg.release_channel = "android"
    msg.extra_info = "KqsHT7MUjyjjnA/jcWo74TjG04IMJoCAYFBIAOaqjgev7SOLjHCkzmg2MVIU4w9Hoxb4LQ=="
    msg.origin_platform_type = pt
    msg.primary_platform_type = pt
    msg.unk_102 = UNK_102_OB53
    
    if hasattr(msg, 'oaid'):
        msg.oaid = oaid
    
    return msg.SerializeToString()

def ob53_request_headers(access_token, profile):
    return {
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": f"{profile['language']},{profile['language'].split('-')[0]};q=0.9",
        "Authorization": f"Bearer {access_token}",
        "Connection": "keep-alive",
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": "loginbp.ggpolarbear.com",
        "ReleaseVersion": "OB53",
        "User-Agent": profile["user_agent"],
        "X-GA": "v1 1",
        "X-Unity-Version": "2022.3.47f1",
    }

KEY = base64.b64decode("WWcmdGMlREV1aDYlWmNeOA==")
IV = base64.b64decode("Nm95WkRyMjJFM3ljaGpNJQ==")

def octet_stream_to_hex(octet_stream):
    return binascii.hexlify(octet_stream).decode()

def hex_to_octet_stream(hex_str):
    return bytes.fromhex(hex_str)

def _aes_cbc_decrypt_nopad(data, key, iv):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    return cipher.decryptor().update(data) + cipher.decryptor().finalize()

def _strip_pkcs7(data):
    pad = data[-1]
    if 1 <= pad <= 16 and data[-pad:] == bytes([pad]) * pad:
        return data[:-pad]
    return data

def _try_proto(data, proto_cls):
    msg = proto_cls()
    msg.ParseFromString(data)
    oid = getattr(msg, "open_id", "") or ""
    tok = getattr(msg, "access_token", "") or getattr(msg, "login_token", "") or ""
    otyp = getattr(msg, "open_id_type", "") or ""
    ptype = getattr(msg, "origin_platform_type", "") or ""
    if not ptype and otyp:
        ptype = otyp
    return oid, tok, otyp, ptype

def try_parse_loginreq_decrypted(raw_body):
    if len(raw_body) % 16 != 0:
        return None
    try:
        dec = _aes_cbc_decrypt_nopad(raw_body, KEY, IV)
        dec = _strip_pkcs7(dec)
        r = LoginReq()
        r.ParseFromString(dec)
        if r.open_id:
            return r
    except:
        pass
    return None

def try_parse_loginreq_plain(raw_body):
    try:
        r = LoginReq()
        r.ParseFromString(raw_body)
        if r.open_id:
            return r
    except:
        pass
    return None

def extract_credentials(raw_body):
    for proto_cls in (MajorLoginOb53, LoginReq):
        try:
            oid, tok, otyp, ptype = _try_proto(raw_body, proto_cls)
            if oid:
                print(f"[PARSE] Plain {proto_cls.__name__} OK — open_id={oid}")
                return oid, tok, otyp, ptype
        except:
            pass
    if len(raw_body) % 16 == 0:
        try:
            dec = _aes_cbc_decrypt_nopad(raw_body, KEY, IV)
            dec = _strip_pkcs7(dec)
            for proto_cls in (MajorLoginOb53, LoginReq):
                try:
                    oid, tok, otyp, ptype = _try_proto(dec, proto_cls)
                    if oid:
                        print(f"[PARSE] AES-CBC {proto_cls.__name__} OK — open_id={oid}")
                        return oid, tok, otyp, ptype
                except:
                    pass
        except:
            pass
    raise ValueError(f"Cannot parse MajorLogin body")

class MajorLoginInterceptor:
    def request(self, flow):
        try:
            if flow.request.method.upper() != "POST":
                return
            if "/MajorLogin" not in flow.request.path:
                return
            
            time.sleep(get_random_delay())
            
            real_ip = flow.client_conn.address[0]
            profile, region = get_region_profile(flow)
            
            print(f"[IP] Real client IP: {real_ip}")
            print(f"[REGION] Detected: {region}")
            print(f"[INTERCEPT] MajorLogin")
            
            raw = flow.request.content
            
            login_orig = try_parse_loginreq_plain(raw) or try_parse_loginreq_decrypted(raw)
            if login_orig:
                access_token = login_orig.login_token
                open_id = login_orig.open_id
                pt = login_orig.open_id_type or "3"
                print(f"[PARSE] LoginReq — open_id={open_id}")
            else:
                open_id, access_token, open_id_type, platform_type = extract_credentials(raw)
                pt = platform_type or open_id_type or "3"
                print(f"[PARSE] Fallback extract — open_id={open_id}")
            
            log_access_token(open_id, access_token, platform=pt)
            
            plain = build_majorlogin_ob53(open_id, access_token, pt, real_ip, profile, region)
            encrypted_body = aesUtils.encrypt_aes_cbc(plain)
            hdrs = ob53_request_headers(access_token, profile)
            
            time.sleep(get_random_delay())
            
            resp = requests.post(
                "https://loginbp.ggblueshark.com/MajorLogin",
                data=bytes.fromhex(encrypted_body.hex()),
                headers=hdrs,
                verify=False,
                timeout=20
            )
            
            out_h = {}
            for k, v in resp.headers.items():
                if k.lower() not in HOP_BY_HOP and k.lower() not in ("transfer-encoding", "content-encoding"):
                    out_h[k] = v
            out_h["Content-Length"] = str(len(resp.content))
            
            flow.response = http.Response.make(resp.status_code, resp.content, out_h)
            
            if resp.status_code == 200:
                print(f"[BYPASS] OK")
            else:
                print(f"[BYPASS] HTTP {resp.status_code}")
                
        except Exception as e:
            print(f"[ERROR] Request: {e}")
    
    def response(self, flow):
        try:
            if flow.request.method.upper() != "POST":
                return
            if "majorlogin" not in flow.request.path.lower():
                return
            if flow.response.status_code != 200:
                return
            
            time.sleep(get_random_delay())
            
            uid_str = None
            try:
                decrypted_resp = aesUtils.decrypt_aes_cbc(flow.response.content)
                major_res = MajorLoginResOb53()
                major_res.ParseFromString(decrypted_resp)
                if major_res.account_uid:
                    uid_str = str(major_res.account_uid)
            except:
                pass
            
            if not uid_str:
                try:
                    decoded = protoUtils.decode_protobuf(flow.response.content, getUID)
                    uid_str = str(decoded.uid)
                except:
                    pass
            
            if not uid_str or uid_str == "0":
                print("[WARN] Could not extract UID")
                return
            
            print(f"[CHECK] UID: {uid_str}")
            
            time.sleep(get_random_delay())
            
            if check_uid(uid_str):
                print(f"[ACCESS GRANTED] UID {uid_str}")
                log_access_token("", "", "", uid_str, "GRANTED")
            else:
                print(f"[ACCESS DENIED] UID {uid_str}")
                log_access_token("", "", "", uid_str, "DENIED")
                
                error_msg = f"""╔══════════════════════════════════════════════════════════════╗
║                    ACCESS DENIED                              ║
╠══════════════════════════════════════════════════════════════╣
║  UID: {uid_str}
║  STATUS: UNAUTHORIZED
║                                                                  ║
║  Please Contact:
║  ► Anmol
║  ► Arpit
║                                                                  ║
║  AXC CORPORATION
╚══════════════════════════════════════════════════════════════╝"""
                
                flow.response.content = error_msg.encode("utf-8")
                flow.response.status_code = 403
                
        except Exception as e:
            print(f"[ERROR] Response: {e}")

addons = [MajorLoginInterceptor()]
save_mitmproxy_cert()

if __name__ == "__main__":
    print("\n" + "="*55)
    print(" 🔥 AXC BYPASS 🔥")
    print("="*55)
    print(f" Whitelisted UIDs: {len(UID_CACHE)}")
    print(f" Firebase: Connected")
    print(f" Regions: IN, US, BR, SG, EU (Auto-detect)")
    print(f" Device: Region-specific random")
    print(f" Carrier: Region-specific random")
    print(f" RAM: Random range (6-12GB)")
    print(f" IP: REAL (No spoofing)")
    print(f" OAID: Random per session (OB53)")
    print(f" Timing: Randomized (Human-like)")
    print(f" Proxy: http://0.0.0.0:9944")
    print("="*55 + "\n")
    
    mitmdump(["-s", __file__, "-p", "9944   ", "--set", "block_global=false"])