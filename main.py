from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import JSONResponse
import requests, base64, json, urllib3
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import MajorLogin_res_pb2

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = FastAPI(title="RE7BAL JWT Extractor", version="2.0")

# -------------------------------------------------------------------
# Protobuf Encoder (ORIGINAL)
# -------------------------------------------------------------------
class SimpleProtobuf:
    @staticmethod
    def encode_varint(value):
        result = bytearray()
        while value > 0x7F:
            result.append((value & 0x7F) | 0x80)
            value >>= 7
        result.append(value & 0x7F)
        return bytes(result)

    @staticmethod
    def encode_string(field, value):
        if isinstance(value, str):
            value = value.encode()
        return (
            SimpleProtobuf.encode_varint((field << 3) | 2)
            + SimpleProtobuf.encode_varint(len(value))
            + value
        )

    @staticmethod
    def encode_int(field, value):
        return (
            SimpleProtobuf.encode_varint((field << 3) | 0)
            + SimpleProtobuf.encode_varint(value)
        )

    @staticmethod
    def create_login_payload(open_id, access_token, platform):
        p = bytearray()
        p += SimpleProtobuf.encode_string(3, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        p += SimpleProtobuf.encode_string(22, open_id)
        p += SimpleProtobuf.encode_string(23, str(platform))
        p += SimpleProtobuf.encode_string(29, access_token)
        p += SimpleProtobuf.encode_string(99, str(platform))
        return bytes(p)

# -------------------------------------------------------------------
# Inspect Token
# -------------------------------------------------------------------
def inspect_token(token: str):
    url = f"https://100067.connect.garena.com/oauth/token/inspect?token={token}"
    headers = {
        "User-Agent": "GarenaMSDK/4.0.19P4",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    r = requests.get(url, headers=headers, timeout=10, verify=False)
    data = r.json()

    if "error" in data:
        raise ValueError(data["error"])

    if not data.get("open_id") or not data.get("platform"):
        raise ValueError("Inspect failed")

    return data["open_id"], data["platform"]

# -------------------------------------------------------------------
# MajorLogin (FULL)
# -------------------------------------------------------------------
def major_login(open_id, token, platform):
    key = b"Yg&tc%DEuh6%Zc^8"
    iv = b"6oyZDr22E3ychjM%"

    payload = SimpleProtobuf.create_login_payload(open_id, token, platform)
    encrypted = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(payload, 16))

    headers = {
        "User-Agent": "Dalvik/2.1.0",
        "Content-Type": "application/octet-stream",
        "X-Unity-Version": "2018.4.11f1",
        "ReleaseVersion": "OB52"
    }

    r = requests.post(
        "https://loginbp.ggblueshark.com/MajorLogin",
        headers=headers,
        data=encrypted,
        timeout=15,
        verify=False
    )

    if not r.ok:
        raise ValueError("MajorLogin HTTP error")

    # ---- Try decrypt ----
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        decrypted = unpad(cipher.decrypt(r.content), 16)
    except Exception:
        decrypted = r.content

    resp = MajorLogin_res_pb2.MajorLoginRes()
    resp.ParseFromString(decrypted)

    if not resp.account_jwt:
        raise ValueError("JWT not found")

    return {
        "account_id": resp.account_id,
        "jwt": resp.account_jwt,
        "key": resp.key.hex(),
        "iv": resp.iv.hex()
    }

# -------------------------------------------------------------------
# API Routes
# -------------------------------------------------------------------
@app.get("/")
def root():
    return {
        "api": "RE7BAL-JWT-EXTRACTOR",
        "status": "online",
        "endpoint": "/getaccby/@n5nvn/?token=ACCESS_TOKEN"
    }

@app.get("/getaccby/@n5nvn/")
def extract(token: str = Query(...)):
    try:
        open_id, platform = inspect_token(token)
        login = major_login(open_id, token, platform)

        return JSONResponse({
            "success": True,
            "open_id": open_id,
            "platform": platform,
            "account_id": login["account_id"],
            "jwt": login["jwt"],
            "aes_key": login["key"],
            "aes_iv": login["iv"],
            "timestamp": datetime.utcnow().isoformat()
        })

    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception:
        raise HTTPException(500, "Internal server error")

# Vercel compatibility
app = app
