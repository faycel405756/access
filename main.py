import requests
from fastapi import FastAPI, HTTPException
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import MajorLogin_res_pb2
from datetime import datetime
from google.protobuf.timestamp_pb2 import Timestamp
import json, base64, traceback, warnings

warnings.filterwarnings("ignore")

app = FastAPI()

# ==== نفس الكلاس الأصلي ====
class SimpleProtobuf:
    @staticmethod
    def encode_varint(value):
        r = bytearray()
        while value > 0x7F:
            r.append((value & 0x7F) | 0x80)
            value >>= 7
        r.append(value & 0x7F)
        return bytes(r)

    @staticmethod
    def encode_string(f, v):
        if isinstance(v, str):
            v = v.encode()
        r = bytearray()
        r.extend(SimpleProtobuf.encode_varint((f << 3) | 2))
        r.extend(SimpleProtobuf.encode_varint(len(v)))
        r.extend(v)
        return bytes(r)

    @staticmethod
    def encode_int32(f, v):
        r = bytearray()
        r.extend(SimpleProtobuf.encode_varint((f << 3) | 0))
        r.extend(SimpleProtobuf.encode_varint(v))
        return bytes(r)

    @staticmethod
    def create_login_payload(open_id, access_token, platform):
        p = bytearray()
        p.extend(SimpleProtobuf.encode_string(3, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        p.extend(SimpleProtobuf.encode_string(4, "free fire"))
        p.extend(SimpleProtobuf.encode_int32(5, 1))
        p.extend(SimpleProtobuf.encode_string(22, open_id))
        p.extend(SimpleProtobuf.encode_string(23, str(platform)))
        p.extend(SimpleProtobuf.encode_string(29, access_token))
        return bytes(p)

# ==== API ====
@app.get("/access")
def access(token: str):
    try:
        inspect_url = f"https://100067.connect.garena.com/oauth/token/inspect?token={token}"
        inspect_headers = {
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close",
            "Content-Type": "application/x-www-form-urlencoded",
            "Host": "100067.connect.garena.com",
            "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)"
        }

        inspect_data = requests.get(inspect_url, headers=inspect_headers, timeout=10).json()

        if "error" in inspect_data:
            raise HTTPException(status_code=400, detail=inspect_data)

        open_id = inspect_data.get("open_id")
        platform = inspect_data.get("platform")

        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'

        payload = SimpleProtobuf.create_login_payload(open_id, token, platform)
        enc = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(payload, 16))

        headers = {
            "User-Agent": "Dalvik/2.1.0 (Linux; Android)",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "Content-Type": "application/octet-stream",
            "Expect": "100-continue",
            "X-GA": "v1 1",
            "X-Unity-Version": "2018.4.11f1",
            "ReleaseVersion": "OB52"
        }

        r = requests.post(
            "https://loginbp.ggblueshark.com/MajorLogin",
            headers=headers,
            data=enc,
            timeout=15
        )

        cipher = AES.new(key, AES.MODE_CBC, iv)
        dec = unpad(cipher.decrypt(r.content), 16)

        msg = MajorLogin_res_pb2.MajorLoginRes()
        msg.ParseFromString(dec)

        return {
            "open_id": open_id,
            "platform": platform,
            "account_id": msg.account_id,
            "jwt": msg.account_jwt,
            "key": msg.key.hex(),
            "iv": msg.iv.hex()
        }

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))
