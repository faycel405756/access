from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import JSONResponse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from datetime import datetime
import requests, urllib3, re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = FastAPI(title="RE7BAL JWT Extractor", version="1.0")

class ProtobufEncoder:
    @staticmethod
    def encode_varint(value: int) -> bytes:
        result = bytearray()
        while value > 0x7F:
            result.append((value & 0x7F) | 0x80)
            value >>= 7
        result.append(value & 0x7F)
        return bytes(result)

    @staticmethod
    def encode_field(field_number: int, wire_type: int, value) -> bytes:
        key = (field_number << 3) | wire_type
        result = ProtobufEncoder.encode_varint(key)
        if wire_type == 0:
            result += ProtobufEncoder.encode_varint(int(value))
        elif wire_type == 2:
            if isinstance(value, str):
                value = value.encode("utf-8")
            result += ProtobufEncoder.encode_varint(len(value))
            result += value
        return result

    @staticmethod
    def create_login_request(open_id, access_token, platform):
        payload = bytearray()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        payload.extend(ProtobufEncoder.encode_field(3, 2, timestamp))
        payload.extend(ProtobufEncoder.encode_field(22, 2, open_id))
        payload.extend(ProtobufEncoder.encode_field(23, 2, platform))
        payload.extend(ProtobufEncoder.encode_field(29, 2, access_token))
        payload.extend(ProtobufEncoder.encode_field(99, 2, platform))
        return bytes(payload)

def inspect_access_token_api(token: str):
    r = requests.get(
        "https://100067.connect.garena.com/oauth/token/inspect",
        params={"token": token},
        timeout=10,
        verify=False
    )
    data = r.json()
    if r.status_code != 200 or data.get("error"):
        raise ValueError("Invalid access token")
    return str(data["open_id"]), str(data["platform"])

def get_major_login_token_api(open_id, token, platform):
    key = b"Yg&tc%DEuh6%Zc^8"
    iv = b"6oyZDr22E3ychjM%"
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(
        pad(ProtobufEncoder.create_login_request(open_id, token, platform), AES.block_size)
    )
    r = requests.post(
        "https://loginbp.ggblueshark.com/MajorLogin",
        data=encrypted,
        timeout=15,
        verify=False
    )
    match = re.search(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", r.text)
    if not match:
        raise ValueError("JWT not found")
    return match.group(0)

@app.get("/")
async def root():
    return {"status": "OK"}

@app.get("/getaccby/@n5nvn/")
async def extract(token: str = Query(...)):
    try:
        open_id, platform = inspect_access_token_api(token)
        jwt = get_major_login_token_api(open_id, token, platform)
        return {"success": True, "jwt": jwt}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

app = app
