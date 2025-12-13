# api/main.py - RE7BAL JWT Extractor API
from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import JSONResponse
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from datetime import datetime
import base64, json, time, urllib3, traceback, re
from typing import Optional

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = FastAPI(title="RE7BAL JWT Extractor", version="1.0")

# Your original functions here (same as before, but simplified for API)
class ProtobufEncoder:
    @staticmethod
    def encode_varint(value):
        result = bytearray()
        while value > 0x7F:
            result.append((value & 0x7F) | 0x80)
            value >>= 7
        result.append(value & 0x7F)
        return bytes(result)
    
    @staticmethod
    def encode_field(field_number, wire_type, value):
        key = (field_number << 3) | wire_type
        result = ProtobufEncoder.encode_varint(key)
        if wire_type == 0:
            result += ProtobufEncoder.encode_varint(value)
        elif wire_type == 2:
            if isinstance(value, str):
                value = value.encode('utf-8')
            result += ProtobufEncoder.encode_varint(len(value))
            result += value
        return result
    
    @staticmethod
    def create_login_request(open_id, access_token, platform):
        payload = bytearray()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        payload.extend(ProtobufEncoder.encode_field(3, 2, timestamp))
        payload.extend(ProtobufEncoder.encode_field(22, 2, str(open_id)))
        payload.extend(ProtobufEncoder.encode_field(23, 2, str(platform)))
        payload.extend(ProtobufEncoder.encode_field(29, 2, access_token))
        payload.extend(ProtobufEncoder.encode_field(99, 2, str(platform)))
        return bytes(payload)

def inspect_access_token_api(access_token: str):
    url = f"https://100067.connect.garena.com/oauth/token/inspect?token={access_token}"
    headers = {
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    try:
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        response.raise_for_status()
        data = response.json()
        if 'error' in data:
            raise ValueError(f"Token inspection failed: {data['error']}")
        open_id = data.get('open_id')
        platform = data.get('platform')
        if not open_id or not platform:
            raise ValueError("Could not extract open_id or platform")
        return open_id, platform
    except Exception as e:
        raise ValueError(f"Token inspection failed: {str(e)}")

def get_major_login_token_api(open_id, access_token, platform):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    protobuf_data = ProtobufEncoder.create_login_request(open_id, access_token, platform)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(protobuf_data, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-S908E Build/TP1A.220624.014)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/octet-stream",
        "X-GA": "v1 1",
        "X-Unity-Version": "2018.4.11f1",
        "ReleaseVersion": "OB51"
    }
    try:
        response = requests.post(url, headers=headers, data=encrypted_data, timeout=15, verify=False)
        if response.status_code != 200:
            raise ValueError(f"MajorLogin failed with status: {response.status_code}")
        
        # Search for JWT in response
        response_text = response.text
        jwt_pattern = r'[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+'
        matches = re.findall(jwt_pattern, response_text)
        for match in matches:
            if len(match) > 100 and match.count('.') == 2:
                return {'jwt_token': match}
        raise ValueError("No JWT token found in response")
    except Exception as e:
        raise ValueError(f"MajorLogin request failed: {str(e)}")

@app.get("/")
async def root():
    return {
        "api": "RE7BAL-JWT-EXTRACTOR",
        "version": "1.0",
        "author": "@N5NVN",
        "endpoint": "GET /getaccby/@n5nvn/?token=YOUR_TOKEN"
    }

@app.get("/getaccby/@n5nvn/")
async def extract_jwt(token: str = Query(..., description="Garena Access Token")):
    """Main endpoint to extract JWT token"""
    try:
        # Step 1: Inspect token
        open_id, platform = inspect_access_token_api(token)
        
        # Step 2: Get JWT
        result = get_major_login_token_api(open_id, token, platform)
        jwt_token = result['jwt_token']
        
        return JSONResponse({
            "success": True,
            "message": "JWT extracted successfully",
            "open_id": open_id,
            "platform": platform,
            "jwt_token": jwt_token,
            "timestamp": datetime.now().isoformat()
        })
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail={"success": False, "error": str(e)})
    except Exception as e:
        raise HTTPException(status_code=500, detail={"success": False, "error": "Internal server error"})

# Vercel requires this
app = app
