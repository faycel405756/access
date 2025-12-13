from flask import Flask, request, jsonify
import requests, json, base64, warnings, traceback
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from datetime import datetime
import MajorLogin_res_pb2

warnings.filterwarnings("ignore")

app = Flask(__name__)

# =========================
# AES CONFIG
# =========================
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV  = b'6oyZDr22E3ychjM%'

# =========================
# SimpleProtobuf (كامل)
# =========================
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
    def encode_string(field, value):
        if isinstance(value, str):
            value = value.encode()
        return (
            SimpleProtobuf.encode_varint((field << 3) | 2) +
            SimpleProtobuf.encode_varint(len(value)) +
            value
        )

    @staticmethod
    def encode_int(field, value):
        return (
            SimpleProtobuf.encode_varint((field << 3) | 0) +
            SimpleProtobuf.encode_varint(value)
        )

    @staticmethod
    def parse(data):
        out, i = {}, 0
        while i < len(data):
            tag = data[i]
            field = tag >> 3
            wire = tag & 7
            i += 1

            if wire == 0:
                val, shift = 0, 0
                while True:
                    b = data[i]; i += 1
                    val |= (b & 0x7F) << shift
                    if not (b & 0x80): break
                    shift += 7
                out[field] = val

            elif wire == 2:
                ln, shift = 0, 0
                while True:
                    b = data[i]; i += 1
                    ln |= (b & 0x7F) << shift
                    if not (b & 0x80): break
                    shift += 7
                raw = data[i:i+ln]
                i += ln
                try:
                    out[field] = raw.decode()
                except:
                    out[field] = raw.hex()
            else:
                break
        return out

    @staticmethod
    def create_login_payload(open_id, access_token, platform):
        p = bytearray()
        p.extend(SimpleProtobuf.encode_string(3, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        p.extend(SimpleProtobuf.encode_string(4, "free fire"))
        p.extend(SimpleProtobuf.encode_int(5, 1))
        p.extend(SimpleProtobuf.encode_string(7, "2.111.2"))
        p.extend(SimpleProtobuf.encode_string(8, "Android OS 12 / API-31"))
        p.extend(SimpleProtobuf.encode_string(9, "Handheld"))
        p.extend(SimpleProtobuf.encode_string(10, "we"))
        p.extend(SimpleProtobuf.encode_string(11, "WIFI"))
        p.extend(SimpleProtobuf.encode_int(12, 1334))
        p.extend(SimpleProtobuf.encode_int(13, 800))
        p.extend(SimpleProtobuf.encode_string(14, "225"))
        p.extend(SimpleProtobuf.encode_string(15, "ARM64 FP ASIMD AES | 4032 | 8"))
        p.extend(SimpleProtobuf.encode_int(16, 2705))
        p.extend(SimpleProtobuf.encode_string(17, "Adreno (TM) 610"))
        p.extend(SimpleProtobuf.encode_string(18, "OpenGL ES 3.2"))
        p.extend(SimpleProtobuf.encode_string(19, "Google|device"))
        p.extend(SimpleProtobuf.encode_string(20, "154.183.6.12"))
        p.extend(SimpleProtobuf.encode_string(21, "ar"))
        p.extend(SimpleProtobuf.encode_string(22, open_id))
        p.extend(SimpleProtobuf.encode_string(23, str(platform)))
        p.extend(SimpleProtobuf.encode_string(24, "Handheld"))
        p.extend(SimpleProtobuf.encode_string(25, "samsung SM-T505N"))
        p.extend(SimpleProtobuf.encode_string(29, access_token))
        p.extend(SimpleProtobuf.encode_int(30, 1))
        p.extend(SimpleProtobuf.encode_string(41, "we"))
        p.extend(SimpleProtobuf.encode_string(42, "WIFI"))
        p.extend(SimpleProtobuf.encode_string(57, "e89b158e4bcf988ebd09eb83f5378e87"))
        p.extend(SimpleProtobuf.encode_int(60, 22394))
        p.extend(SimpleProtobuf.encode_int(61, 1424))
        p.extend(SimpleProtobuf.encode_int(62, 3349))
        p.extend(SimpleProtobuf.encode_int(63, 24))
        p.extend(SimpleProtobuf.encode_int(64, 1552))
        p.extend(SimpleProtobuf.encode_int(65, 22394))
        p.extend(SimpleProtobuf.encode_int(66, 1552))
        p.extend(SimpleProtobuf.encode_int(67, 22394))
        p.extend(SimpleProtobuf.encode_int(73, 1))
        p.extend(SimpleProtobuf.encode_string(74, "/data/app/lib/arm64"))
        p.extend(SimpleProtobuf.encode_int(76, 2))
        p.extend(SimpleProtobuf.encode_string(77, "apk|/base.apk"))
        p.extend(SimpleProtobuf.encode_int(78, 2))
        p.extend(SimpleProtobuf.encode_int(79, 2))
        p.extend(SimpleProtobuf.encode_string(81, "64"))
        p.extend(SimpleProtobuf.encode_string(83, "2019115296"))
        p.extend(SimpleProtobuf.encode_int(85, 1))
        p.extend(SimpleProtobuf.encode_string(86, "OpenGLES3"))
        p.extend(SimpleProtobuf.encode_int(87, 16383))
        p.extend(SimpleProtobuf.encode_int(88, 4))
        p.extend(SimpleProtobuf.encode_string(90, "Damanhur"))
        p.extend(SimpleProtobuf.encode_string(91, "BH"))
        p.extend(SimpleProtobuf.encode_int(92, 31095))
        p.extend(SimpleProtobuf.encode_string(93, "android_max"))
        p.extend(SimpleProtobuf.encode_string(94, "KqsHTzpfADfqKnEg/KMctJLElsm8bN2M4ts0zq+ifY="))
        p.extend(SimpleProtobuf.encode_int(97, 1))
        p.extend(SimpleProtobuf.encode_int(98, 1))
        p.extend(SimpleProtobuf.encode_string(99, str(platform)))
        p.extend(SimpleProtobuf.encode_string(100, str(platform)))
        inner = SimpleProtobuf.encode_string(8, "GAW")
        p.extend(SimpleProtobuf.encode_string(102, inner.decode("latin1")))
        return bytes(p)

# =========================
# JWT helper
# =========================
def decode_jwt(jwt):
    try:
        payload = jwt.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except:
        return None

# =========================
# API ROUTE
# =========================
@app.route("/api/major_login", methods=["GET"])
def major_login_api():
    token = request.args.get("access_token")
    if not token:
        return jsonify({"error": "access_token required"}), 400

    inspect = requests.get(
        f"https://100067.connect.garena.com/oauth/token/inspect?token={token}",
        timeout=10
    ).json()

    if "error" in inspect:
        return jsonify({"error": "invalid_token", "inspect": inspect}), 400

    open_id = inspect["open_id"]
    platform = inspect["platform"]

    payload = SimpleProtobuf.create_login_payload(open_id, token, platform)
    enc = AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(pad(payload, 16))

    r = requests.post(
        "https://loginbp.ggblueshark.com/MajorLogin",
        data=enc,
        headers={
            "Content-Type": "application/octet-stream",
            "User-Agent": "Dalvik/2.1.0",
            "X-Unity-Version": "2018.4.11f1",
            "ReleaseVersion": "OB51",
        },
        timeout=15
    )

    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    dec = unpad(cipher.decrypt(r.content), 16)

    msg = MajorLogin_res_pb2.MajorLoginRes()
    msg.ParseFromString(dec)

    jwt = msg.account_jwt.decode(errors="ignore")

    return jsonify({
        "open_id": open_id,
        "platform": platform,
        "account_id": msg.account_id,
        "jwt": jwt,
        "jwt_payload": decode_jwt(jwt),
        "key": msg.key.hex(),
        "iv": msg.iv.hex()
    })

# =========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
