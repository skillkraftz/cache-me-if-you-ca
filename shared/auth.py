import base64
import hmac
import hashlib
import json
import time
import uuid


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def sign_payload(payload: dict, secret: str) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).digest()
    return f"{_b64e(body)}.{_b64e(sig)}"


def verify_payload(token: str, secret: str) -> dict | None:
    try:
        body_b64, sig_b64 = token.split(".", 1)
        body = _b64d(body_b64)
        sig = _b64d(sig_b64)
    except Exception:
        return None
    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except Exception:
        return None


def now_ts() -> int:
    return int(time.time())


def new_jti() -> str:
    return str(uuid.uuid4())
