import base64
import hashlib
import json
import time
import uuid
from functools import lru_cache

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def canonical_json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


@lru_cache(maxsize=None)
def _private_key(pem: str):
    return serialization.load_pem_private_key(pem.encode("utf-8"), password=None)


@lru_cache(maxsize=None)
def _public_key(pem: str):
    return serialization.load_pem_public_key(pem.encode("utf-8"))


def sign_payload(payload: dict, private_key_pem: str) -> str:
    body = canonical_json_bytes(payload)
    sig = _private_key(private_key_pem).sign(body, padding.PKCS1v15(), hashes.SHA256())
    return f"{_b64e(body)}.{_b64e(sig)}"


def verify_payload(token: str, public_key_pem: str) -> dict | None:
    try:
        body_b64, sig_b64 = token.split(".", 1)
        body = _b64d(body_b64)
        sig = _b64d(sig_b64)
    except Exception:
        return None
    try:
        _public_key(public_key_pem).verify(
            sig, body, padding.PKCS1v15(), hashes.SHA256()
        )
    except InvalidSignature:
        return None
    except Exception:
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except Exception:
        return None


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def now_ts() -> int:
    return int(time.time())


def new_jti() -> str:
    return str(uuid.uuid4())
