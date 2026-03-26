# app/token_manager.py

import os
import json
import threading
import time
import logging
import httpx
from Crypto.Cipher import AES
from cachetools import TTLCache
from datetime import timedelta
from google.protobuf import json_format

logger = logging.getLogger(__name__)

CACHE_DURATION = timedelta(hours=7).seconds
TOKEN_REFRESH_THRESHOLD = timedelta(hours=6).seconds


def get_headers(token: str):
    return {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB51"
    }


def pkcs7_pad(b: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(b) % block_size)
    return b + bytes([pad_len]) * pad_len


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pkcs7_pad(plaintext, 16))


def _generate_token_sync(uid: str, password: str) -> str | None:
    """Generate JWT token secara SYNC penuh — tidak pakai asyncio sama sekali."""
    try:
        from app.jwt_settings import settings
        from ff_proto import freefire_pb2

        # Step 1: Garena OAuth — dapat access_token
        parts = settings.CLIENT_SECRET_PAYLOAD.split('&client_id=')
        client_secret = parts[0]
        client_id = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 100067

        payload = {
            "client_id": client_id,
            "client_secret": client_secret,
            "client_type": 2,
            "password": password,
            "response_type": "token",
            "uid": int(uid)
        }

        oauth_headers = {
            "User-Agent": settings.USER_AGENT,
            "Accept": "application/json",
            "Content-Type": "application/json; charset=utf-8",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip"
        }

        with httpx.Client(http2=False, timeout=settings.TIMEOUT) as client:
            r = client.post(settings.OAUTH_URL, json=payload, headers=oauth_headers)
            r.raise_for_status()
            data = r.json().get("data", {})

            if 'error' in data:
                raise RuntimeError(f"Garena error: {data.get('error_description', data['error'])}")

            access_token = data.get("access_token", "0")
            open_id = data.get("open_id", "0")

            if access_token == "0":
                raise RuntimeError("access_token kosong dari Garena")

            # Step 2: MajorLogin — dapat JWT
            login_req_data = {
                "open_id": open_id,
                "open_id_type": "4",
                "login_token": access_token,
                "orign_platform_type": "4",
            }

            req_msg = freefire_pb2.LoginReq()
            json_format.ParseDict(login_req_data, req_msg)
            encoded = req_msg.SerializeToString()
            encrypted = aes_cbc_encrypt(settings.MAIN_KEY, settings.MAIN_IV, encoded)

            major_headers = {
                "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 15; I2404 Build/AP3A.240905.015.A2_V000L1)",
                "Connection": "Keep-Alive",
                "Accept-Encoding": "gzip",
                "Content-Type": "application/octet-stream",
                "Expect": "100-continue",
                "X-Unity-Version": settings.X_UNITY_VERSION,
                "X-GA": "v1 1",
                "ReleaseVersion": settings.RELEASE_VERSION,
            }

            r2 = client.post(settings.MAJOR_LOGIN_URL, content=encrypted, headers=major_headers)
            r2.raise_for_status()

            res_msg = freefire_pb2.LoginRes()
            res_msg.ParseFromString(r2.content)

            token = res_msg.token if res_msg.token else "0"
            if not token or token == "0":
                raise RuntimeError("JWT kosong dari MajorLogin")

            logger.info(f"Token OK untuk UID {uid}")
            return token

    except Exception as e:
        logger.error(f"Gagal generate token untuk UID {uid}: {e}")
        return None


class TokenCache:
    def __init__(self, servers_config):
        self.cache = TTLCache(maxsize=100, ttl=CACHE_DURATION)
        self.last_refresh = {}
        self.lock = threading.Lock()
        self.servers_config = servers_config

    def get_tokens(self, server_key):
        with self.lock:
            now = time.time()
            refresh_needed = (
                server_key not in self.cache or
                server_key not in self.last_refresh or
                (now - self.last_refresh.get(server_key, 0)) > TOKEN_REFRESH_THRESHOLD
            )
            if refresh_needed:
                self._refresh_tokens(server_key)
                self.last_refresh[server_key] = now
            return self.cache.get(server_key, [])

    def _refresh_tokens(self, server_key):
        try:
            creds = self._load_credentials(server_key)
            tokens = []
            for user in creds:
                token = _generate_token_sync(user['uid'], user['password'])
                if token:
                    tokens.append(token)

            self.cache[server_key] = tokens
            if tokens:
                logger.info(f"Refresh selesai {server_key}: {len(tokens)} token")
            else:
                logger.warning(f"Tidak ada token valid untuk {server_key}")

        except Exception as e:
            logger.error(f"Error refresh {server_key}: {e}")
            if server_key not in self.cache:
                self.cache[server_key] = []

    def _load_credentials(self, server_key):
        try:
            config_data = os.getenv(f"{server_key}_CONFIG")
            if config_data:
                return json.loads(config_data)

            config_path = os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                'config',
                f'{server_key.lower()}_config.json'
            )
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    return json.load(f)
            logger.warning(f"Config tidak ditemukan: {config_path}")
            return []
        except Exception as e:
            logger.error(f"Error load credentials {server_key}: {e}")
            return []
