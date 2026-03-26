# app/token_manager.py — pakai JWT generator lokal (tanpa external auth server)

import os
import json
import asyncio
import threading
import time
import logging
from cachetools import TTLCache
from datetime import timedelta

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


def _generate_token_sync(uid: str, password: str) -> str | None:
    """Generate JWT token dari uid+password langsung via Garena OAuth (sync wrapper)."""
    try:
        from app.jwt_core import create_jwt
        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(create_jwt(uid, password))
        loop.close()
        token = result.get("token")
        if token and token != "0":
            logger.info(f"Token berhasil di-generate untuk UID {uid}")
            return token
        else:
            logger.warning(f"Token kosong untuk UID {uid}: {result}")
            return None
    except Exception as e:
        logger.error(f"Gagal generate token untuk UID {uid}: {str(e)}")
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

            if tokens:
                self.cache[server_key] = tokens
                logger.info(f"Token refresh selesai untuk {server_key}: {len(tokens)} token")
            else:
                logger.warning(f"Tidak ada token valid untuk {server_key}")
                self.cache[server_key] = []

        except Exception as e:
            logger.error(f"Error refresh token {server_key}: {str(e)}")
            if server_key not in self.cache:
                self.cache[server_key] = []

    def _load_credentials(self, server_key):
        try:
            # Coba dari environment variable dulu
            config_data = os.getenv(f"{server_key}_CONFIG")
            if config_data:
                return json.loads(config_data)

            # Fallback ke file JSON
            config_path = os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                'config',
                f'{server_key.lower()}_config.json'
            )
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    return json.load(f)
            else:
                logger.warning(f"Config tidak ditemukan untuk {server_key}: {config_path}")
                return []
        except Exception as e:
            logger.error(f"Error load credentials {server_key}: {str(e)}")
            return []
