import socket
import ipaddress
from urllib.parse import urlparse
import httpx
from fastapi import FastAPI, HTTPException, Request
import hashlib
import os
import redis.asyncio as redis
import time


REDIS_RETRY_INTERVAL = 600

redis_available = True
redis_last_check = 0

LOCAL_WHITELIST = {}  # { key: expire_timestamp }

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

redis_client = redis.from_url(
    REDIS_URL,
    decode_responses=True,
    socket_connect_timeout=1,
    socket_timeout=1,
    retry_on_timeout=False
)

app = FastAPI()

# In-memory whitelist as backup for Redis
WHITELIST = {}
WHITELIST_TTL = 60 * 60 * 24  # 24 hours

# ALLOWED_SERVICES = {"WMS", "WFS", "WCS"}
ALLOWED_REQUESTS = {
    "GetCapabilities",
    "GetMap",
    "GetFeature",
    "GetFeatureInfo",
    "GetLegendGraphic",
    "DescribeFeatureType",
    "GetPropertyValue",
    "GetGMLObject",
    "GetCoverage"
}

PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
]


def is_private_ip(hostname: str) -> bool:
    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        raise HTTPException(status_code=400, detail="DNS resolution failed")

    ip_obj = ipaddress.ip_address(ip)
    return any(ip_obj in net for net in PRIVATE_NETWORKS)


def validate_ogc_params(query_params: dict):
    # service = query_params.get("SERVICE", [""])[0].upper()
    request = query_params.get("request", "")

    # if service not in ALLOWED_SERVICES:
    #     raise HTTPException(status_code=400, detail="Invalid OGC SERVICE")

    if request not in ALLOWED_REQUESTS:
        raise HTTPException(status_code=400, detail="Invalid OGC REQUEST " + request)


def is_ogc_service(base_url: str, params_ci) -> bool:
    try:
        service_type = params_ci.get('service', infer_service_from_path(base_url))
        if not service_type:
            params = {"REQUEST": "GetCapabilities"}
        else:
            params = {"SERVICE": service_type, "REQUEST": "GetCapabilities"}
        r = httpx.get(base_url, params=params, timeout=10)
        result = "_Capabilities" in r.text
        # print(f"Is OGC {base_url}: {result}")
        return result
    except Exception:
        return False


def whitelist_key(base: str) -> str:
    digest = hashlib.sha256(base.encode()).hexdigest()
    return f"ogc_whitelist:{digest}"


async def add_to_whitelist(base: str):
    global redis_available

    key = whitelist_key(base)

    if redis_available:
        try:
            await redis_client.set(key, "1", ex=WHITELIST_TTL)
            return
        except Exception:
            print("Redis failed. Switching to local cache.")
            redis_available = False

    # Fallback to local cache
    LOCAL_WHITELIST[key] = time.time() + WHITELIST_TTL


async def is_whitelisted(base: str) -> bool:
    global redis_available

    key = whitelist_key(base)

    # Try Redis first
    if redis_available:
        try:
            exists = await redis_client.exists(key)
            return bool(exists)
        except Exception:
            print("Redis failed. Switching to local cache.")
            redis_available = False

    # Try to recover Redis if down
    await check_redis_health()

    # Fallback to local cache
    expire = LOCAL_WHITELIST.get(key)

    if not expire:
        return False

    if expire < time.time():
        del LOCAL_WHITELIST[key]
        return False

    return True


def infer_service_from_path(full_url: str) -> str | None:
    path = full_url.lower()

    if "/wms" in path:
        return "WMS"
    if "/wfs" in path:
        return "WFS"
    if "/wcs" in path:
        return "WCS"

    return None


async def check_redis_health():
    global redis_available, redis_last_check

    now = time.time()

    # Only retry every 10 minutes
    if redis_available:
        return True

    if now - redis_last_check < REDIS_RETRY_INTERVAL:
        return False

    redis_last_check = now

    try:
        await redis_client.ping()
        redis_available = True
        print("Redis is back online.")
        return True
    except Exception:
        return False


@app.get("/ogcproxy/{full_url:path}")
async def proxy(full_url: str, request: Request):
    parsed = urlparse("https://" + full_url)

    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    query_params = dict(request.query_params)
    params_ci = {k.lower(): v for k, v in query_params.items()}

    if not await is_whitelisted(base):
        hostname = parsed.hostname
        if not hostname:
            raise HTTPException(status_code=400, detail="Invalid hostname")

        if is_private_ip(hostname):
            raise HTTPException(status_code=403, detail="Private IP not allowed")

        if not is_ogc_service(base, params_ci):
            raise HTTPException(status_code=400, detail="Not a valid OGC service")

        await add_to_whitelist(base)

    validate_ogc_params(params_ci)

    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.get(base, params=query_params)

    return resp.content
